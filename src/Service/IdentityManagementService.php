<?php declare(strict_types=1);

namespace Monarc\Core\Service;

use Doctrine\ORM\EntityManagerInterface;
use Monarc\Core\Entity\UserSuperClass;
use Monarc\FrontOffice\Entity\Identity;
use Monarc\FrontOffice\Entity\Provider;
use Monarc\FrontOffice\Entity\User;
use Monarc\Core\Provider\ExternalIdentityDto;
use Monarc\FrontOffice\Entity\SsoSession;
use RuntimeException;

class IdentityManagementService
{
    private EntityManagerInterface $entityManager;
    private array $config;

    public function __construct(EntityManagerInterface $entityManager, array $config = [])
    {
        $this->entityManager = $entityManager;
        $this->config = $config;
    }

    /**
     * Récupère la liste des fournisseurs SSO configurés dans local.php
     */
    public function getActiveProviders(): array
    {
        $configuredProviders = $this->config['sso_providers'] ?? [];

        // Si des fournisseurs sont définis dans config/autoload/local.php
        if (!empty($configuredProviders)) {
            $providerRepo = $this->entityManager->getRepository(Provider::class);
            $activeList = [];
            foreach ($configuredProviders as $code => $details) {
                // Si le provider est explicitement désactivé (is_active => false), on l'ignore
                if (isset($details['is_active']) && !$details['is_active']) {
                    continue;
                }
                $provider = $providerRepo->findOneBy(['code' => (string)$code]);
                if (!$provider) {
                    $provider = new Provider();
                    $provider->setCode((string)$code);
                }
                $provider->setName($details['name'] ?? (string)$code);
                $provider->setIsActive(true);
                $this->entityManager->persist($provider);
                $activeList[] = [
                    'id' => $provider->getId(),
                    'code' => $provider->getCode(),
                    'name' => $provider->getName(),
                ];
            }
            $this->entityManager->flush();
            return $activeList;
        }
        // Fallback depuis la base si aucune clé 'sso_providers' n'est définie
        $providers = $this->entityManager->getRepository(Provider::class)->findBy(['isActive' => true]);
        $result = [];
        foreach ($providers as $p) {
            $result[] = [
                'id' => $p->getId(),
                'code' => $p->getCode(),
                'name' => $p->getName(),
            ];
        }
        return $result;
    }

    /**
     * Récupère l'identité SSO d'un utilisateur
     */
    public function getUserIdentity(int $userId): array
    {
        /** @var Identity|null $identity */
        $identity = $this->entityManager->getRepository(Identity::class)->findOneBy(['user' => $userId]);
        if (!$identity) {
            return [
                'isLinked' => false,
                'providerCode' => null,
                'providerName' => null,
                'providerIdentifier' => null,
                'sub' => null,
            ];
        }

        return [
            'isLinked' => true,
            'providerCode' => $identity->getProvider()->getCode(),
            'providerName' => $identity->getProvider()->getName(),
            'providerIdentifier' => $identity->getProviderIdentifier(),
            'sub' => $identity->getSub(),
        ];
    }

    /**
     * Associe ou met à jour le compte SSO d'un utilisateur
     */
    public function linkUserIdentityById(int $userId, string $providerCode, string $providerIdentifier): Identity
    {
        $user = $this->entityManager->getRepository(User::class)->find($userId);
        if (!$user) {
            throw new \RuntimeException("Utilisateur introuvable.");
        }

        $provider = $this->entityManager->getRepository(Provider::class)->findOneBy(['code' => $providerCode]);
        if (!$provider) {
            throw new \RuntimeException("Fournisseur SSO introuvable.");
        }

        // Vérifier si cet identifiant SSO est déjà lié à un autre compte
        $existing = $this->entityManager->getRepository(Identity::class)->findOneBy([
            'provider' => $provider,
            'providerIdentifier' => $providerIdentifier,
        ]);

        if ($existing && $existing->getUser()->getId() !== $userId) {
            throw new \RuntimeException("L'identifiant SSO '{$providerIdentifier}' est déjà rattaché à un autre compte.");
        }

        $identity = $this->entityManager->getRepository(Identity::class)->findOneBy(['user' => $userId]) ?: new Identity();
        $identity->setUser($user);
        $identity->setProvider($provider);
        $identity->setProviderIdentifier($providerIdentifier);

        $this->entityManager->persist($identity);
        $this->entityManager->flush();

        return $identity;
    }

    /**
     * Supprime la liaison SSO d'un utilisateur
     */
    public function unlinkUserIdentityById(int $userId): void
    {
        $identity = $this->entityManager->getRepository(Identity::class)->findOneBy(['user' => $userId]);
        if ($identity) {
            $this->entityManager->remove($identity);
            $this->entityManager->flush();
        }
    }

    public function findUserByIdentity(ExternalIdentityDto $dto): UserSuperClass
    {
        $provider = $this->entityManager->getRepository(Provider::class)->findOneBy(['code' => $dto->providerCode]);
        if (!$provider || !$provider->getIsActive()) {
            throw new RuntimeException("Fournisseur SSO {$dto->providerCode} inactif.");
        }

        // 1. Recherche d'abord par sub (si déjà enregistré), sinon par providerIdentifier (NPI)
        /** @var Identity|null $identity */
        $sub = $dto->attributes['sub'] ?? null;
        $identity = null;

        if (!empty($sub)) {
            $identity = $this->entityManager->getRepository(Identity::class)->findOneBy([
                'provider' => $provider,
                'sub' => (string)$sub,
            ]);
        }

        if (!$identity) {
            $identity = $this->entityManager->getRepository(Identity::class)->findOneBy([
                'provider' => $provider,
                'providerIdentifier' => $dto->providerIdentifier,
            ]);
        }

        if (!$identity) {
            throw new RuntimeException("Aucun compte MONARC n'est associé à cette identité SSO ({$dto->providerIdentifier}).");
        }

        // 2. Enregistrement automatique du 'sub' à la première connexion
        if (!empty($sub) && $identity->getSub() !== (string)$sub) {
            $identity->setSub((string)$sub);
            $this->entityManager->persist($identity);
            $this->entityManager->flush();
            error_log("[SSO SUCCESS] Le 'sub' ({$sub}) a été enregistré automatiquement pour l'utilisateur ID #{$identity->getUser()->getId()}.");
        }

        return $identity->getUser();
    }

    /**
     * Chiffre et enregistre les jetons de session SSO pour une utilisation ultérieure
     */
    public function storeSsoSession(
        UserSuperClass $user,
        string $providerCode,
        string $monarcSessionToken,
        array $tokenData
    ): SsoSession {
        $provider = $this->entityManager->getRepository(Provider::class)->findOneBy(['code' => $providerCode]);
        if (!$provider) {
            throw new \RuntimeException("Fournisseur SSO {$providerCode} introuvable.");
        }

        $secretKey = $this->getEncryptionKey();

        $session = new SsoSession();
        $session->setUser($user);
        $session->setProvider($provider);
        $session->setSessionToken($monarcSessionToken);

        // Chiffrement AES-256-GCM du jeton d'accès obligatoire
        $rawAccessToken = $tokenData['access_token'] ?? '';
        if (!empty($rawAccessToken)) {
            $session->setAccessTokenEncrypted($this->encryptToken((string)$rawAccessToken, $secretKey));
        }

        // Chiffrement du refresh token si disponible
        if (!empty($tokenData['refresh_token'])) {
            $session->setRefreshTokenEncrypted($this->encryptToken((string)$tokenData['refresh_token'], $secretKey));
        }

        // Chiffrement du ID token si disponible
        if (!empty($tokenData['id_token'])) {
            $session->setIdTokenEncrypted($this->encryptToken((string)$tokenData['id_token'], $secretKey));
        }

        $session->setTokenType($tokenData['token_type'] ?? 'Bearer');
        $session->setScope($tokenData['scope'] ?? null);

        // Calcul de la date d'expiration
        if (!empty($tokenData['expires_in'])) {
            $expiresAt = (new \DateTime())->modify('+' . (int)$tokenData['expires_in'] . ' seconds');
            $session->setExpiresAt($expiresAt);
        }

        $this->entityManager->persist($session);
        $this->entityManager->flush();

        error_log("[SSO SESSION] Jetons SSO chiffrés et enregistrés avec succès pour l'utilisateur ID #{$user->getId()}.");

        return $session;
    }

    /**
     * Récupère le jeton d'accès déchiffré pour un utilisateur
     */
    public function getValidAccessToken(UserSuperClass $user, string $providerCode = 'trustedx_pki'): ?string
    {
        $provider = $this->entityManager->getRepository(Provider::class)->findOneBy(['code' => $providerCode]);
        if (!$provider) {
            return null;
        }

        /** @var SsoSession|null $session */
        $session = $this->entityManager->getRepository(SsoSession::class)->findOneBy(
            ['user' => $user, 'provider' => $provider],
            ['createdAt' => 'DESC']
        );

        if (!$session || empty($session->getAccessTokenEncrypted())) {
            return null;
        }

        return $this->decryptToken($session->getAccessTokenEncrypted(), $this->getEncryptionKey());
    }

    private function getEncryptionKey(): string
    {
        return (string)($this->config['monarc']['salt'] ?? ($this->config['trustedx']['client_secret'] ?? 'MONARC_SSO_SECURE_ENCRYPTION_KEY_2026'));
    }

    private function encryptToken(string $plainText, string $secretKey): string
    {
        $iv = random_bytes(12); // IV standard de 96 bits pour GCM
        $tag = '';
        $cipherText = openssl_encrypt(
            $plainText,
            'aes-256-gcm',
            hash('sha256', $secretKey, true),
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );
        return base64_encode($iv . $tag . $cipherText);
    }

    private function decryptToken(string $encryptedData, string $secretKey): ?string
    {
        $data = base64_decode($encryptedData);
        if (strlen($data) < 28) {
            return null;
        }
        $iv = substr($data, 0, 12);
        $tag = substr($data, 12, 16);
        $cipherText = substr($data, 28);

        $result = openssl_decrypt(
            $cipherText,
            'aes-256-gcm',
            hash('sha256', $secretKey, true),
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );

        return $result !== false ? $result : null;
    }
}