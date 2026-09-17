<?php declare(strict_types=1);

namespace Monarc\Core\Service\Sso;

use Doctrine\ORM\EntityManager;
use Monarc\Core\Entity\UserSuperClass;
use Monarc\Core\Entity\Sso\Identity;
use Monarc\Core\Entity\Sso\Provider;
use Monarc\Core\Entity\Sso\SsoSession;
use Monarc\Core\Exception\Exception;
use Monarc\Core\Provider\Sso\GenericOAuth2IdentityProvider;
use Monarc\Core\Provider\Sso\IdentityProviderInterface;
use Monarc\Core\Service\AuthenticationService;

class IdentityManagementService
{
    protected EntityManager $em;
    protected AuthenticationService $authService;
    protected array $config;
    protected string $userEntityClass;

    public function __construct(EntityManager $em, AuthenticationService $authService, array $config)
    {
        $this->em = $em;
        $this->authService = $authService;
        $this->config = $config;

        $userEntityClass = $config['monarc_sso']['user_entity_class'] ?? null;
        if (empty($userEntityClass) || !class_exists($userEntityClass)) {
            throw new Exception(
                "Configuration manquante : 'monarc_sso.user_entity_class' doit pointer vers la classe User de l'application (ex: Monarc\\FrontOffice\\Entity\\User).",
                500
            );
        }
        $this->userEntityClass = $userEntityClass;
    }

    // Génère l'URL d'autorisation vers le fournisseur SSO
    public function getAuthorizationUrl(string $providerCode): string
    {
        $providerInstance = $this->getProviderInstance($providerCode);
        $encodedState = $this->generateOAuthState($providerCode);
        return $providerInstance->getAuthorizationUrl($encodedState);
    }

    // Génère une URL d'autorisation OAuth2 avec un redirect_uri personnalisé
    public function getAuthorizationUrlWithCustomRedirect(string $providerCode, string $redirectUri): string
    {
        $providerInstance = $this->getProviderInstance($providerCode);
        $encodedState = $this->generateOAuthState($providerCode);
        return $providerInstance->getAuthorizationUrlWithRedirect($encodedState, $redirectUri);
    }

    // Point d'entrée principal du callback SSO
    public function processSsoCallback(array $params): string
    {
        $forwardedPrefix = $_SERVER['HTTP_X_FORWARDED_PREFIX'] ?? '';
        $basePath = !empty($forwardedPrefix) ? '/' . trim((string)$forwardedPrefix, '/') : '';

        try {
            $authResult = $this->handleCallback($params);
            $token = urlencode((string)$authResult['token']);
            $userId = urlencode((string)$authResult['user']->getId());
            return "{$basePath}/#/sso-landing?token={$token}&uid={$userId}";
        } catch (\Throwable $e) {
            $errorMessage = urlencode($e->getMessage());
            return "{$basePath}/#/sso-landing?error={$errorMessage}";
        }
    }

    // Récupère un access token valide pour l'utilisateur, en le rafraîchissant si expiré
    public function getValidAccessTokenForUser(UserSuperClass $user, string $providerCode = 'trustedx_pki'): ?string
    {
        $providerRepo = $this->em->getRepository(Provider::class);
        $provider = $providerRepo->findOneBy(['code' => $providerCode]);
        if (!$provider) {
            return null;
        }

        $sessionRepo = $this->em->getRepository(SsoSession::class);
        $ssoSession = $sessionRepo->findOneBy([
            'userId'   => $user->getId(),
            'provider' => $provider,
        ]);

        if (!$ssoSession || empty($ssoSession->getAccessTokenEncrypted())) {
            return null;
        }

        $nowWithMargin = (new \DateTime())->modify('+60 seconds');
        $expiresAt = $ssoSession->getExpiresAt();

        if ($expiresAt === null || $expiresAt > $nowWithMargin) {
            return $this->decryptToken($ssoSession->getAccessTokenEncrypted());
        }

        $refreshToken = $this->decryptToken($ssoSession->getRefreshTokenEncrypted());
        if (!empty($refreshToken)) {
            try {
                $providerInstance = $this->getProviderInstance($providerCode);
                $tokenResponse = $providerInstance->refreshAccessToken($refreshToken);
                $updatedSession = $this->saveSsoSession($user, $provider, $tokenResponse);
                return $this->decryptToken($updatedSession->getAccessTokenEncrypted());
            } catch (\Throwable $e) {
                try {
                    $this->em->remove($ssoSession);
                    $this->em->flush();
                } catch (\Throwable $ex) {}
                return null;
            }
        }

        return null;
    }

    // Échange un code OAuth2 contre un token TX frais et le sauvegarde en DB
    public function exchangeAndSaveToken(string $code, string $redirectUri, UserSuperClass $user, string $providerCode = 'trustedx_pki'): void
    {
        $ssoConfig    = $this->config['sso_providers'][$providerCode] ?? [];
        $tokenUrl     = $ssoConfig['token_url']     ?? '';
        $clientId     = $ssoConfig['client_id']     ?? '';
        $clientSecret = $ssoConfig['client_secret'] ?? '';

        if (empty($tokenUrl) || empty($clientId)) {
            throw new Exception("Configuration SSO manquante pour le provider '$providerCode'.", 500);
        }

        $postData = [
            'grant_type'   => 'authorization_code',
            'code'         => $code,
            'redirect_uri' => $redirectUri,
        ];

        $ch = curl_init($tokenUrl);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => http_build_query($postData),
            CURLOPT_HTTPHEADER     => [
                'Authorization: Basic ' . base64_encode("$clientId:$clientSecret"),
                'Content-Type: application/x-www-form-urlencoded',
                'Accept: application/json',
            ],
            CURLOPT_TIMEOUT        => 15,
        ]);

        $response  = curl_exec($ch);
        $httpCode  = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curlError = curl_error($ch);
        curl_close($ch);

        if ($curlError) {
            throw new Exception("Erreur réseau lors de l'échange de token TX: $curlError", 500);
        }

        $data = json_decode((string)$response, true);

        if ($httpCode >= 400 || empty($data['access_token'])) {
            $msg = $data['error_description'] ?? $data['error'] ?? "HTTP $httpCode";
            throw new Exception("Échec de l'échange de code OAuth2 TX: $msg", 400);
        }

        $providerRepo = $this->em->getRepository(Provider::class);
        $provider     = $providerRepo->findOneBy(['code' => $providerCode]);
        if (!$provider) {
            throw new Exception("Provider '$providerCode' introuvable en base.", 500);
        }

        $this->saveSsoSession($user, $provider, $data);
    }

    // Échange un code OAuth2 TrustedX contre un access token frais
    public function exchangeSignatureCode(string $code, string $redirectUri, string $providerCode = 'trustedx_pki'): ?string
    {
        $ssoConfig = $this->config['sso_providers'][$providerCode] ?? [];
        $tokenUrl   = $ssoConfig['token_url']     ?? '';
        $clientId   = $ssoConfig['client_id']     ?? '';
        $clientSecret = $ssoConfig['client_secret'] ?? '';

        if (empty($tokenUrl) || empty($clientId)) {
            return null;
        }

        $postData = [
            'grant_type'   => 'authorization_code',
            'code'         => $code,
            'redirect_uri' => $redirectUri,
        ];

        $ch = curl_init($tokenUrl);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => http_build_query($postData),
            CURLOPT_HTTPHEADER     => [
                'Authorization: Basic ' . base64_encode("$clientId:$clientSecret"),
                'Content-Type: application/x-www-form-urlencoded',
                'Accept: application/json',
            ],
            CURLOPT_TIMEOUT        => 15,
        ]);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curlError = curl_error($ch);
        curl_close($ch);

        if ($curlError) {
            return null;
        }

        $data = json_decode((string)$response, true);

        return !empty($data['access_token']) ? (string)$data['access_token'] : null;
    }

    // Récupère toutes les identités SSO liées à un utilisateur
    public function getUserIdentities(int $userId): array
    {
        $user = $this->em->getRepository($this->userEntityClass)->find($userId);
        if (!$user) {
            throw new Exception("Utilisateur introuvable.", 404);
        }

        $identities = $this->em->getRepository(Identity::class)
            ->findBy(['userId' => $userId], ['updatedAt' => 'DESC']);

        return array_map(static fn (Identity $identity) => [
            'id'                 => $identity->getId(),
            'providerCode'       => $identity->getProvider()->getCode(),
            'providerName'       => $identity->getProvider()->getName(),
            'providerIdentifier' => $identity->getProviderIdentifier(),
        ], $identities);
    }

    // Lie un identifiant SSO / NPI à un utilisateur MONARC
    public function linkUserIdentityById(int $userId, string $providerCode, string $providerIdentifier): Identity
    {
        $user = $this->em->getRepository($this->userEntityClass)->find($userId);
        if (!$user) {
            throw new Exception("Utilisateur introuvable.", 404);
        }

        $provider = $this->findOrCreateProvider($providerCode);

        $identityRepo = $this->em->getRepository(Identity::class);
        $existing = $identityRepo->findOneBy([
            'provider'           => $provider,
            'providerIdentifier' => $providerIdentifier,
        ]);

        if ($existing && $existing->getUserId() !== $userId) {
            throw new Exception("Cet identifiant SSO ($providerIdentifier) est déjà associé à un autre utilisateur.", 400);
        }

        $identity = $identityRepo->findOneBy(['userId' => $userId, 'provider' => $provider]);
        if (!$identity) {
            $identity = new Identity();
            $identity->setUserId($userId);
        }

        $identity->setProvider($provider);
        $identity->setProviderIdentifier($providerIdentifier);

        $this->em->persist($identity);
        $this->em->flush();

        return $identity;
    }

    // Délie une identité SSO précise
    public function unlinkIdentityById(int $userId, int $identityId): bool
    {
        $identity = $this->em->getRepository(Identity::class)->find($identityId);
        if (!$identity || $identity->getUserId() !== $userId) {
            throw new Exception("Identité SSO introuvable pour cet utilisateur.", 404);
        }

        $this->em->remove($identity);
        $this->em->flush();

        return true;
    }

    // Délie toutes les identités SSO d'un utilisateur MONARC
    public function unlinkAllUserIdentities(int $userId): bool
    {
        $user = $this->em->getRepository($this->userEntityClass)->find($userId);
        if (!$user) {
            throw new Exception("Utilisateur introuvable.", 404);
        }

        foreach ($this->em->getRepository(Identity::class)->findBy(['userId' => $userId]) as $identity) {
            $this->em->remove($identity);
        }
        $this->em->flush();

        return true;
    }

    // Retourne la liste des fournisseurs d'identité actifs
    public function getActiveProviders(): array
    {
        $configuredProviders = [];

        foreach ($this->config['sso_providers'] ?? [] as $code => $conf) {
            if (isset($conf['is_active']) && !$conf['is_active']) {
                continue;
            }
            $configuredProviders[(string)$code] = $this->findOrCreateProvider((string)$code);
        }

        $result = [];
        foreach ($configuredProviders as $provider) {
            $result[] = [
                'id'   => $provider->getId(),
                'code' => $provider->getCode(),
                'name' => $provider->getName(),
            ];
        }

        foreach ($this->em->getRepository(Provider::class)->findBy(['isActive' => true]) as $p) {
            if (!isset($configuredProviders[$p->getCode()])) {
                $result[] = [
                    'id'   => $p->getId(),
                    'code' => $p->getCode(),
                    'name' => $p->getName(),
                ];
            }
        }

        return $result;
    }

    private function handleCallback(array $params): array
    {
        $stateData = $this->verifyAndDecodeState($params['state'] ?? null);
        $providerCode = $stateData['provider'];

        if (!$providerCode) {
            throw new Exception("Le fournisseur d'identité n'a pas été trouvé.", 400);
        }

        $providerInstance = $this->getProviderInstance($providerCode);
        $externalIdentity = $providerInstance->handleCallback($params);

        $provider = $this->findOrCreateProvider($providerCode);

        $identityRepo = $this->em->getRepository(Identity::class);
        $identity = null;

        if (!empty($externalIdentity->sub)) {
            $identity = $identityRepo->findOneBy([
                'provider' => $provider,
                'sub'      => $externalIdentity->sub,
            ]);
        }

        if (!$identity) {
            $identity = $identityRepo->findOneBy([
                'provider'           => $provider,
                'providerIdentifier' => $externalIdentity->providerIdentifier,
            ]);

            if ($identity && !empty($externalIdentity->sub) && $identity->getSub() !== $externalIdentity->sub) {
                $identity->setSub($externalIdentity->sub);
                $this->em->persist($identity);
                $this->em->flush();
            }
        }

        if (!$identity) {
            $name = trim(($externalIdentity->firstname ?? '') . ' ' . ($externalIdentity->lastname ?? ''));
            $displayName = $name ?: ($externalIdentity->email ?: 'Utilisateur');

            throw new Exception(
                "Votre compte d'identité numérique ($displayName - NPI: {$externalIdentity->providerIdentifier}) n'est associé à aucun compte utilisateur MONARC. " .
                "Veuillez contacter votre administrateur pour lier votre identifiant.",
                403
            );
        }

        $user = $this->em->getRepository($this->userEntityClass)->find($identity->getUserId());
        if (!$user) {
            throw new Exception("L'utilisateur MONARC lié à cette identité SSO n'existe plus.", 403);
        }

        if (method_exists($user, 'getIsActive') && !$user->getIsActive()) {
            throw new Exception("Votre compte utilisateur MONARC est désactivé.", 403);
        }

        $tokenResponse = $externalIdentity->rawAttributes['_token_response'] ?? [];
        if (!empty($tokenResponse['access_token'])) {
            $this->saveSsoSession($user, $provider, $tokenResponse);
        }

        $sessionData = $this->authService->createSessionForUser($user);

        return [
            'token' => $sessionData['token'],
            'user'  => $user,
            'externalIdentity' => $externalIdentity,
        ];
    }

    private function generateOAuthState(string $providerCode): string
    {
        $statePayload = [
            'csrf'     => bin2hex(random_bytes(16)),
            'provider' => $providerCode,
            'exp'      => time() + 600,
        ];

        $encodedPayload = $this->base64UrlEncode((string)json_encode($statePayload));
        $signature = $this->signStatePayload($encodedPayload);

        return $encodedPayload . '.' . $signature;
    }

    private function verifyAndDecodeState(?string $state): array
    {
        if (empty($state) || !str_contains($state, '.')) {
            throw new Exception(
                "Requête d'authentification SSO invalide ou expirée (paramètre 'state' manquant ou malformé). Veuillez relancer la connexion.",
                400
            );
        }

        [$encodedPayload, $signature] = explode('.', $state, 2);
        $expectedSignature = $this->signStatePayload($encodedPayload);

        if (!hash_equals($expectedSignature, $signature)) {
            throw new Exception(
                "Requête d'authentification SSO invalide (signature du 'state' incorrecte). Veuillez relancer la connexion.",
                400
            );
        }

        $statePayload = json_decode($this->base64UrlDecode($encodedPayload), true);
        if (!is_array($statePayload) || empty($statePayload['exp']) || time() > (int)$statePayload['exp']) {
            throw new Exception(
                "Votre session d'authentification SSO a expiré. Veuillez relancer la connexion.",
                400
            );
        }

        return $statePayload;
    }

    private function signStatePayload(string $encodedPayload): string
    {
        $hmacKey = hash('sha256', $this->getEncryptionKey() . '|oauth2_state', true);

        return $this->base64UrlEncode(hash_hmac('sha256', $encodedPayload, $hmacKey, true));
    }

    private function base64UrlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    private function base64UrlDecode(string $data): string
    {
        return (string)base64_decode(strtr($data, '-_', '+/'));
    }

    protected function saveSsoSession(UserSuperClass $user, Provider $provider, array $tokenResponse): SsoSession
    {
        $sessionRepo = $this->em->getRepository(SsoSession::class);
        $ssoSession = $sessionRepo->findOneBy([
            'userId'   => $user->getId(),
            'provider' => $provider,
        ]);

        if (!$ssoSession) {
            $ssoSession = new SsoSession();
            $ssoSession->setUserId($user->getId());
            $ssoSession->setProvider($provider);
        }

        $sessionToken = bin2hex(random_bytes(32));
        $ssoSession->setSessionToken($sessionToken);
        $ssoSession->setAccessTokenEncrypted($this->encryptToken((string)$tokenResponse['access_token']));
        $ssoSession->setRefreshTokenEncrypted(
            !empty($tokenResponse['refresh_token']) ? $this->encryptToken((string)$tokenResponse['refresh_token']) : null
        );
        $ssoSession->setIdTokenEncrypted(
            !empty($tokenResponse['id_token']) ? $this->encryptToken((string)$tokenResponse['id_token']) : null
        );
        $ssoSession->setTokenType($tokenResponse['token_type'] ?? 'Bearer');
        $ssoSession->setScope($tokenResponse['scope'] ?? null);

        if (!empty($tokenResponse['expires_in'])) {
            $expiresAt = new \DateTime();
            $expiresAt->modify('+' . (int)$tokenResponse['expires_in'] . ' seconds');
            $ssoSession->setExpiresAt($expiresAt);
        }

        $this->em->persist($ssoSession);
        $this->em->flush();

        return $ssoSession;
    }

    private function getEncryptionKey(): string
    {
        $key = $this->config['monarc_sso']['encryption_key'] ?? null;
        if (empty($key) || strlen((string)$key) < 32) {
            throw new Exception(
                "Configuration manquante ou invalide : 'monarc_sso.encryption_key' doit être définie "
                . "(chaîne aléatoire d'au moins 32 caractères) pour chiffrer les jetons SSO en base.",
                500
            );
        }

        return (string)$key;
    }

    private function encryptToken(string $plainText): string
    {
        $iv = random_bytes(12);
        $tag = '';
        $cipherText = openssl_encrypt(
            $plainText,
            'aes-256-gcm',
            hash('sha256', $this->getEncryptionKey(), true),
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );

        if ($cipherText === false) {
            throw new Exception("Échec du chiffrement du jeton SSO.", 500);
        }

        return base64_encode($iv . $tag . $cipherText);
    }

    private function decryptToken(?string $encryptedData): ?string
    {
        if (empty($encryptedData)) {
            return null;
        }

        $data = base64_decode($encryptedData, true);
        if ($data === false || strlen($data) < 29) {
            return null;
        }

        $iv = substr($data, 0, 12);
        $tag = substr($data, 12, 16);
        $cipherText = substr($data, 28);

        $result = openssl_decrypt(
            $cipherText,
            'aes-256-gcm',
            hash('sha256', $this->getEncryptionKey(), true),
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );

        return $result !== false ? $result : null;
    }

    protected function getProviderInstance(string $providerCode): IdentityProviderInterface
    {
        $ssoConfig = $this->config['sso_providers'] ?? [];
        if (!isset($ssoConfig[$providerCode])) {
            throw new Exception("Configuration introuvable pour le fournisseur SSO: $providerCode", 500);
        }

        return new GenericOAuth2IdentityProvider($ssoConfig[$providerCode]);
    }

    private function findOrCreateProvider(string $providerCode): Provider
    {
        $provider = $this->em->getRepository(Provider::class)->findOneBy(['code' => $providerCode]);
        if (!$provider) {
            $provider = new Provider();
            $provider->setCode($providerCode);
            $provider->setIsActive(true);
        }
        $provider->setName($this->config['sso_providers'][$providerCode]['name'] ?? ucfirst($providerCode));
        $this->em->persist($provider);
        $this->em->flush();

        return $provider;
    }
}
