<?php declare(strict_types=1);

namespace Monarc\Core\Controller;

use Laminas\Mvc\Controller\AbstractActionController;
use Monarc\Core\Provider\IdentityProviderInterface;
use Monarc\Core\Service\AuthenticationService;
use Monarc\Core\Service\IdentityManagementService;

/**
 * Contrôleur d'authentification SSO générique
 */
class SsoAuthenticationController extends AbstractActionController
{
    private IdentityProviderInterface $identityProvider;
    private IdentityManagementService $identityService;
    private AuthenticationService $authenticationService;

    public function __construct(
        IdentityProviderInterface $identityProvider,
        IdentityManagementService $identityService,
        AuthenticationService $authenticationService
    ) {
        $this->identityProvider = $identityProvider;
        $this->identityService = $identityService;
        $this->authenticationService = $authenticationService;
    }

    private function getRedirectUri(): string
    {
        $httpHost = $_SERVER['HTTP_HOST'] ?? 'localhost:5001';
        $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
        return "{$scheme}://{$httpHost}/auth/sso/callback";
    }

    /**
     * 1. Redirige l'utilisateur vers le fournisseur SSO actif avec logs détaillés
     */
    public function redirectAction()
    {
        $redirectUri = $this->getRedirectUri();
        $state = bin2hex(random_bytes(16));
        $url = $this->identityProvider->getAuthorizationUrl($redirectUri, $state);


        return $this->redirect()->toUrl($url);
    }

    /**
     * 2. Reçoit le retour SSO avec capture des erreurs retournées par le fournisseur
     */
    public function callbackAction()
    {
        $request = $this->getRequest();
        $queryParams = $this->params()->fromQuery();

        // Vérification si TrustedX a renvoyé une erreur dans l'URL
        if (!empty($queryParams['error'])) {
            $err = $queryParams['error'];
            $errDesc = $queryParams['error_description'] ?? 'Pas de description';
      
            return $this->redirect()->toUrl('/#/?error=' . urlencode("Erreur SSO: {$err} - {$errDesc}"));
        }

        $code = $this->params()->fromQuery('code');

        if (empty($code)) {
            
            $this->getResponse()->setStatusCode(400);
            return $this->redirect()->toUrl('/#/?error=sso_code_missing');
        }

        try {
            $redirectUri = $this->getRedirectUri();
            
            // 1. Échange du code d'autorisation contre les données SSO
            $externalDto = $this->identityProvider->authenticateCode($code, $redirectUri);
            
            // 2. Recherche et association automatique du sub
            $user = $this->identityService->findUserByIdentity($externalDto);
            
            // 3. Création de session native MONARC
            $authData = $this->authenticationService->createSessionForUser($user);
            $token = $authData['token'];
            $language = $user->getLanguage();

            // 4. Enregistrement chiffré des jetons SSO
            try {
                $this->identityService->storeSsoSession(
                    $user,
                    $externalDto->providerCode,
                    $token,
                    $externalDto->attributes
                );
            } catch (\Throwable $sessionEx) {
                error_log("[SSO SESSION WARNING] Impossible d'enregistrer les jetons : " . $sessionEx->getMessage());
            }

            // 5. Redirection vers le frontend
            $targetUrl = sprintf(
                '/#/?token=%s&uid=%d&language=%s',
                urlencode($token),
                $user->getId(),
                urlencode((string)$language)
            );
           
            return $this->redirect()->toUrl($targetUrl);

        } catch (\Throwable $e) {
            error_log("[SSO EXCEPTION] " . $e->getMessage() . " | " . $e->getTraceAsString());
            return $this->redirect()->toUrl('/#/?error=' . urlencode($e->getMessage()));
        }
    }
}