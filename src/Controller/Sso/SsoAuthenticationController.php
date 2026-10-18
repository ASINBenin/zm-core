<?php declare(strict_types=1);

namespace Monarc\Core\Controller\Sso;

use Laminas\Http\Header\SetCookie;
use Laminas\Mvc\Controller\AbstractActionController;
use Laminas\View\Model\JsonModel;
use Monarc\Core\Service\ConnectedUserService;
use Monarc\Core\Service\Sso\IdentityManagementService;

/**
 * @method \Laminas\Http\PhpEnvironment\Request getRequest()
 * @method \Laminas\Http\PhpEnvironment\Response getResponse()
 */
class SsoAuthenticationController extends AbstractActionController
{
    // Nonce lié au navigateur, recopié dans le state OAuth2 et vérifié au retour (anti-CSRF de connexion)
    private const NONCE_COOKIE = 'monarc_sso_nonce';
    private const NONCE_TTL = 600;

    public function __construct(
        private IdentityManagementService $identityService,
        private ConnectedUserService $connectedUserService
    ) {
    }

    public function redirectAction()
    {
        $providerCode = $this->params()->fromQuery('provider', 'trustedx_pki');
        $nonce = bin2hex(random_bytes(16));
        $authUrl = $this->identityService->getAuthorizationUrl($providerCode, $nonce);

        $this->setNonceCookie($nonce, self::NONCE_TTL);

        return $this->redirect()->toUrl($authUrl);
    }

    public function callbackAction()
    {
        $cookie = $this->getRequest()->getCookie();
        $nonce = $cookie !== false && isset($cookie[self::NONCE_COOKIE]) ? (string)$cookie[self::NONCE_COOKIE] : null;

        $redirectUrl = $this->identityService->processSsoCallback($this->params()->fromQuery(), $nonce);

        $this->setNonceCookie('', 0);

        return $this->redirect()->toUrl($redirectUrl);
    }

    /**
     * Appelé par le front à la déconnexion MONARC : supprime les jetons TrustedX conservés pour la signature.
     */
    public function closeSessionAction()
    {
        $this->identityService->closeSsoSessions($this->connectedUserService->getConnectedUser());

        return new JsonModel([]);
    }

    private function setNonceCookie(string $value, int $ttl): void
    {
        $prefix = trim((string)($_SERVER['HTTP_X_FORWARDED_PREFIX'] ?? ''), '/');
        $isHttps = ($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https'
            || (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');

        $this->getResponse()->getHeaders()->addHeader(new SetCookie(
            self::NONCE_COOKIE,
            $value,
            time() + ($ttl > 0 ? $ttl : -3600),
            $prefix === '' ? '/' : '/' . $prefix,
            null,
            $isHttps,
            true,
            $ttl > 0 ? $ttl : 0,
            null,
            SetCookie::SAME_SITE_LAX
        ));
    }
}
