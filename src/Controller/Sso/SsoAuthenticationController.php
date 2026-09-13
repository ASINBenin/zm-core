<?php declare(strict_types=1);

namespace Monarc\Core\Controller\Sso;

use Laminas\Mvc\Controller\AbstractActionController;
use Monarc\Core\Service\Sso\IdentityManagementService;

class SsoAuthenticationController extends AbstractActionController
{
    public function __construct(private IdentityManagementService $identityService)
    {
    }

    public function redirectAction()
    {
        $providerCode = $this->params()->fromQuery('provider', 'trustedx_pki');
        $authUrl = $this->identityService->getAuthorizationUrl($providerCode);
        
        return $this->redirect()->toUrl($authUrl);
    }

    public function callbackAction()
    {
        $params = $this->params()->fromQuery();
        $redirectUrl = $this->identityService->processSsoCallback($params);

        return $this->redirect()->toUrl($redirectUrl);
    }
}
