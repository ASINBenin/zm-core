<?php declare(strict_types=1);

namespace Monarc\Core\Controller\Sso;

use Laminas\Mvc\Controller\AbstractRestfulController;
use Laminas\View\Model\JsonModel;
use Monarc\Core\Service\Sso\IdentityManagementService;

class ApiIdentityProvidersController extends AbstractRestfulController
{
    public function __construct(private IdentityManagementService $identityService)
    {
    }

    public function getList()
    {
        return new JsonModel($this->identityService->getActiveProviders());
    }

    public function get($id)
    {
        return new JsonModel($this->identityService->getActiveProviders());
    }
}
