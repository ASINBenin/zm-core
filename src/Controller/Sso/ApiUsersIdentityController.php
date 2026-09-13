<?php declare(strict_types=1);

namespace Monarc\Core\Controller\Sso;

use Laminas\Mvc\Controller\AbstractRestfulController;
use Laminas\View\Model\JsonModel;
use Monarc\Core\Service\Sso\IdentityManagementService;

class ApiUsersIdentityController extends AbstractRestfulController
{
    public function __construct(private IdentityManagementService $identityService)
    {
    }

    // Liste toutes les identités SSO liées à l'utilisateur
    public function getList()
    {
        $userId = (int)$this->params()->fromRoute('userId');
        return new JsonModel($this->identityService->getUserIdentities($userId));
    }

    public function create($data)
    {
        $userId = (int)$this->params()->fromRoute('userId');
        $providerCode = $data['providerCode'] ?? 'trustedx_pki';
        $providerIdentifier = trim((string)($data['providerIdentifier'] ?? ''));

        if (empty($providerIdentifier)) {
            $this->getResponse()->setStatusCode(400);
            return new JsonModel(['error' => "L'identifiant SSO / NPI est requis."]);
        }

        try {
            $this->identityService->linkUserIdentityById($userId, (string)$providerCode, $providerIdentifier);
            return new JsonModel(['success' => true]);
        } catch (\Throwable $e) {
            $this->getResponse()->setStatusCode(400);
            return new JsonModel(['error' => $e->getMessage()]);
        }
    }

    // Délie une identité SSO précise (:id = id de la ligne `identities`)
    public function delete($id)
    {
        $userId = (int)$this->params()->fromRoute('userId');

        try {
            $this->identityService->unlinkIdentityById($userId, (int)$id);
            return new JsonModel(['success' => true]);
        } catch (\Throwable $e) {
            $this->getResponse()->setStatusCode((int)($e->getCode() ?: 400));
            return new JsonModel(['error' => $e->getMessage()]);
        }
    }

    // Délie toutes les identités SSO de l'utilisateur
    public function deleteList($data)
    {
        $userId = (int)$this->params()->fromRoute('userId');
        $this->identityService->unlinkAllUserIdentities($userId);

        return new JsonModel(['success' => true]);
    }
}
