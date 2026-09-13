<?php declare(strict_types=1);

namespace Monarc\Core\Controller\Sso;

use Psr\Container\ContainerInterface;
use Laminas\ServiceManager\Factory\FactoryInterface;
use Monarc\Core\Service\Sso\IdentityManagementService;

class ApiIdentityProvidersControllerFactory implements FactoryInterface
{
    public function __invoke(ContainerInterface $container, $requestedName, ?array $options = null): ApiIdentityProvidersController
    {
        return new ApiIdentityProvidersController($container->get(IdentityManagementService::class));
    }
}
