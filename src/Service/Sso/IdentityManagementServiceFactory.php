<?php declare(strict_types=1);

namespace Monarc\Core\Service\Sso;

use Psr\Container\ContainerInterface;
use Laminas\ServiceManager\Factory\FactoryInterface;
use Monarc\Core\Service\AuthenticationService;

class IdentityManagementServiceFactory implements FactoryInterface
{
    public function __invoke(ContainerInterface $container, $requestedName, ?array $options = null): IdentityManagementService
    {
        $em = $container->get('doctrine.entitymanager.orm_cli');
        $authService = $container->get(AuthenticationService::class);
        $config = $container->get('Config');

        return new IdentityManagementService($em, $authService, $config);
    }
}
