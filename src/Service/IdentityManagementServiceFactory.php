<?php declare(strict_types=1);

namespace Monarc\Core\Service;

use Interop\Container\ContainerInterface;
use Laminas\ServiceManager\Factory\FactoryInterface;

class IdentityManagementServiceFactory implements FactoryInterface
{
    public function __invoke(ContainerInterface $container, $requestedName, ?array $options = null)
    {
        $entityManager = $container->get('doctrine.entitymanager.orm_cli');
        $config = $container->get('config');

        return new IdentityManagementService($entityManager, $config);
    }
}