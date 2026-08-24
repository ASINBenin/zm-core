<?php declare(strict_types=1);

namespace Monarc\Core\Provider;

use Interop\Container\ContainerInterface;
use Laminas\ServiceManager\Factory\FactoryInterface;

/**
 * Usine dynamique universelle : instancie le fournisseur d'identité à partir de local.php
 */
class IdentityProviderFactory implements FactoryInterface
{
    public function __invoke(ContainerInterface $container, $requestedName, ?array $options = null): IdentityProviderInterface
    {
        $config = $container->get('config');
        $ssoProviders = $config['sso_providers'] ?? [];

        // Récupère le premier fournisseur actif
        $activeCode = null;
        $activeConfig = [];
        foreach ($ssoProviders as $code => $providerData) {
            if (!isset($providerData['is_active']) || $providerData['is_active']) {
                $activeCode = (string)$code;
                $activeConfig = $providerData;
                break;
            }
        }

        if (!$activeCode || empty($activeConfig)) {
            return new GenericOAuth2IdentityProvider();
        }

        // On associe le code du fournisseur
        $activeConfig['provider_code'] = $activeCode;

        // On transmet directement la totalité de la configuration au moteur OAuth2
        return new GenericOAuth2IdentityProvider($activeConfig);
    }
}