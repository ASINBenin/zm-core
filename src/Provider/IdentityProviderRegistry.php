<?php declare(strict_types=1);

namespace Monarc\Core\Provider;

class IdentityProviderRegistry
{
    /** @var IdentityProviderInterface[] */
    private array $providers = [];

    public function registerProvider(string $code, IdentityProviderInterface $provider): self
    {
        $this->providers[$code] = $provider;
        return $this;
    }

    public function getProvider(string $code): IdentityProviderInterface
    {
        if (!isset($this->providers[$code])) {
            throw new \InvalidArgumentException("Fournisseur d'identité OAuth2 '{$code}' non enregistré.");
        }
        return $this->providers[$code];
    }

    public function hasProvider(string $code): bool
    {
        return isset($this->providers[$code]);
    }
}