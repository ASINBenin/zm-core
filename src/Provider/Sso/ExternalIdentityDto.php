<?php declare(strict_types=1);

namespace Monarc\Core\Provider\Sso;

class ExternalIdentityDto
{
    public function __construct(
        public string $sub,
        public string $providerIdentifier,
        public ?string $email = null,
        public ?string $firstname = null,
        public ?string $lastname = null,
        public array $rawAttributes = []
    ) {}
}
