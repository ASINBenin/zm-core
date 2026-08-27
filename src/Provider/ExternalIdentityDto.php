<?php declare(strict_types=1);

namespace Monarc\Core\Provider;

class ExternalIdentityDto
{
    public string $providerCode;
    public string $providerIdentifier;
    public ?string $email;
    public ?string $firstname;
    public ?string $lastname;
    public array $attributes;

    public function __construct(
        string $providerCode,
        string $providerIdentifier,
        ?string $email = null,
        ?string $firstname = null,
        ?string $lastname = null,
        array $attributes = []
    ) {
        $this->providerCode = $providerCode;
        $this->providerIdentifier = $providerIdentifier;
        $this->email = $email;
        $this->firstname = $firstname;
        $this->lastname = $lastname;
        $this->attributes = $attributes;
    }
}
