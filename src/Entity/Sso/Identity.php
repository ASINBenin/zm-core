<?php declare(strict_types=1);

namespace Monarc\Core\Entity\Sso;

use Doctrine\ORM\Mapping as ORM;
use Monarc\Core\Entity\Traits\CreateEntityTrait;
use Monarc\Core\Entity\Traits\UpdateEntityTrait;

/**
 * Lien entre une identité externe (SSO) et un utilisateur MONARC.
 * `$userId` reste un entier simple (pas de relation Doctrine) : zm-core est partagé entre
 * plusieurs apps, chacune avec sa propre classe User (voir monarc_sso.user_entity_class).
 *
 * @ORM\Entity
 * @ORM\Table(name="identities", uniqueConstraints={
 *     @ORM\UniqueConstraint(name="uniq_user_provider", columns={"user_id", "provider_id"}),
 *     @ORM\UniqueConstraint(name="uniq_provider_identifier", columns={"provider_id", "provider_identifier"})
 * })
 * @ORM\HasLifecycleCallbacks()
 */
class Identity
{
    use CreateEntityTrait;
    use UpdateEntityTrait;

    /**
     * @ORM\Id
     * @ORM\Column(type="integer")
     * @ORM\GeneratedValue(strategy="AUTO")
     */
    private int $id;

    /**
     * @ORM\Column(type="integer", name="user_id", nullable=false)
     */
    private int $userId;

    /**
     * @ORM\ManyToOne(targetEntity="Monarc\Core\Entity\Sso\Provider")
     * @ORM\JoinColumn(name="provider_id", referencedColumnName="id", nullable=false, onDelete="RESTRICT")
     */
    private Provider $provider;

    /**
     * @ORM\Column(type="string", length=100, name="provider_identifier", nullable=false)
     */
    private string $providerIdentifier;

    /**
     * @ORM\Column(type="string", length=255, name="sub", nullable=true)
     */
    private ?string $sub = null;

    /**
     * @ORM\Column(type="text", name="extra_data", nullable=true)
     */
    private ?string $extraData = null;

    public function getId(): int { return $this->id; }
    public function getUserId(): int { return $this->userId; }
    public function setUserId(int $userId): self { $this->userId = $userId; return $this; }
    public function getProvider(): Provider { return $this->provider; }
    public function setProvider(Provider $provider): self { $this->provider = $provider; return $this; }
    public function getProviderIdentifier(): string { return $this->providerIdentifier; }
    public function setProviderIdentifier(string $providerIdentifier): self { $this->providerIdentifier = $providerIdentifier; return $this; }
    public function getSub(): ?string { return $this->sub; }
    public function setSub(?string $sub): self { $this->sub = $sub; return $this; }
    public function getExtraData(): ?string { return $this->extraData; }
    public function setExtraData(?string $extraData): self { $this->extraData = $extraData; return $this; }
}
