<?php declare(strict_types=1);

namespace Monarc\Core\Entity;

use Doctrine\ORM\Mapping as ORM;
use Monarc\Core\Entity\UserSuperClass;

/**
 * @ORM\Entity
 * @ORM\Table(name="identities", uniqueConstraints={
 *     @ORM\UniqueConstraint(name="uk_provider_identifier", columns={"provider_id", "provider_identifier"})
 * })
 */
class Identity
{
    /**
     * @ORM\Id
     * @ORM\Column(type="integer")
     * @ORM\GeneratedValue(strategy="AUTO")
     */
    private int $id;

    /**
     * @ORM\ManyToOne(targetEntity="Monarc\Core\Entity\UserSuperClass")
     * @ORM\JoinColumn(name="user_id", referencedColumnName="id", nullable=false, onDelete="CASCADE")
     */
    private UserSuperClass $user;

    /**
     * @ORM\ManyToOne(targetEntity="Monarc\Core\Entity\Provider")
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

    /**
     * @ORM\Column(type="datetime", name="created_at", options={"default": "CURRENT_TIMESTAMP"})
     */
    private \DateTime $createdAt;

    public function __construct()
    {
        $this->createdAt = new \DateTime();
    }

    public function getId(): int { return $this->id; }
    public function getUser(): UserSuperClass { return $this->user; }
    public function setUser(UserSuperClass $user): self { $this->user = $user; return $this; }
    public function getProvider(): Provider { return $this->provider; }
    public function setProvider(Provider $provider): self { $this->provider = $provider; return $this; }
    public function getProviderIdentifier(): string { return $this->providerIdentifier; }
    public function setProviderIdentifier(string $providerIdentifier): self { $this->providerIdentifier = $providerIdentifier; return $this; }
    public function getSub(): ?string { return $this->sub; }
    public function setSub(?string $sub): self { $this->sub = $sub; return $this; }
    public function getExtraData(): ?string { return $this->extraData; }
    public function setExtraData(?string $extraData): self { $this->extraData = $extraData; return $this; }
    public function getCreatedAt(): \DateTime { return $this->createdAt; }
}
