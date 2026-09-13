<?php declare(strict_types=1);

namespace Monarc\Core\Entity\Sso;

use Doctrine\ORM\Mapping as ORM;
use Monarc\Core\Entity\Traits\CreateEntityTrait;
use Monarc\Core\Entity\Traits\UpdateEntityTrait;

/**
 * @ORM\Entity
 * @ORM\Table(name="providers")
 * @ORM\HasLifecycleCallbacks()
 */
class Provider
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
     * @ORM\Column(type="string", length=50, unique=true, nullable=false)
     */
    private string $code;

    /**
     * @ORM\Column(type="string", length=100, nullable=false)
     */
    private string $name;

    /**
     * @ORM\Column(type="boolean", name="is_active", options={"default": true})
     */
    private bool $isActive = true;

    public function getId(): int { return $this->id; }
    public function getCode(): string { return $this->code; }
    public function setCode(string $code): self { $this->code = $code; return $this; }
    public function getName(): string { return $this->name; }
    public function setName(string $name): self { $this->name = $name; return $this; }
    public function getIsActive(): bool { return $this->isActive; }
    public function setIsActive(bool $isActive): self { $this->isActive = $isActive; return $this; }
}
