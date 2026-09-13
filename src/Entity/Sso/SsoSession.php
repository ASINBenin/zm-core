<?php declare(strict_types=1);

namespace Monarc\Core\Entity\Sso;

use Doctrine\ORM\Mapping as ORM;

/**
 * Session/tokens OAuth2 d'un utilisateur pour un provider SSO.
 * `$userId` : voir la note dans Identity.php — entier simple, pas de relation Doctrine,
 * pour rester utilisable par n'importe quelle application consommatrice (FO, BO...).
 *
 * @ORM\Entity
 * @ORM\Table(name="sso_sessions", indexes={
 *     @ORM\Index(name="idx_sso_user_session", columns={"user_id", "session_token"})
 * })
 */
class SsoSession
{
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
     * @ORM\JoinColumn(name="provider_id", referencedColumnName="id", nullable=false, onDelete="CASCADE")
     */
    private Provider $provider;

    /**
     * @ORM\Column(type="string", length=100, name="session_token", nullable=false)
     */
    private string $sessionToken;

    /**
     * @ORM\Column(type="text", name="access_token_encrypted", nullable=false)
     */
    private string $accessTokenEncrypted;

    /**
     * @ORM\Column(type="text", name="refresh_token_encrypted", nullable=true)
     */
    private ?string $refreshTokenEncrypted = null;

    /**
     * @ORM\Column(type="text", name="id_token_encrypted", nullable=true)
     */
    private ?string $idTokenEncrypted = null;

    /**
     * @ORM\Column(type="string", length=50, name="token_type", options={"default": "Bearer"})
     */
    private string $tokenType = 'Bearer';

    /**
     * @ORM\Column(type="text", name="scope", nullable=true)
     */
    private ?string $scope = null;

    /**
     * @ORM\Column(type="datetime", name="expires_at", nullable=true)
     */
    private ?\DateTime $expiresAt = null;

    /**
     * @ORM\Column(type="datetime", name="created_at", options={"default": "CURRENT_TIMESTAMP"})
     */
    private \DateTime $createdAt;

    /**
     * @ORM\Column(type="datetime", name="updated_at", options={"default": "CURRENT_TIMESTAMP"})
     */
    private \DateTime $updatedAt;

    public function __construct()
    {
        $this->createdAt = new \DateTime();
        $this->updatedAt = new \DateTime();
    }

    public function getId(): int { return $this->id; }
    public function getUserId(): int { return $this->userId; }
    public function setUserId(int $userId): self { $this->userId = $userId; return $this; }
    public function getProvider(): Provider { return $this->provider; }
    public function setProvider(Provider $provider): self { $this->provider = $provider; return $this; }
    public function getSessionToken(): string { return $this->sessionToken; }
    public function setSessionToken(string $sessionToken): self { $this->sessionToken = $sessionToken; return $this; }
    public function getAccessTokenEncrypted(): string { return $this->accessTokenEncrypted; }
    public function setAccessTokenEncrypted(string $token): self { $this->accessTokenEncrypted = $token; return $this; }
    public function getRefreshTokenEncrypted(): ?string { return $this->refreshTokenEncrypted; }
    public function setRefreshTokenEncrypted(?string $token): self { $this->refreshTokenEncrypted = $token; return $this; }
    public function getIdTokenEncrypted(): ?string { return $this->idTokenEncrypted; }
    public function setIdTokenEncrypted(?string $token): self { $this->idTokenEncrypted = $token; return $this; }
    public function getTokenType(): string { return $this->tokenType; }
    public function setTokenType(string $tokenType): self { $this->tokenType = $tokenType; return $this; }
    public function getScope(): ?string { return $this->scope; }
    public function setScope(?string $scope): self { $this->scope = $scope; return $this; }
    public function getExpiresAt(): ?\DateTime { return $this->expiresAt; }
    public function setExpiresAt(?\DateTime $expiresAt): self { $this->expiresAt = $expiresAt; return $this; }
    public function getCreatedAt(): \DateTime { return $this->createdAt; }
    public function getUpdatedAt(): \DateTime { return $this->updatedAt; }
}
