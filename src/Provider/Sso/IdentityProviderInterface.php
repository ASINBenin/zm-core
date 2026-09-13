<?php declare(strict_types=1);

namespace Monarc\Core\Provider\Sso;

interface IdentityProviderInterface
{
    public function getAuthorizationUrl(string $state): string;
    public function getAuthorizationUrlWithRedirect(string $state, string $redirectUri): string;
    public function handleCallback(array $params): ExternalIdentityDto;
    public function refreshAccessToken(string $refreshToken): array;
}
