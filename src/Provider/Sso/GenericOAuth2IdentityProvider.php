<?php declare(strict_types=1);

namespace Monarc\Core\Provider\Sso;

use Monarc\Core\Exception\Exception;

class GenericOAuth2IdentityProvider implements IdentityProviderInterface
{
    protected array $config;

    public function __construct(array $config)
    {
        $this->config = $config;
    }

    public function getAuthorizationUrl(string $state): string
    {
        return $this->buildAuthorizationUrl($state, $this->getRedirectUri());
    }

    public function getAuthorizationUrlWithRedirect(string $state, string $redirectUri): string
    {
        return $this->buildAuthorizationUrl($state, $redirectUri);
    }

    public function handleCallback(array $params): ExternalIdentityDto
    {
        $code = $params['code'] ?? null;
        if (!$code) {
            throw new Exception("Code d'autorisation OAuth2 manquant dans la réponse.", 400);
        }

        $tokenResponse = $this->exchangeCodeForToken($code);
        $accessToken = $tokenResponse['access_token'] ?? null;

        if (!$accessToken) {
            throw new Exception("Échec de récupération de l'access token depuis le serveur d'autorisation.", 400);
        }

        $userInfo = $this->fetchUserInfo($accessToken);

        if (!empty($tokenResponse['id_token'])) {
            $jwtPayload = $this->decodeIdToken((string)$tokenResponse['id_token']);
            if (is_array($jwtPayload)) {
                $userInfo = array_merge($jwtPayload, $userInfo);
            }
        }

        $sub = isset($userInfo['sub']) ? (string)$userInfo['sub'] : null;
        $claimKey = (string)($this->config['identifier_claim']);

        if (!isset($userInfo[$claimKey]) || trim((string)$userInfo[$claimKey]) === '') {
            throw new Exception("La claim d'identité '{$claimKey}' est absente des données renvoyées par le fournisseur SSO.", 400);
        }

        $providerIdentifier = trim((string)$userInfo[$claimKey]);

        return new ExternalIdentityDto(
            sub: (string)$sub,
            providerIdentifier: $providerIdentifier,
            email: $userInfo['email'] ?? null,
            firstname: $userInfo['given_name'] ?? $userInfo['first_name'] ?? null,
            lastname: $userInfo['family_name'] ?? $userInfo['last_name'] ?? null,
            rawAttributes: array_merge($userInfo, ['_token_response' => $tokenResponse])
        );
    }

    public function refreshAccessToken(string $refreshToken): array
    {
        $tokenUrl = $this->config['token_url'] ?? '';
        $clientId = $this->config['client_id'] ?? '';
        $clientSecret = $this->config['client_secret'] ?? '';

        $postData = [
            'grant_type'    => 'refresh_token',
            'refresh_token' => $refreshToken,
        ];

        $ch = curl_init($tokenUrl);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => http_build_query($postData),
            CURLOPT_HTTPHEADER => [
                'Authorization: Basic ' . base64_encode("$clientId:$clientSecret"),
                'Content-Type: application/x-www-form-urlencoded',
                'Accept: application/json',
            ],
            CURLOPT_TIMEOUT => 15,
        ]);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);
        curl_close($ch);

        if ($error) {
            throw new Exception("Erreur réseau lors du rafraîchissement du token: $error", 500);
        }

        $data = json_decode((string)$response, true);
        if ($httpCode >= 400 || empty($data['access_token'])) {
            $msg = $data['error_description'] ?? $data['error'] ?? "Erreur HTTP $httpCode lors du refresh token";
            throw new Exception("Échec du rafraîchissement OAuth2: $msg", 400);
        }

        return $data;
    }

    protected function getRedirectUri(): string
    {
        if (!empty($this->config['redirect_uri'])) {
            return (string)$this->config['redirect_uri'];
        }

        $appUrl = $this->config['app_url'] ?? (getenv('APP_URL') ?: null);
        if (!empty($appUrl)) {
            return rtrim((string)$appUrl, '/') . '/auth/sso/callback';
        }

        $httpHost = $_SERVER['HTTP_HOST'] ?? 'localhost:5001';
        $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';

        return "{$scheme}://{$httpHost}/auth/sso/callback";
    }

    private function buildAuthorizationUrl(string $state, string $redirectUri): string
    {
        $params = [
            'response_type' => 'code',
            'client_id'     => $this->config['client_id'] ?? '',
            'redirect_uri'  => $redirectUri,
            'scope'         => $this->config['scope'] ?? 'openid profile email',
            'state'         => $state,
        ];

        if (!empty($this->config['acr_values'])) {
            $params['acr_values'] = $this->config['acr_values'];
        }

        $url = $this->config['authorize_url'] ?? '';

        return $url . (str_contains($url, '?') ? '&' : '?') . http_build_query($params);
    }

    protected function exchangeCodeForToken(string $code): array
    {
        $tokenUrl = $this->config['token_url'] ?? '';
        $clientId = $this->config['client_id'] ?? '';
        $clientSecret = $this->config['client_secret'] ?? '';

        $postData = [
            'grant_type'   => 'authorization_code',
            'code'         => $code,
            'redirect_uri' => $this->getRedirectUri(),
        ];

        $ch = curl_init($tokenUrl);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => http_build_query($postData),
            CURLOPT_HTTPHEADER => [
                'Authorization: Basic ' . base64_encode("$clientId:$clientSecret"),
                'Content-Type: application/x-www-form-urlencoded',
                'Accept: application/json',
            ],
            CURLOPT_TIMEOUT => 15,
        ]);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);
        curl_close($ch);

        if ($error) {
            throw new Exception("Erreur réseau lors de l'échange de token: $error", 500);
        }

        $data = json_decode((string)$response, true);
        if ($httpCode >= 400 || empty($data['access_token'])) {
            $msg = $data['error_description'] ?? $data['error'] ?? "Erreur HTTP $httpCode lors du token exchange";
            throw new Exception("Erreur d'authentification OAuth2: $msg", 400);
        }

        return $data;
    }

    protected function fetchUserInfo(string $accessToken): array
    {
        $userInfoUrl = $this->config['userinfo_url'] ?? '';
        if (empty($userInfoUrl)) {
            return [];
        }

        $ch = curl_init($userInfoUrl);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => '',
            CURLOPT_HTTPHEADER => [
                'Authorization: Bearer ' . $accessToken,
                'Accept: application/json',
            ],
            CURLOPT_TIMEOUT => 15,
        ]);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);
        curl_close($ch);

        if ($error) {
            throw new Exception("Erreur réseau lors de la récupération des infos utilisateur: $error", 500);
        }

        $data = json_decode((string)$response, true);
        if ($httpCode >= 400 || !is_array($data)) {
            throw new Exception("Impossible de récupérer le profil utilisateur (HTTP $httpCode).", 400);
        }

        return $data;
    }

    private function decodeIdToken(string $idToken): ?array
    {
        $parts = explode('.', $idToken);
        if (count($parts) !== 3) {
            return null;
        }
        [$headerB64, $payloadB64, $signatureB64] = $parts;

        $payload = json_decode(base64_decode(strtr($payloadB64, '-_', '+/')), true);
        if (!is_array($payload)) {
            return null;
        }

        $jwksUrl = $this->config['jwks_url'] ?? '';
        if (empty($jwksUrl)) {
            return $payload;
        }

        if (!$this->verifyIdTokenSignature($headerB64, $payloadB64, $signatureB64, $jwksUrl)) {
            throw new Exception("Signature du id_token OIDC invalide : authentification SSO rejetée.", 400);
        }

        return $payload;
    }

    private function verifyIdTokenSignature(string $headerB64, string $payloadB64, string $signatureB64, string $jwksUrl): bool
    {
        $header = json_decode(base64_decode(strtr($headerB64, '-_', '+/')), true);
        if (!is_array($header) || ($header['alg'] ?? '') !== 'RS256') {
            return false;
        }

        $ch = curl_init($jwksUrl);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 10,
        ]);
        $jwksResponse = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($httpCode !== 200) {
            return false;
        }

        $jwks = json_decode((string)$jwksResponse, true);
        if (empty($jwks['keys']) || !is_array($jwks['keys'])) {
            return false;
        }

        $kid = $header['kid'] ?? null;
        $jwk = null;
        foreach ($jwks['keys'] as $candidate) {
            if ($kid === null || ($candidate['kid'] ?? null) === $kid) {
                $jwk = $candidate;
                break;
            }
        }

        if (!$jwk || empty($jwk['n']) || empty($jwk['e'])) {
            return false;
        }

        $publicKeyPem = $this->rsaJwkToPem((string)$jwk['n'], (string)$jwk['e']);
        $signedData = $headerB64 . '.' . $payloadB64;
        $signature = base64_decode(strtr($signatureB64, '-_', '+/'));

        return openssl_verify($signedData, $signature, $publicKeyPem, OPENSSL_ALGO_SHA256) === 1;
    }

    private function rsaJwkToPem(string $modulusB64, string $exponentB64): string
    {
        $modulus = base64_decode(strtr($modulusB64, '-_', '+/'));
        $exponent = base64_decode(strtr($exponentB64, '-_', '+/'));

        $rsaPublicKey = $this->asnSequence(
            $this->asnInteger($modulus) . $this->asnInteger($exponent)
        );

        $algorithmIdentifier = pack('H*', '300d06092a864886f70d0101010500');
        $publicKeyBitString = "\x03" . $this->asnLength(strlen($rsaPublicKey) + 1) . "\x00" . $rsaPublicKey;
        $publicKeyInfo = $this->asnSequence($algorithmIdentifier . $publicKeyBitString);

        return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($publicKeyInfo), 64, "\n") . "-----END PUBLIC KEY-----\n";
    }

    private function asnLength(int $length): string
    {
        if ($length < 128) {
            return chr($length);
        }
        $bytes = ltrim(pack('N', $length), "\x00");

        return chr(0x80 | strlen($bytes)) . $bytes;
    }

    private function asnInteger(string $bytes): string
    {
        if (ord($bytes[0]) > 0x7f) {
            $bytes = "\x00" . $bytes;
        }

        return "\x02" . $this->asnLength(strlen($bytes)) . $bytes;
    }

    private function asnSequence(string $bytes): string
    {
        return "\x30" . $this->asnLength(strlen($bytes)) . $bytes;
    }
}
