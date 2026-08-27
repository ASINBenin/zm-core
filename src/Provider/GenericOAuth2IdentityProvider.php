<?php declare(strict_types=1);

namespace Monarc\Core\Provider;

/**
 * Moteur Universel OAuth 2.0 / OpenID Connect (OIDC)
 * Conforme aux spécifications RFC 6749 et OpenID Connect Core 1.0.
 */
class GenericOAuth2IdentityProvider implements IdentityProviderInterface
{
    protected array $config;

    public function __construct(array $config = [])
    {
        $this->config = array_merge([
            'provider_code'    => 'oauth2',
            'authorize_url'    => '',
            'token_url'        => '',
            'userinfo_url'     => '',
            'client_id'        => '',
            'client_secret'    => '',
            'scope'            => 'openid profile email',
            'identifier_claim' => 'sub',
            'acr_values'       => '',
        ], $config);
    }

    public function getAuthorizationUrl(string $redirectUri, string $state): string
    {
        $baseUrl = rtrim($this->config['authorize_url'], '/');
        $params = [
            'response_type' => 'code',
            'client_id'     => $this->config['client_id'],
            'redirect_uri'  => $redirectUri,
            'scope'         => $this->config['scope'],
            'state'         => $state,
        ];

        if (!empty($this->config['acr_values'])) {
            $params['acr_values'] = $this->config['acr_values'];
        }

        return $baseUrl . (str_contains($baseUrl, '?') ? '&' : '?') . http_build_query($params);
    }

    public function authenticateCode(string $code, string $redirectUri): ExternalIdentityDto
    {
       
        // 1. Échange du code d'autorisation contre le jeton d'accès (RFC 6749 Section 4.1.3)
        $ch = curl_init($this->config['token_url']);
        curl_setopt_array($ch, [
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => http_build_query([
                'grant_type'    => 'authorization_code',
                'code'          => $code,
                'redirect_uri'  => $redirectUri,
                'client_id'     => $this->config['client_id'],
                'client_secret' => $this->config['client_secret'],
            ]),
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => false,
        ]);
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curlError = curl_error($ch);
        curl_close($ch);


        $tokenData = json_decode((string)$response, true);
        $accessToken = $tokenData['access_token'] ?? null;

        if (!$accessToken) {
            throw new \RuntimeException("Échec d'authentification OAuth2 : jeton non obtenu (HTTP {$httpCode} - Réponse: {$response}).");
        }

        $userData = is_array($tokenData) ? $tokenData : [];

        // 2. Décodage du jeton id_token (JWT OIDC) si présent dans la réponse
        if (!empty($tokenData['id_token'])) {
            $parts = explode('.', $tokenData['id_token']);
            if (count($parts) >= 2) {
                $jwtPayload = json_decode(base64_decode(strtr($parts[1], '-_', '+/')), true);
                if (is_array($jwtPayload)) {
                    $userData = array_merge($userData, $jwtPayload);
                }
            }
        }

        // 3. Interrogation de l'endpoint UserInfo (OIDC Core 1.0 Section 5.3)
        if (!empty($this->config['userinfo_url'])) {
            $ch = curl_init($this->config['userinfo_url']);
            curl_setopt_array($ch, [
                CURLOPT_HTTPHEADER     => ["Authorization: Bearer {$accessToken}"],
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_SSL_VERIFYPEER => false,
                CURLOPT_SSL_VERIFYHOST => false,
            ]);
            $userinfoResponse = curl_exec($ch);
            $uHttpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);

            if ($uHttpCode === 200 && !empty($userinfoResponse)) {
                $decoded = json_decode((string)$userinfoResponse, true);
                if (is_array($decoded)) {
                    $userData = array_merge($userData, $decoded);
                }
            }
        }

        // 4. Extraction dynamique de la claim unique (sub, npi, email, preferred_username)
        $claim = $this->config['identifier_claim'];
        $identifier = $userData[$claim] ?? $userData['sub'] ?? $userData['npi'] ?? $userData['user_id'] ?? null;

        if (!$identifier) {
            throw new \RuntimeException("Erreur de profil OAuth2 : La claim d'identité '{$claim}' est absente des données : " . json_encode($userData));
        }

        return new ExternalIdentityDto(
            $this->config['provider_code'],
            (string)$identifier,
            $userData['email'] ?? null,
            $userData['first_name'] ?? ($userData['given_name'] ?? null),
            $userData['last_name'] ?? ($userData['family_name'] ?? null),
            $userData
        );
    }
}