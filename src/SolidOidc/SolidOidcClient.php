<?php

namespace SolidOidc;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Firebase\JWT\JWK;

/**
 * PHP OIDC Client for CommunitySolidServer with DPoP support
 * 
 * This class implements OpenID Connect authentication specifically for
 * CommunitySolidServer, including support for Demonstrating Proof-of-Possession (DPoP).
 */
class SolidOidcClient
{
    private string $issuerUrl;
    private string $clientId;
    private string $clientSecret;
    private string $redirectUri;
    private array $discoveryDocument = [];
    private ?string $privateKey = null;
    private ?array $publicKeyJwk = null;
    private array $jwks = [];

    /**
     * Constructor
     * 
     * @param string $issuerUrl The base URL of the OIDC issuer
     * @param string $clientId The client ID registered with the OIDC provider
     * @param string $clientSecret The client secret for confidential clients
     * @param string $redirectUri The URI where the OIDC provider redirects after authorization
     */
    public function __construct(string $issuerUrl, string $clientId, string $clientSecret, string $redirectUri)
    {
        $this->issuerUrl = rtrim($issuerUrl, '/');
        $this->clientId = $clientId;
        $this->clientSecret = $clientSecret;
        $this->redirectUri = $redirectUri;
        
        // Generate DPoP key pair on initialization
        $this->generateKeyPair();
    }

    /**
     * Fetch and parse the OIDC discovery document
     * 
     * @throws SolidOidcException If discovery fails or document is invalid
     */
    public function discover(): void
    {
        $discoveryUrl = $this->issuerUrl . '/.well-known/openid-configuration';
        
        try {
            $response = $this->sendHttpRequest('GET', $discoveryUrl);
        } catch (\Exception $e) {
            throw SolidOidcException::discoveryFailed('Failed to fetch discovery document: ' . $e->getMessage(), ['url' => $discoveryUrl]);
        }
        
        if (!isset($response['issuer'])) {
            throw SolidOidcException::discoveryFailed('Invalid discovery document: missing issuer', ['response' => $response]);
        }
        
        $this->discoveryDocument = $response;
        
        // Fetch JWKS for token validation
        if (isset($this->discoveryDocument['jwks_uri'])) {
            try {
                $jwksResponse = $this->sendHttpRequest('GET', $this->discoveryDocument['jwks_uri']);
                $this->jwks = $jwksResponse;
            } catch (\Exception $e) {
                throw SolidOidcException::discoveryFailed('Failed to fetch JWKS: ' . $e->getMessage(), ['jwks_uri' => $this->discoveryDocument['jwks_uri']]);
            }
        }
    }

    /**
     * Generate the authorization URL for redirection
     * 
     * @param string $state Unique state parameter for CSRF protection
     * @param array $scopes Array of requested scopes
     * @return string The authorization URL
     * @throws SolidOidcException If discovery document is not loaded
     */
    public function getAuthorizationUrl(string $state, array $scopes = ['openid', 'profile']): string
    {
        if (empty($this->discoveryDocument)) {
            throw SolidOidcException::authenticationFailed('Discovery document not loaded. Call discover() first.');
        }
        
        $params = [
            'response_type' => 'code',
            'client_id' => $this->clientId,
            'redirect_uri' => $this->redirectUri,
            'scope' => implode(' ', $scopes),
            'state' => $state,
        ];
        
        return $this->discoveryDocument['authorization_endpoint'] . '?' . http_build_query($params);
    }

    /**
     * Exchange authorization code for tokens and handle DPoP
     * 
     * @param string $code The authorization code from the callback
     * @param string $state The state parameter from the callback
     * @return array Array containing tokens and user information
     * @throws \Exception If token exchange fails or validation fails
     */
    public function handleAuthorizationResponse(string $code, string $state): array
    {
        if (empty($this->discoveryDocument)) {
            throw new \Exception('Discovery document not loaded. Call discover() first.');
        }
        
        // Prepare token request
        $tokenEndpoint = $this->discoveryDocument['token_endpoint'];
        $body = [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $this->redirectUri,
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret,
        ];
        
        // Make token request with DPoP
        $response = $this->sendHttpRequest('POST', $tokenEndpoint, [], $body, true);
        
        if (!isset($response['access_token']) || !isset($response['id_token'])) {
            throw new \Exception('Invalid token response: missing required tokens');
        }
        
        // Validate ID token
        $idTokenClaims = $this->validateIdToken($response['id_token']);
        
        return [
            'access_token' => $response['access_token'],
            'id_token' => $response['id_token'],
            'refresh_token' => $response['refresh_token'] ?? null,
            'token_type' => $response['token_type'] ?? 'Bearer',
            'expires_in' => $response['expires_in'] ?? null,
            'id_token_claims' => $idTokenClaims,
        ];
    }

    /**
     * Fetch user information using the access token and DPoP
     * 
     * @param string $accessToken The access token
     * @return array User information from the userinfo endpoint
     * @throws \Exception If userinfo request fails
     */
    public function getUserInfo(string $accessToken): array
    {
        if (empty($this->discoveryDocument)) {
            throw new \Exception('Discovery document not loaded. Call discover() first.');
        }
        
        if (!isset($this->discoveryDocument['userinfo_endpoint'])) {
            throw new \Exception('Userinfo endpoint not available');
        }
        
        $userinfoEndpoint = $this->discoveryDocument['userinfo_endpoint'];
        
        return $this->sendHttpRequest('GET', $userinfoEndpoint, [
            'Authorization' => 'Bearer ' . $accessToken
        ], [], true, $accessToken);
    }

    /**
     * Generate a DPoP JWT proof
     * 
     * @param string $method HTTP method
     * @param string $url HTTP URL
     * @param string|null $accessToken Access token for ath claim
     * @return string The DPoP JWT
     */
    private function generateDpopProof(string $method, string $url, ?string $accessToken = null): string
    {
        $header = [
            'typ' => 'dpop+jwt',
            'alg' => 'RS256',
            'jwk' => $this->publicKeyJwk,
        ];
        
        $payload = [
            'jti' => bin2hex(random_bytes(16)),
            'htm' => $method,
            'htu' => $url,
            'iat' => time(),
        ];
        
        // Add access token hash if provided
        if ($accessToken !== null) {
            $payload['ath'] = base64url_encode(hash('sha256', $accessToken, true));
        }
        
        return JWT::encode($payload, $this->privateKey, 'RS256', null, $header);
    }

    /**
     * Generate RSA key pair for DPoP
     */
    private function generateKeyPair(): void
    {
        $config = [
            'digest_alg' => 'sha256',
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ];
        
        $resource = openssl_pkey_new($config);
        if (!$resource) {
            throw new \Exception('Failed to generate key pair: ' . openssl_error_string());
        }
        
        // Export private key
        openssl_pkey_export($resource, $this->privateKey);
        
        // Get public key details
        $details = openssl_pkey_get_details($resource);
        if (!$details) {
            throw new \Exception('Failed to get key details: ' . openssl_error_string());
        }
        
        // Convert to JWK format
        $this->publicKeyJwk = [
            'kty' => 'RSA',
            'use' => 'sig',
            'alg' => 'RS256',
            'n' => base64url_encode($details['rsa']['n']),
            'e' => base64url_encode($details['rsa']['e']),
        ];
    }

    /**
     * Send HTTP request with optional DPoP support
     * 
     * @param string $method HTTP method
     * @param string $url Request URL
     * @param array $headers Additional headers
     * @param array $body Request body
     * @param bool $withDpop Whether to include DPoP header
     * @param string|null $accessToken Access token for DPoP ath claim
     * @return array Parsed JSON response
     * @throws \Exception If request fails
     */
    private function sendHttpRequest(string $method, string $url, array $headers = [], array $body = [], bool $withDpop = false, ?string $accessToken = null): array
    {
        $ch = curl_init();
        
        // Basic cURL options
        curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_TIMEOUT => 30,
            CURLOPT_CUSTOMREQUEST => $method,
        ]);
        
        // Set headers
        $requestHeaders = [
            'Accept: application/json',
            'User-Agent: SolidOidcClient/1.0',
        ];
        
        // Add DPoP header if requested
        if ($withDpop) {
            $dpopProof = $this->generateDpopProof($method, $url, $accessToken);
            $requestHeaders[] = 'DPoP: ' . $dpopProof;
        }
        
        // Add custom headers
        foreach ($headers as $name => $value) {
            $requestHeaders[] = $name . ': ' . $value;
        }
        
        curl_setopt($ch, CURLOPT_HTTPHEADER, $requestHeaders);
        
        // Handle request body
        if (!empty($body)) {
            if ($method === 'POST') {
                curl_setopt($ch, CURLOPT_POST, true);
                curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($body));
                curl_setopt($ch, CURLOPT_HTTPHEADER, array_merge($requestHeaders, [
                    'Content-Type: application/x-www-form-urlencoded'
                ]));
            }
        }
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);
        curl_close($ch);
        
        if ($response === false) {
            throw new \Exception('cURL error: ' . $error);
        }
        
        if ($httpCode >= 400) {
            throw new \Exception('HTTP error ' . $httpCode . ': ' . $response);
        }
        
        $decoded = json_decode($response, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new \Exception('Invalid JSON response: ' . json_last_error_msg());
        }
        
        return $decoded;
    }

    /**
     * Validate ID Token signature and claims
     * 
     * @param string $idToken The ID token JWT
     * @return array Decoded token claims
     * @throws \Exception If validation fails
     */
    private function validateIdToken(string $idToken): array
    {
        if (empty($this->jwks)) {
            throw new \Exception('JWKS not loaded. Cannot validate ID token.');
        }
        
        try {
            // Decode header to get key ID
            $header = json_decode(base64_decode(explode('.', $idToken)[0]), true);
            $kid = $header['kid'] ?? null;
            
            // Find the appropriate key
            $key = null;
            foreach ($this->jwks['keys'] as $jwk) {
                if ($kid === null || $jwk['kid'] === $kid) {
                    $key = $jwk;
                    break;
                }
            }
            
            if (!$key) {
                throw new \Exception('Unable to find appropriate key for ID token validation');
            }
            
            // Convert JWK to PEM and validate
            $keyObject = JWK::parseKey($key);
            $decoded = JWT::decode($idToken, $keyObject);
            
            // Validate claims
            $claims = (array) $decoded;
            
            // Check issuer
            if ($claims['iss'] !== $this->discoveryDocument['issuer']) {
                throw new \Exception('Invalid issuer in ID token');
            }
            
            // Check audience
            if ($claims['aud'] !== $this->clientId) {
                throw new \Exception('Invalid audience in ID token');
            }
            
            // Check expiration
            if ($claims['exp'] < time()) {
                throw new \Exception('ID token has expired');
            }
            
            return $claims;
            
        } catch (\Exception $e) {
            throw new \Exception('ID token validation failed: ' . $e->getMessage());
        }
    }
}

/**
 * Base64url encode function
 * 
 * @param string $data Data to encode
 * @return string Base64url encoded string
 */
function base64url_encode(string $data): string
{
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

/**
 * Base64url decode function
 * 
 * @param string $data Data to decode
 * @return string Decoded string
 */
function base64url_decode(string $data): string
{
    return base64_decode(str_pad(strtr($data, '-_', '+/'), strlen($data) % 4, '=', STR_PAD_RIGHT));
}

