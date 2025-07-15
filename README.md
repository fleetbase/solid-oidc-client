# Solid OIDC Client for PHP

A PHP library for authenticating with CommunitySolidServer using OpenID Connect (OIDC) with Demonstrating Proof-of-Possession (DPoP) support.

## Features

- Full OpenID Connect Authorization Code Flow implementation
- Demonstrating Proof-of-Possession (DPoP) support for enhanced security
- Automatic OIDC discovery
- ID Token validation with JWKS
- Comprehensive error handling with custom exceptions
- Support for custom scopes and claims
- Compatible with CommunitySolidServer and other Solid-OIDC providers

## Requirements

- PHP 8.1 or higher
- cURL extension
- JSON extension
- OpenSSL extension
- Composer for dependency management

## Installation

1. Clone or download this library
2. Install dependencies using Composer:

```bash
composer install
```

## Quick Start

### Basic Authentication Flow

```php
<?php
require_once 'vendor/autoload.php';

use SolidOidc\SolidOidcClient;
use SolidOidc\SolidOidcException;

// Initialize the client
$client = new SolidOidcClient(
    'https://solidcommunity.net',        // Issuer URL
    'your-client-id',                    // Client ID
    'your-client-secret',                // Client Secret
    'http://localhost:8080/callback'     // Redirect URI
);

try {
    // Perform OIDC discovery
    $client->discover();
    
    // Generate authorization URL
    $state = bin2hex(random_bytes(16));
    $authUrl = $client->getAuthorizationUrl($state, ['openid', 'profile']);
    
    // Redirect user to authorization URL
    header('Location: ' . $authUrl);
    
} catch (SolidOidcException $e) {
    echo "Error: " . $e->getMessage();
}
```

### Handling the Callback

```php
<?php
// In your callback handler (e.g., callback.php)

if (isset($_GET['code']) && isset($_GET['state'])) {
    try {
        // Exchange code for tokens
        $tokens = $client->handleAuthorizationResponse($_GET['code'], $_GET['state']);
        
        // Access the tokens
        $accessToken = $tokens['access_token'];
        $idToken = $tokens['id_token'];
        $idTokenClaims = $tokens['id_token_claims'];
        
        // Get user information
        $userInfo = $client->getUserInfo($accessToken);
        
        // Store tokens securely (session, database, etc.)
        $_SESSION['access_token'] = $accessToken;
        $_SESSION['user_info'] = $userInfo;
        
    } catch (SolidOidcException $e) {
        echo "Authentication failed: " . $e->getMessage();
    }
}
```

## Configuration

### Client Registration

Before using this library, you need to register your application with the Solid OIDC provider:

1. **For CommunitySolidServer**: Visit your pod's settings or use the registration endpoint
2. **For SolidCommunity.net**: Use their client registration interface
3. **For custom instances**: Follow the provider's client registration process

You'll need to provide:
- **Client Name**: A human-readable name for your application
- **Redirect URIs**: The callback URLs where users will be redirected after authentication
- **Scopes**: The permissions your application requires (e.g., `openid`, `profile`, `email`)

### Required Configuration Parameters

```php
$config = [
    'issuer_url' => 'https://your-solid-server.example.com',
    'client_id' => 'your-registered-client-id',
    'client_secret' => 'your-client-secret',
    'redirect_uri' => 'https://your-app.example.com/callback'
];
```

## API Reference

### SolidOidcClient Class

#### Constructor

```php
public function __construct(
    string $issuerUrl,
    string $clientId,
    string $clientSecret,
    string $redirectUri
)
```

**Parameters:**
- `$issuerUrl`: The base URL of the OIDC issuer (e.g., `https://solidcommunity.net`)
- `$clientId`: Your registered client identifier
- `$clientSecret`: Your client secret (for confidential clients)
- `$redirectUri`: The callback URL registered with the provider

#### Methods

##### `discover(): void`

Fetches and parses the OIDC discovery document from the provider's well-known endpoint.

**Throws:** `SolidOidcException` if discovery fails

##### `getAuthorizationUrl(string $state, array $scopes = ['openid', 'profile']): string`

Generates the authorization URL for redirecting users to the OIDC provider.

**Parameters:**
- `$state`: A unique, unguessable string for CSRF protection
- `$scopes`: Array of requested OAuth 2.0 scopes

**Returns:** The complete authorization URL

**Throws:** `SolidOidcException` if discovery hasn't been performed

##### `handleAuthorizationResponse(string $code, string $state): array`

Exchanges the authorization code for tokens and validates the ID token.

**Parameters:**
- `$code`: The authorization code from the callback
- `$state`: The state parameter from the callback

**Returns:** Array containing:
- `access_token`: The access token for API requests
- `id_token`: The ID token (JWT) containing user identity claims
- `refresh_token`: The refresh token (if available)
- `token_type`: Token type (usually "Bearer")
- `expires_in`: Token lifetime in seconds
- `id_token_claims`: Decoded and validated ID token claims

**Throws:** `SolidOidcException` for authentication or validation failures

##### `getUserInfo(string $accessToken): array`

Retrieves user profile information from the userinfo endpoint.

**Parameters:**
- `$accessToken`: A valid access token

**Returns:** Array of user profile information

**Throws:** `SolidOidcException` if the request fails

### Exception Handling

The library uses custom exceptions for better error handling:

```php
use SolidOidc\SolidOidcException;

try {
    // Your OIDC operations
} catch (SolidOidcException $e) {
    echo "Error: " . $e->getMessage();
    echo "Code: " . $e->getErrorCode();
    
    // Get additional context
    $context = $e->getContext();
    if ($context) {
        print_r($context);
    }
}
```

#### Exception Types

- `DISCOVERY_FAILED`: Issues with fetching or parsing the discovery document
- `AUTHENTICATION_FAILED`: Problems during the authentication flow
- `TOKEN_VALIDATION_FAILED`: ID token validation errors
- `DPOP_FAILED`: DPoP-related failures
- `HTTP_REQUEST_FAILED`: Network or HTTP errors

## Security Considerations

### State Parameter

Always use a cryptographically secure random state parameter:

```php
$state = bin2hex(random_bytes(16));
// Store $state in session for validation
$_SESSION['oauth_state'] = $state;
```

Validate the state parameter in your callback:

```php
if ($_GET['state'] !== $_SESSION['oauth_state']) {
    throw new Exception('Invalid state parameter - possible CSRF attack');
}
```

### Token Storage

- **Never store tokens in client-side storage** (localStorage, cookies without HttpOnly flag)
- **Use secure session storage** or encrypted database storage
- **Implement token expiration handling**
- **Consider using refresh tokens** for long-lived sessions

### HTTPS Requirements

- **All communication must use HTTPS** in production
- **Redirect URIs must use HTTPS** (except for localhost during development)
- **Validate SSL certificates** (don't disable SSL verification)

### DPoP Security

This library automatically handles DPoP (Demonstrating Proof-of-Possession) which:
- Binds access tokens to the client
- Prevents token replay attacks
- Provides cryptographic proof of token possession

## Examples

### Complete Authentication Flow

See `examples/simple_auth.php` for a complete working example.

### Advanced Usage

See `examples/advanced_auth.php` for advanced features including:
- Custom scopes
- Resource access
- Error handling
- Token information display

## Troubleshooting

### Common Issues

#### Discovery Fails
- Verify the issuer URL is correct and accessible
- Check that the server supports OIDC discovery
- Ensure network connectivity and SSL certificates are valid

#### Authentication Fails
- Verify client ID and secret are correct
- Check that redirect URI matches exactly what's registered
- Ensure the authorization code hasn't expired

#### Token Validation Fails
- Check system clock synchronization
- Verify JWKS endpoint is accessible
- Ensure ID token hasn't expired

#### DPoP Errors
- Verify OpenSSL extension is installed and working
- Check that the server supports DPoP
- Ensure proper key generation and signing

### Debug Mode

Enable verbose error reporting for debugging:

```php
// Enable all error reporting
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Use try-catch blocks to capture detailed error information
try {
    $client->discover();
} catch (SolidOidcException $e) {
    echo "Detailed error: " . $e->getMessage() . "\n";
    echo "Error code: " . $e->getErrorCode() . "\n";
    echo "Context: " . json_encode($e->getContext(), JSON_PRETTY_PRINT) . "\n";
}
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is open source. Please check the LICENSE file for details.

## Support

For issues and questions:
1. Check the troubleshooting section above
2. Review the examples for proper usage
3. Create an issue with detailed error information and context

## Changelog

### Version 1.0.0
- Initial release
- Full OIDC Authorization Code Flow support
- DPoP implementation
- Comprehensive error handling
- Examples and documentation

