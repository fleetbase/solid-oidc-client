<?php
/**
 * Simple Authentication Example
 * 
 * This example demonstrates how to use the SolidOidcClient to authenticate
 * with a CommunitySolidServer instance.
 */

require_once '../vendor/autoload.php';

use SolidOidc\SolidOidcClient;
use SolidOidc\SolidOidcException;

session_start();

// Configuration - Replace with your actual values
$config = [
    'issuer_url' => 'https://solidcommunity.net',
    'client_id' => 'your-client-id',
    'client_secret' => 'your-client-secret',
    'redirect_uri' => 'http://localhost:8080/examples/simple_auth.php'
];

try {
    $client = new SolidOidcClient(
        $config['issuer_url'],
        $config['client_id'],
        $config['client_secret'],
        $config['redirect_uri']
    );

    // Perform discovery
    $client->discover();

    // Check if we're handling a callback
    if (isset($_GET['code']) && isset($_GET['state'])) {
        // Verify state parameter
        if (!isset($_SESSION['oauth_state']) || $_GET['state'] !== $_SESSION['oauth_state']) {
            throw new Exception('Invalid state parameter');
        }

        // Exchange code for tokens
        $tokens = $client->handleAuthorizationResponse($_GET['code'], $_GET['state']);
        
        // Store tokens in session (in production, use secure storage)
        $_SESSION['access_token'] = $tokens['access_token'];
        $_SESSION['id_token'] = $tokens['id_token'];
        $_SESSION['id_token_claims'] = $tokens['id_token_claims'];

        // Get user info
        $userInfo = $client->getUserInfo($tokens['access_token']);
        $_SESSION['user_info'] = $userInfo;

        // Clear state
        unset($_SESSION['oauth_state']);

        // Redirect to avoid refresh issues
        header('Location: ' . $config['redirect_uri']);
        exit;
    }

    // Check if user is already authenticated
    if (isset($_SESSION['access_token'])) {
        // User is authenticated, display user info
        echo "<h1>Authentication Successful!</h1>";
        echo "<h2>ID Token Claims:</h2>";
        echo "<pre>" . json_encode($_SESSION['id_token_claims'], JSON_PRETTY_PRINT) . "</pre>";
        
        echo "<h2>User Info:</h2>";
        echo "<pre>" . json_encode($_SESSION['user_info'], JSON_PRETTY_PRINT) . "</pre>";
        
        echo '<p><a href="?logout=1">Logout</a></p>';
    } else {
        // Handle logout
        if (isset($_GET['logout'])) {
            session_destroy();
            header('Location: ' . $config['redirect_uri']);
            exit;
        }

        // User is not authenticated, show login link
        $state = bin2hex(random_bytes(16));
        $_SESSION['oauth_state'] = $state;
        
        $authUrl = $client->getAuthorizationUrl($state, ['openid', 'profile', 'email']);
        
        echo "<h1>Solid OIDC Authentication Example</h1>";
        echo "<p>Click the link below to authenticate with your Solid Pod:</p>";
        echo '<p><a href="' . htmlspecialchars($authUrl) . '">Login with Solid</a></p>';
    }

} catch (SolidOidcException $e) {
    echo "<h1>Authentication Error</h1>";
    echo "<p><strong>Error:</strong> " . htmlspecialchars($e->getMessage()) . "</p>";
    echo "<p><strong>Error Code:</strong> " . htmlspecialchars($e->getErrorCode()) . "</p>";
    
    if ($e->getContext()) {
        echo "<p><strong>Context:</strong></p>";
        echo "<pre>" . htmlspecialchars(json_encode($e->getContext(), JSON_PRETTY_PRINT)) . "</pre>";
    }
} catch (Exception $e) {
    echo "<h1>General Error</h1>";
    echo "<p><strong>Error:</strong> " . htmlspecialchars($e->getMessage()) . "</p>";
}
?>

