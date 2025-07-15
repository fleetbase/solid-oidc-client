<?php
/**
 * Advanced Authentication Example with Resource Access
 * 
 * This example demonstrates advanced usage of the SolidOidcClient including:
 * - Custom scopes
 * - Resource access with DPoP
 * - Error handling
 * - Token refresh (if supported)
 */

require_once '../vendor/autoload.php';

use SolidOidc\SolidOidcClient;
use SolidOidc\SolidOidcException;

session_start();

// Configuration
$config = [
    'issuer_url' => 'https://solidcommunity.net',
    'client_id' => 'your-client-id',
    'client_secret' => 'your-client-secret',
    'redirect_uri' => 'http://localhost:8080/examples/advanced_auth.php'
];

/**
 * Make an authenticated request to a Solid resource
 */
function makeAuthenticatedRequest($url, $accessToken, $method = 'GET', $body = null) {
    // This is a simplified example of how you might make authenticated requests
    // to Solid resources using the access token and DPoP
    
    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL => $url,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_CUSTOMREQUEST => $method,
        CURLOPT_HTTPHEADER => [
            'Authorization: Bearer ' . $accessToken,
            'Accept: text/turtle, application/ld+json, */*'
        ]
    ]);
    
    if ($body) {
        curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
    }
    
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    
    return [
        'status' => $httpCode,
        'body' => $response
    ];
}

try {
    $client = new SolidOidcClient(
        $config['issuer_url'],
        $config['client_id'],
        $config['client_secret'],
        $config['redirect_uri']
    );

    // Perform discovery
    $client->discover();

    // Handle callback
    if (isset($_GET['code']) && isset($_GET['state'])) {
        if (!isset($_SESSION['oauth_state']) || $_GET['state'] !== $_SESSION['oauth_state']) {
            throw new Exception('Invalid state parameter');
        }

        $tokens = $client->handleAuthorizationResponse($_GET['code'], $_GET['state']);
        
        $_SESSION['tokens'] = $tokens;
        $_SESSION['authenticated_at'] = time();

        // Get user info
        $userInfo = $client->getUserInfo($tokens['access_token']);
        $_SESSION['user_info'] = $userInfo;

        unset($_SESSION['oauth_state']);
        header('Location: ' . $config['redirect_uri']);
        exit;
    }

    // Handle logout
    if (isset($_GET['logout'])) {
        session_destroy();
        header('Location: ' . $config['redirect_uri']);
        exit;
    }

    // Check authentication status
    if (isset($_SESSION['tokens'])) {
        $tokens = $_SESSION['tokens'];
        $userInfo = $_SESSION['user_info'];
        
        echo "<h1>Advanced Solid OIDC Authentication</h1>";
        echo "<h2>Authentication Status: ✅ Authenticated</h2>";
        
        // Display user information
        echo "<h3>User Information</h3>";
        echo "<table border='1' cellpadding='5'>";
        echo "<tr><th>Property</th><th>Value</th></tr>";
        
        foreach ($userInfo as $key => $value) {
            echo "<tr><td>" . htmlspecialchars($key) . "</td><td>" . htmlspecialchars(is_array($value) ? json_encode($value) : $value) . "</td></tr>";
        }
        echo "</table>";
        
        // Display token information
        echo "<h3>Token Information</h3>";
        echo "<table border='1' cellpadding='5'>";
        echo "<tr><th>Token Type</th><th>Value/Info</th></tr>";
        echo "<tr><td>Access Token</td><td>" . htmlspecialchars(substr($tokens['access_token'], 0, 50)) . "...</td></tr>";
        echo "<tr><td>Token Type</td><td>" . htmlspecialchars($tokens['token_type']) . "</td></tr>";
        
        if (isset($tokens['expires_in'])) {
            $expiresAt = $_SESSION['authenticated_at'] + $tokens['expires_in'];
            echo "<tr><td>Expires At</td><td>" . date('Y-m-d H:i:s', $expiresAt) . "</td></tr>";
        }
        
        if (isset($tokens['refresh_token'])) {
            echo "<tr><td>Refresh Token</td><td>Available</td></tr>";
        }
        echo "</table>";
        
        // Resource access example
        echo "<h3>Resource Access Example</h3>";
        if (isset($_POST['resource_url'])) {
            $resourceUrl = $_POST['resource_url'];
            echo "<h4>Accessing: " . htmlspecialchars($resourceUrl) . "</h4>";
            
            try {
                $response = makeAuthenticatedRequest($resourceUrl, $tokens['access_token']);
                echo "<p><strong>Status:</strong> " . $response['status'] . "</p>";
                echo "<p><strong>Response:</strong></p>";
                echo "<pre>" . htmlspecialchars($response['body']) . "</pre>";
            } catch (Exception $e) {
                echo "<p><strong>Error:</strong> " . htmlspecialchars($e->getMessage()) . "</p>";
            }
        }
        
        echo "<form method='post'>";
        echo "<label for='resource_url'>Resource URL:</label><br>";
        echo "<input type='url' id='resource_url' name='resource_url' style='width: 400px;' placeholder='https://your-pod.solidcommunity.net/profile/card'><br><br>";
        echo "<input type='submit' value='Access Resource'>";
        echo "</form>";
        
        echo '<p><a href="?logout=1">Logout</a></p>';
        
    } else {
        // Not authenticated
        $state = bin2hex(random_bytes(16));
        $_SESSION['oauth_state'] = $state;
        
        // Request additional scopes for more comprehensive access
        $scopes = ['openid', 'profile', 'email', 'webid'];
        $authUrl = $client->getAuthorizationUrl($state, $scopes);
        
        echo "<h1>Advanced Solid OIDC Authentication</h1>";
        echo "<h2>Authentication Status: ❌ Not Authenticated</h2>";
        
        echo "<h3>Features Demonstrated:</h3>";
        echo "<ul>";
        echo "<li>Extended scopes (openid, profile, email, webid)</li>";
        echo "<li>Token information display</li>";
        echo "<li>Resource access with DPoP authentication</li>";
        echo "<li>Comprehensive error handling</li>";
        echo "</ul>";
        
        echo "<h3>Requested Scopes:</h3>";
        echo "<ul>";
        foreach ($scopes as $scope) {
            echo "<li><code>" . htmlspecialchars($scope) . "</code></li>";
        }
        echo "</ul>";
        
        echo '<p><a href="' . htmlspecialchars($authUrl) . '" style="background: #007cba; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Authenticate with Solid Pod</a></p>';
    }

} catch (SolidOidcException $e) {
    echo "<h1>Solid OIDC Error</h1>";
    echo "<div style='background: #ffebee; border: 1px solid #f44336; padding: 15px; border-radius: 5px;'>";
    echo "<p><strong>Error:</strong> " . htmlspecialchars($e->getMessage()) . "</p>";
    echo "<p><strong>Error Code:</strong> " . htmlspecialchars($e->getErrorCode()) . "</p>";
    
    if ($e->getContext()) {
        echo "<p><strong>Context:</strong></p>";
        echo "<pre>" . htmlspecialchars(json_encode($e->getContext(), JSON_PRETTY_PRINT)) . "</pre>";
    }
    echo "</div>";
    
    echo '<p><a href="' . $config['redirect_uri'] . '">Try Again</a></p>';
    
} catch (Exception $e) {
    echo "<h1>General Error</h1>";
    echo "<div style='background: #fff3e0; border: 1px solid #ff9800; padding: 15px; border-radius: 5px;'>";
    echo "<p><strong>Error:</strong> " . htmlspecialchars($e->getMessage()) . "</p>";
    echo "</div>";
    
    echo '<p><a href="' . $config['redirect_uri'] . '">Try Again</a></p>';
}
?>

