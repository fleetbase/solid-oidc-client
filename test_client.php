<?php

require_once 'vendor/autoload.php';

use SolidOidc\SolidOidcClient;
use SolidOidc\SolidOidcException;

// Test configuration (replace with actual values)
$issuerUrl = 'https://solidcommunity.net';
$clientId = 'test-client-id';
$clientSecret = 'test-client-secret';
$redirectUri = 'http://localhost:8080/callback';

try {
    echo "Creating SolidOidcClient...\n";
    $client = new SolidOidcClient($issuerUrl, $clientId, $clientSecret, $redirectUri);
    
    echo "Performing discovery...\n";
    $client->discover();
    echo "Discovery successful!\n";
    
    echo "Generating authorization URL...\n";
    $state = bin2hex(random_bytes(16));
    $authUrl = $client->getAuthorizationUrl($state, ['openid', 'profile']);
    echo "Authorization URL: " . $authUrl . "\n";
    
    echo "\nTest completed successfully!\n";
    
} catch (SolidOidcException $e) {
    echo "SolidOidc Error: " . $e->getMessage() . "\n";
    echo "Error Code: " . $e->getErrorCode() . "\n";
    if ($e->getContext()) {
        echo "Context: " . json_encode($e->getContext(), JSON_PRETTY_PRINT) . "\n";
    }
} catch (Exception $e) {
    echo "General Error: " . $e->getMessage() . "\n";
}

