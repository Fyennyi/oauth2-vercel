<?php
/**
 * Basic Example - Sign in with Vercel
 * 
 * This example demonstrates the complete OAuth 2.0 flow with Vercel.
 * 
 * Setup:
 * 1. Create a .env file with your Vercel app credentials
 * 2. Install dependencies: composer install
 * 3. Run: php -S localhost:8000
 * 4. Visit: http://localhost:8000/examples/basic.php
 */

require_once __DIR__ . '/../vendor/autoload.php';

// Load environment variables (you can use vlucas/phpdotenv or similar)
$dotenv = file_exists(__DIR__ . '/../.env') 
    ? parse_ini_file(__DIR__ . '/../.env') 
    : [];

$clientId = $dotenv['VERCEL_APP_CLIENT_ID'] ?? $_ENV['VERCEL_APP_CLIENT_ID'] ?? '';
$clientSecret = $dotenv['VERCEL_APP_CLIENT_SECRET'] ?? $_ENV['VERCEL_APP_CLIENT_SECRET'] ?? '';
$redirectUri = 'http://localhost:8000/examples/basic.php';

if (empty($clientId) || empty($clientSecret)) {
    die('Please set VERCEL_APP_CLIENT_ID and VERCEL_APP_CLIENT_SECRET');
}

session_start();

// Initialize the provider
$provider = new \Fyennyi\OAuth2\Client\Provider\Vercel([
    'clientId'     => $clientId,
    'clientSecret' => $clientSecret,
    'redirectUri'  => $redirectUri,
]);

// Check if we have an authorization code
if (!isset($_GET['code'])) {
    
    // No code - start the authorization flow
    $authorizationUrl = $provider->getAuthorizationUrl([
        'scope' => ['openid', 'email', 'profile', 'offline_access']
    ]);
    
    // Store state for CSRF protection
    $_SESSION['oauth2state'] = $provider->getState();
    
    // Display sign in page
    ?>
    <!DOCTYPE html>
    <html>
    <head>
        <title>Sign in with Vercel - Example</title>
        <style>
            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                max-width: 600px;
                margin: 50px auto;
                padding: 20px;
            }
            .button {
                background: black;
                color: white;
                padding: 12px 24px;
                border: none;
                border-radius: 8px;
                font-size: 16px;
                cursor: pointer;
                text-decoration: none;
                display: inline-block;
            }
            .button:hover {
                background: #333;
            }
        </style>
    </head>
    <body>
        <h1>Sign in with Vercel</h1>
        <p>This is a basic example demonstrating OAuth 2.0 authentication with Vercel.</p>
        <a href="<?php echo htmlspecialchars($authorizationUrl); ?>" class="button">
            Sign in with Vercel
        </a>
    </body>
    </html>
    <?php
    exit;
}

// We have a code - verify state and exchange it for a token
if (empty($_GET['state']) || 
    (isset($_SESSION['oauth2state']) && $_GET['state'] !== $_SESSION['oauth2state'])) {
    
    unset($_SESSION['oauth2state']);
    exit('Invalid state - possible CSRF attack');
}

try {
    // Exchange the authorization code for an access token
    $accessToken = $provider->getAccessToken('authorization_code', [
        'code' => $_GET['code']
    ]);
    
    // Get the user's information
    $user = $provider->getResourceOwner($accessToken);
    
    // Display success page
    ?>
    <!DOCTYPE html>
    <html>
    <head>
        <title>Signed In - Vercel Example</title>
        <style>
            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                max-width: 600px;
                margin: 50px auto;
                padding: 20px;
            }
            .profile {
                background: #f5f5f5;
                padding: 20px;
                border-radius: 8px;
                margin: 20px 0;
            }
            .profile img {
                width: 80px;
                height: 80px;
                border-radius: 50%;
                margin-bottom: 10px;
            }
            .info {
                margin: 10px 0;
            }
            .label {
                font-weight: bold;
                color: #666;
            }
            .button {
                background: black;
                color: white;
                padding: 12px 24px;
                border: none;
                border-radius: 8px;
                font-size: 16px;
                cursor: pointer;
                text-decoration: none;
                display: inline-block;
                margin-top: 20px;
            }
        </style>
    </head>
    <body>
        <h1>✓ Successfully Signed In!</h1>
        
        <div class="profile">
            <?php if ($user->getPicture()): ?>
                <img src="<?php echo htmlspecialchars($user->getPicture()); ?>" 
                     alt="Profile Picture">
            <?php endif; ?>
            
            <div class="info">
                <span class="label">ID:</span>
                <?php echo htmlspecialchars($user->getId()); ?>
            </div>
            
            <div class="info">
                <span class="label">Name:</span>
                <?php echo htmlspecialchars($user->getName()); ?>
            </div>
            
            <div class="info">
                <span class="label">Email:</span>
                <?php echo htmlspecialchars($user->getEmail()); ?>
                <?php if ($user->isEmailVerified()): ?>
                    ✓ Verified
                <?php endif; ?>
            </div>
            
            <div class="info">
                <span class="label">Username:</span>
                @<?php echo htmlspecialchars($user->getPreferredUsername()); ?>
            </div>
        </div>
        
        <h2>Token Information</h2>
        <div class="profile">
            <div class="info">
                <span class="label">Access Token:</span>
                <?php echo substr($accessToken->getToken(), 0, 20); ?>...
            </div>
            
            <div class="info">
                <span class="label">Expires:</span>
                <?php echo date('Y-m-d H:i:s', $accessToken->getExpires()); ?>
            </div>
            
            <div class="info">
                <span class="label">Has Expired:</span>
                <?php echo $accessToken->hasExpired() ? 'Yes' : 'No'; ?>
            </div>
            
            <?php if ($accessToken->getRefreshToken()): ?>
            <div class="info">
                <span class="label">Refresh Token:</span>
                <?php echo substr($accessToken->getRefreshToken(), 0, 20); ?>...
            </div>
            <?php endif; ?>
        </div>
        
        <a href="basic.php" class="button">Sign in Again</a>
    </body>
    </html>
    <?php
    
} catch (\League\OAuth2\Client\Provider\Exception\IdentityProviderException $e) {
    // Handle OAuth errors
    ?>
    <!DOCTYPE html>
    <html>
    <head>
        <title>Error - Vercel Example</title>
        <style>
            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                max-width: 600px;
                margin: 50px auto;
                padding: 20px;
            }
            .error {
                background: #fee;
                color: #c00;
                padding: 20px;
                border-radius: 8px;
                border: 1px solid #fcc;
            }
            .button {
                background: black;
                color: white;
                padding: 12px 24px;
                border: none;
                border-radius: 8px;
                font-size: 16px;
                cursor: pointer;
                text-decoration: none;
                display: inline-block;
                margin-top: 20px;
            }
        </style>
    </head>
    <body>
        <h1>Error</h1>
        <div class="error">
            <strong>OAuth Error:</strong>
            <?php echo htmlspecialchars($e->getMessage()); ?>
        </div>
        <a href="basic.php" class="button">Try Again</a>
    </body>
    </html>
    <?php
}
