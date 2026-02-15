# Vercel Provider for OAuth 2.0 Client

[![Latest Stable Version](https://img.shields.io/packagist/v/fyennyi/oauth2-vercel.svg?label=Packagist&logo=packagist)](https://packagist.org/packages/fyennyi/oauth2-vercel)
[![Total Downloads](https://img.shields.io/packagist/dt/fyennyi/oauth2-vercel.svg?label=Downloads&logo=packagist)](https://packagist.org/packages/fyennyi/oauth2-vercel)
[![License](https://img.shields.io/packagist/l/fyennyi/oauth2-vercel.svg?label=License)](https://packagist.org/packages/fyennyi/oauth2-vercel)
[![PHP Version](https://img.shields.io/packagist/php-v/fyennyi/oauth2-vercel.svg)](https://packagist.org/packages/fyennyi/oauth2-vercel)

This package provides Vercel OAuth 2.0 support for the PHP League's [OAuth 2.0 Client](https://github.com/thephpleague/oauth2-client).

## Features

- 🔐 **Full OAuth 2.0 & OIDC Support** - Implements authorization code flow with PKCE
- 🎯 **Automatic Endpoint Discovery** - Configures endpoints from Vercel's OIDC discovery document
- ✅ **ID Token Validation** - Cryptographically validates ID tokens using JWKS
- 🔍 **Token Introspection** - Check token validity and metadata
- 🚫 **Token Revocation** - Invalidate tokens when needed
- 📦 **Easy Integration** - Works seamlessly with `league/oauth2-client`

## Installation

Install via Composer:

```bash
composer require fyennyi/oauth2-vercel
```

### Requirements

- PHP 7.4 or higher
- `league/oauth2-client` ^2.0
- `guzzlehttp/guzzle` ^7.0
- `firebase/php-jwt` ^6.0

## Quick Start

### 1. Create a Vercel App

Before using this library, you need to create an app in your Vercel account:

1. Go to your [Vercel Team Settings](https://vercel.com/dashboard/settings)
2. Navigate to **Apps** and click **Create**
3. Configure your app:
   - **Name**: Your app name
   - **Client Authentication**: Choose your preferred method
   - **Authorization Callback URL**: Add your callback URL (e.g., `https://yourapp.com/callback`)
   - **Permissions**: Select scopes (`openid`, `email`, `profile`, `offline_access`)
4. Generate a **Client Secret** (if using confidential client authentication)
5. Save your **Client ID** and **Client Secret**

### 2. Initialize the Provider

```php
<?php
require_once 'vendor/autoload.php';

session_start();

$provider = new \Fyennyi\OAuth2\Client\Provider\Vercel([
    'clientId'     => 'your-client-id',
    'clientSecret' => 'your-client-secret',
    'redirectUri'  => 'https://yourapp.com/callback',
]);
```

### 3. Authorization Flow

**Redirect to Vercel for authorization:**

```php
if (!isset($_GET['code'])) {
    // Generate and store state for CSRF protection
    $authorizationUrl = $provider->getAuthorizationUrl([
        'scope' => ['openid', 'email', 'profile', 'offline_access']
    ]);
    
    $_SESSION['oauth2state'] = $provider->getState();
    
    header('Location: ' . $authorizationUrl);
    exit;
}
```

**Handle the callback:**

```php
// Verify state to prevent CSRF
if (empty($_GET['state']) || 
    (isset($_SESSION['oauth2state']) && $_GET['state'] !== $_SESSION['oauth2state'])) {
    unset($_SESSION['oauth2state']);
    exit('Invalid state');
}

try {
    // Exchange code for access token
    $accessToken = $provider->getAccessToken('authorization_code', [
        'code' => $_GET['code']
    ]);

    // Access token details
    echo 'Access Token: ' . $accessToken->getToken() . "\n";
    echo 'Refresh Token: ' . $accessToken->getRefreshToken() . "\n";
    echo 'Expires: ' . date('Y-m-d H:i:s', $accessToken->getExpires()) . "\n";

    // Get user information
    $user = $provider->getResourceOwner($accessToken);
    
    echo 'User ID: ' . $user->getId() . "\n";
    echo 'Email: ' . $user->getEmail() . "\n";
    echo 'Name: ' . $user->getName() . "\n";
    echo 'Username: ' . $user->getPreferredUsername() . "\n";

} catch (\League\OAuth2\Client\Provider\Exception\IdentityProviderException $e) {
    exit('Error: ' . $e->getMessage());
}
```

## Advanced Usage

### Refreshing an Access Token

```php
if ($accessToken->hasExpired()) {
    $newAccessToken = $provider->getAccessToken('refresh_token', [
        'refresh_token' => $accessToken->getRefreshToken()
    ]);
    
    // Use the new access token
}
```

### Token Introspection

Check if a token is active and view its metadata:

```php
$introspection = $provider->introspectToken($accessToken->getToken());

if ($introspection['active']) {
    echo "Token is active\n";
    echo "Subject: " . $introspection['sub'] . "\n";
    echo "Expires: " . date('Y-m-d H:i:s', $introspection['exp']) . "\n";
} else {
    echo "Token is not active\n";
}
```

### Token Revocation

Invalidate a token (logout):

```php
// Revoke the access token
$provider->revokeToken($accessToken->getToken());

// Revoke the refresh token (optional)
if ($accessToken->getRefreshToken()) {
    $provider->revokeToken($accessToken->getRefreshToken());
}
```

### Manual Endpoint Configuration

If you need to override specific endpoints:

```php
$provider = new \Fyennyi\OAuth2\Client\Provider\Vercel([
    'clientId'            => 'your-client-id',
    'clientSecret'        => 'your-client-secret',
    'redirectUri'         => 'https://yourapp.com/callback',
    'issuer'              => 'https://vercel.com',
    
    // Optional: Override specific endpoints
    'baseAccessTokenUrl'  => 'https://custom-token-endpoint.com',
]);
```

## Available Scopes

Configure which user information your app can access:

| Scope | Description |
|-------|-------------|
| `openid` | Required for OIDC - issues an ID token |
| `email` | Access to user's email address |
| `profile` | Access to user's name, username, and picture |
| `offline_access` | Issues a refresh token for extended access |

Example with custom scopes:

```php
$authorizationUrl = $provider->getAuthorizationUrl([
    'scope' => ['openid', 'email', 'profile']
]);
```

## User Data Methods

The `VercelUser` resource owner provides these methods:

```php
$user = $provider->getResourceOwner($accessToken);

$user->getId();                    // string - User's unique identifier
$user->getEmail();                 // string - User's email address
$user->isEmailVerified();          // bool   - Whether email is verified
$user->getName();                  // string - User's full name
$user->getPreferredUsername();     // string - User's username
$user->getPicture();               // string - URL to profile picture
$user->toArray();                  // array  - All user data
```

## Security Best Practices

1. **Always verify the state parameter** to prevent CSRF attacks
2. **Store tokens securely** - Never expose them in client-side code
3. **Use HTTPS** for all OAuth flows in production
4. **Implement token refresh** to maintain sessions without re-authentication
5. **Revoke tokens** when users log out or when compromised
6. **Validate ID tokens** - This library automatically validates signatures and claims

## Error Handling

```php
try {
    $accessToken = $provider->getAccessToken('authorization_code', [
        'code' => $_GET['code']
    ]);
} catch (\League\OAuth2\Client\Provider\Exception\IdentityProviderException $e) {
    // OAuth error from Vercel
    echo 'OAuth Error: ' . $e->getMessage();
    
    // Get detailed error information
    $response = $e->getResponseBody();
    echo 'Error Code: ' . $response['error'];
    echo 'Description: ' . $response['error_description'];
} catch (\Exception $e) {
    // Other errors
    echo 'Error: ' . $e->getMessage();
}
```

## Testing

Run the test suite:

```bash
composer test
```

Run static analysis:

```bash
composer phpstan
```

Check coding standards:

```bash
composer phpcs
```

Run all checks:

```bash
composer check
```

## Documentation

- [Vercel Sign in with Vercel Documentation](https://vercel.com/docs/sign-in-with-vercel)
- [OAuth 2.0 Client Documentation](https://oauth2-client.thephpleague.com/)
- [Troubleshooting Guide](TROUBLESHOOTING.md)
- [Contributing Guidelines](CONTRIBUTING.md)
- [Architecture Overview](ARCHITECTURE.md)
- [Next.js Integration Guide](NEXTJS_INTEGRATION.md)
- [Code Comparison: PHP vs Next.js](COMPARISON.md)

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## License

This library is licensed under the CSSM Unlimited License v2.0. See the [LICENSE](LICENSE) file for details.

## Credits

- **Author**: Serhii Cherneha
- **Vendor**: Fyennyi
- **Based on**: [league/oauth2-client](https://github.com/thephpleague/oauth2-client)

## Support

- **Issues**: [GitHub Issues](https://github.com/fyennyi/oauth2-vercel/issues)
- **Discussions**: [GitHub Discussions](https://github.com/fyennyi/oauth2-vercel/discussions)
- **Email**: chernegasergiy3@gmail.com

## Related Projects

- [league/oauth2-client](https://github.com/thephpleague/oauth2-client) - OAuth 2.0 Client Library
- [Vercel Documentation](https://vercel.com/docs) - Official Vercel Documentation
