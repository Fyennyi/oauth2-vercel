# Troubleshooting Guide

This guide helps you solve common issues when using the Vercel OAuth2 Provider.

## Table of Contents

- [Installation Issues](#installation-issues)
- [Configuration Problems](#configuration-problems)
- [Authorization Flow Errors](#authorization-flow-errors)
- [Token Issues](#token-issues)
- [ID Token Validation Errors](#id-token-validation-errors)
- [API Request Failures](#api-request-failures)
- [Common Error Messages](#common-error-messages)

## Installation Issues

### Composer Install Fails

**Problem:** `composer require fyennyi/oauth2-vercel` fails

**Solutions:**

1. Check PHP version:
   ```bash
   php -v
   ```
   Ensure PHP 7.4 or higher is installed.

2. Update Composer:
   ```bash
   composer self-update
   ```

3. Clear Composer cache:
   ```bash
   composer clear-cache
   composer install
   ```

### Dependency Conflicts

**Problem:** Composer reports dependency conflicts

**Solutions:**

1. Check your `composer.json` for conflicting versions
2. Try updating all dependencies:
   ```bash
   composer update
   ```
3. Use `composer why-not` to diagnose:
   ```bash
   composer why-not fyennyi/oauth2-vercel
   ```

## Configuration Problems

### Missing Client ID or Secret

**Error:** `InvalidArgumentException: The 'clientId' option is required`

**Solution:**

Ensure you provide all required configuration:

```php
$provider = new \Fyennyi\OAuth2\Client\Provider\Vercel([
    'clientId'     => 'your-client-id',      // Required
    'clientSecret' => 'your-client-secret',  // Required
    'redirectUri'  => 'https://yourapp.com/callback',  // Required
]);
```

### Endpoint Discovery Fails

**Error:** `RuntimeException: Failed to discover OIDC endpoints`

**Causes:**
- Network connectivity issues
- Vercel services are down
- Firewall blocking HTTPS requests

**Solutions:**

1. Check network connectivity:
   ```bash
   curl https://vercel.com/.well-known/openid-configuration
   ```

2. Manually configure endpoints:
   ```php
   $provider = new \Fyennyi\OAuth2\Client\Provider\Vercel([
       'clientId'                => 'your-client-id',
       'clientSecret'            => 'your-client-secret',
       'redirectUri'             => 'https://yourapp.com/callback',
       'baseAuthorizationUrl'    => 'https://vercel.com/oauth/authorize',
       'baseAccessTokenUrl'      => 'https://api.vercel.com/login/oauth/token',
       'resourceOwnerDetailsUrl' => 'https://api.vercel.com/login/oauth/userinfo',
       'introspectUrl'           => 'https://api.vercel.com/login/oauth/token/introspect',
       'revokeUrl'               => 'https://api.vercel.com/login/oauth/token/revoke',
       'jwksUrl'                 => 'https://vercel.com/.well-known/jwks',
   ]);
   ```

### Invalid Redirect URI

**Error:** `invalid_request: redirect_uri mismatch`

**Solution:**

1. Verify the redirect URI in your code matches exactly what's configured in Vercel:
   ```php
   'redirectUri' => 'https://yourapp.com/callback'  // Must match exactly
   ```

2. Check Vercel app settings:
   - Go to your [Vercel app settings](https://vercel.com/dashboard/settings)
   - Verify the Authorization Callback URL
   - Ensure protocol (http/https), domain, and path match exactly

3. Common mistakes:
   - Using `http` in production instead of `https`
   - Trailing slashes: `https://app.com/callback/` vs `https://app.com/callback`
   - Wrong subdomain: `www.app.com` vs `app.com`

## Authorization Flow Errors

### State Mismatch Error

**Error:** `Invalid state`

**Cause:** CSRF protection detected a mismatch between sent and received state

**Solutions:**

1. Ensure sessions are working:
   ```php
   session_start();  // Must be called before using provider
   ```

2. Check state handling:
   ```php
   // When redirecting to Vercel
   $authUrl = $provider->getAuthorizationUrl();
   $_SESSION['oauth2state'] = $provider->getState();
   
   // When handling callback
   if ($_GET['state'] !== $_SESSION['oauth2state']) {
       exit('Invalid state');
   }
   ```

3. Verify session configuration:
   ```php
   // Check session settings
   var_dump([
       'session_started' => session_status() === PHP_SESSION_ACTIVE,
       'session_id' => session_id(),
       'session_data' => $_SESSION
   ]);
   ```

### User Cancels Authorization

**Error:** `access_denied: The user canceled the authorization process`

**Solution:**

This is expected behavior. Handle it gracefully:

```php
if (isset($_GET['error']) && $_GET['error'] === 'access_denied') {
    // User cancelled - redirect to login page or show message
    echo "Authorization was cancelled. Please try again.";
    exit;
}
```

### Invalid Authorization Code

**Error:** `invalid_grant: Authorization code is invalid or expired`

**Causes:**
- Code was already used
- Code expired (10 minutes)
- Code was used with wrong client

**Solutions:**

1. Don't reuse authorization codes
2. Complete the exchange within 10 minutes
3. Restart the authorization flow:
   ```php
   header('Location: /login');  // Redirect back to start
   ```

## Token Issues

### Access Token Expired

**Error:** Token returns 401 Unauthorized

**Solution:**

Refresh the access token:

```php
if ($accessToken->hasExpired()) {
    try {
        $newAccessToken = $provider->getAccessToken('refresh_token', [
            'refresh_token' => $accessToken->getRefreshToken()
        ]);
        
        // Store the new token
        $_SESSION['access_token'] = $newAccessToken;
        
    } catch (\Exception $e) {
        // Refresh token also expired - redirect to login
        header('Location: /login');
        exit;
    }
}
```

### Missing Refresh Token

**Problem:** `getRefreshToken()` returns null

**Cause:** The `offline_access` scope was not requested

**Solution:**

Request the `offline_access` scope:

```php
$authUrl = $provider->getAuthorizationUrl([
    'scope' => ['openid', 'email', 'profile', 'offline_access']
]);
```

### Token Revocation Fails

**Error:** `IdentityProviderException` during revocation

**Solutions:**

1. Check token is valid before revoking:
   ```php
   if (!empty($accessToken->getToken())) {
       $provider->revokeToken($accessToken->getToken());
   }
   ```

2. Verify client credentials are correct

3. Token might already be revoked (this is not an error)

## ID Token Validation Errors

### Invalid Issuer Claim

**Error:** `Invalid issuer claim in ID token`

**Cause:** The `iss` claim doesn't match expected issuer

**Solution:**

Verify issuer configuration:

```php
$provider = new \Fyennyi\OAuth2\Client\Provider\Vercel([
    'clientId'     => 'your-client-id',
    'clientSecret' => 'your-client-secret',
    'redirectUri'  => 'https://yourapp.com/callback',
    'issuer'       => 'https://vercel.com',  // Must match token issuer
]);
```

### Invalid Audience Claim

**Error:** `Invalid audience claim in ID token`

**Cause:** Token's `aud` claim doesn't include your client ID

**Solution:**

Verify you're using the correct client ID from your Vercel app settings.

### Invalid Nonce

**Error:** `Invalid nonce in ID token`

**Cause:** Nonce mismatch for replay attack protection

**Solution:**

Ensure nonce is properly stored and retrieved:

```php
// Before authorization
$authUrl = $provider->getAuthorizationUrl();
$_SESSION['oauth2state'] = $provider->getState();
$_SESSION['oauth2nonce'] = bin2hex(random_bytes(16));

// The library automatically validates nonce from session
```

### JWKS Fetch Failure

**Error:** `Failed to parse JWKS`

**Causes:**
- Network issues
- Vercel's JWKS endpoint is unavailable

**Solutions:**

1. Test JWKS endpoint manually:
   ```bash
   curl https://vercel.com/.well-known/jwks
   ```

2. Implement retry logic:
   ```php
   $maxRetries = 3;
   $attempt = 0;
   
   while ($attempt < $maxRetries) {
       try {
           $accessToken = $provider->getAccessToken('authorization_code', [
               'code' => $_GET['code']
           ]);
           break;
       } catch (\Exception $e) {
           $attempt++;
           if ($attempt >= $maxRetries) {
               throw $e;
           }
           sleep(1);
       }
   }
   ```

## API Request Failures

### 401 Unauthorized

**Causes:**
- Token expired
- Invalid token
- Token revoked

**Solution:**

```php
try {
    $user = $provider->getResourceOwner($accessToken);
} catch (\League\OAuth2\Client\Provider\Exception\IdentityProviderException $e) {
    if ($e->getCode() === 401) {
        // Token invalid - refresh or re-authenticate
        if ($accessToken->getRefreshToken()) {
            $accessToken = $provider->getAccessToken('refresh_token', [
                'refresh_token' => $accessToken->getRefreshToken()
            ]);
        } else {
            // Redirect to login
            header('Location: /login');
            exit;
        }
    }
}
```

### 429 Rate Limited

**Error:** Too Many Requests

**Solution:**

Implement rate limiting and retries:

```php
function makeRequestWithRetry($provider, $accessToken, $maxRetries = 3) {
    $attempt = 0;
    
    while ($attempt < $maxRetries) {
        try {
            return $provider->getResourceOwner($accessToken);
        } catch (\Exception $e) {
            if ($e->getCode() === 429) {
                $attempt++;
                if ($attempt >= $maxRetries) {
                    throw $e;
                }
                // Exponential backoff
                sleep(pow(2, $attempt));
            } else {
                throw $e;
            }
        }
    }
}
```

### Network Timeouts

**Error:** Connection timeout or couldn't resolve host

**Solutions:**

1. Increase timeout:
   ```php
   $provider = new \Fyennyi\OAuth2\Client\Provider\Vercel(
       [
           'clientId' => 'your-client-id',
           'clientSecret' => 'your-client-secret',
           'redirectUri' => 'https://yourapp.com/callback',
       ],
       [
           'httpClient' => new \GuzzleHttp\Client([
               'timeout' => 30,  // 30 seconds
               'connect_timeout' => 10,
           ])
       ]
   );
   ```

2. Check firewall/proxy settings
3. Verify DNS resolution

## Common Error Messages

### "Class not found"

**Error:** `Class 'Fyennyi\OAuth2\Client\Provider\Vercel' not found`

**Solutions:**

1. Run composer install:
   ```bash
   composer install
   ```

2. Verify autoload:
   ```php
   require_once 'vendor/autoload.php';
   ```

3. Clear Composer autoload cache:
   ```bash
   composer dump-autoload
   ```

### "Call to undefined method"

**Error:** `Call to undefined method getResourceOwner()`

**Solution:**

Ensure you have the access token before calling methods:

```php
// Correct
$accessToken = $provider->getAccessToken('authorization_code', [
    'code' => $_GET['code']
]);
$user = $provider->getResourceOwner($accessToken);

// Incorrect - missing token
$user = $provider->getResourceOwner();  // Error!
```

## Debugging Tips

### Enable Debug Mode

Log all HTTP requests:

```php
$provider = new \Fyennyi\OAuth2\Client\Provider\Vercel(
    [
        'clientId' => 'your-client-id',
        'clientSecret' => 'your-client-secret',
        'redirectUri' => 'https://yourapp.com/callback',
    ],
    [
        'httpClient' => new \GuzzleHttp\Client([
            'debug' => true,  // Enable Guzzle debug output
        ])
    ]
);
```

### Inspect Tokens

```php
// View token details
var_dump([
    'token' => $accessToken->getToken(),
    'refresh_token' => $accessToken->getRefreshToken(),
    'expires' => date('Y-m-d H:i:s', $accessToken->getExpires()),
    'has_expired' => $accessToken->hasExpired(),
    'values' => $accessToken->getValues(),
]);
```

### Check User Data

```php
$user = $provider->getResourceOwner($accessToken);
var_dump($user->toArray());
```

## Still Having Issues?

1. **Check Vercel Status**: https://www.vercel-status.com/
2. **Review Vercel Documentation**: https://vercel.com/docs/sign-in-with-vercel
3. **Search GitHub Issues**: https://github.com/fyennyi/oauth2-vercel/issues
4. **Create a New Issue**: https://github.com/fyennyi/oauth2-vercel/issues/new

When reporting issues, include:
- PHP version
- Library version
- Error messages (full stack trace)
- Code snippet (remove sensitive data)
- Steps to reproduce
