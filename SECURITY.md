# Security Policy

## Supported Versions

We release patches for security vulnerabilities. Currently supported versions:

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Reporting a Vulnerability

We take the security of the Vercel OAuth2 Provider seriously. If you believe you have found a security vulnerability, please report it to us as described below.

### Please do NOT:

- Open a public GitHub issue for security vulnerabilities
- Publicly disclose the vulnerability before it has been addressed

### Please DO:

**Report security vulnerabilities to: chernegasergiy3@gmail.com**

Please include the following information:

1. **Type of vulnerability** (e.g., XSS, CSRF, token leakage, etc.)
2. **Full paths** of source file(s) related to the vulnerability
3. **Location** of the affected source code (tag/branch/commit or direct URL)
4. **Step-by-step instructions** to reproduce the issue
5. **Proof-of-concept or exploit code** (if possible)
6. **Impact** of the issue, including how an attacker might exploit it

### What to Expect

1. **Acknowledgment**: We will acknowledge receipt of your report within 48 hours
2. **Investigation**: We will investigate and validate the report
3. **Fix Development**: We will develop and test a fix
4. **Disclosure Timeline**: We aim to disclose vulnerabilities within 90 days
5. **Credit**: We will credit you in the security advisory (unless you prefer to remain anonymous)

## Security Best Practices

When using this library, please follow these security best practices:

### 1. Environment Variables

Never commit credentials to version control:

```php
// ✅ Good - use environment variables
$provider = new Vercel([
    'clientId'     => $_ENV['VERCEL_APP_CLIENT_ID'],
    'clientSecret' => $_ENV['VERCEL_APP_CLIENT_SECRET'],
    'redirectUri'  => $_ENV['VERCEL_REDIRECT_URI'],
]);

// ❌ Bad - hardcoded credentials
$provider = new Vercel([
    'clientId'     => 'cl_abc123...',  // Never do this!
    'clientSecret' => 'secret123...',  // Never do this!
]);
```

### 2. Use HTTPS in Production

Always use HTTPS for the redirect URI in production:

```php
// ✅ Good
'redirectUri' => 'https://yourapp.com/callback'

// ❌ Bad in production
'redirectUri' => 'http://yourapp.com/callback'
```

### 3. Validate State Parameter

Always verify the state parameter to prevent CSRF attacks:

```php
if ($_GET['state'] !== $_SESSION['oauth2state']) {
    exit('Invalid state - possible CSRF attack');
}
```

### 4. Store Tokens Securely

Use secure, HTTP-only cookies or encrypted database storage:

```php
// ✅ Good - secure cookie
setcookie('access_token', $token, [
    'httponly' => true,
    'secure' => true,
    'samesite' => 'Lax',
]);

// ❌ Bad - exposed in JavaScript
echo "<script>var token = '$token';</script>";
```

### 5. Implement Token Refresh

Check token expiration and refresh proactively:

```php
if ($accessToken->hasExpired()) {
    $accessToken = $provider->getAccessToken('refresh_token', [
        'refresh_token' => $accessToken->getRefreshToken()
    ]);
}
```

### 6. Revoke Tokens on Logout

Always revoke tokens when users log out:

```php
$provider->revokeToken($accessToken->getToken());
if ($accessToken->getRefreshToken()) {
    $provider->revokeToken($accessToken->getRefreshToken());
}
```

### 7. Validate ID Tokens

The library automatically validates ID tokens, but ensure you:

- Don't disable signature verification
- Verify the issuer matches Vercel
- Check the audience matches your client ID
- Validate nonce if using replay protection

### 8. Use Latest Version

Always use the latest version to get security patches:

```bash
composer update fyennyi/oauth2-vercel
```

### 9. Rate Limiting

Implement rate limiting for authentication endpoints:

```php
// Example with basic rate limiting
$key = 'auth_attempts_' . $_SERVER['REMOTE_ADDR'];
$attempts = $_SESSION[$key] ?? 0;

if ($attempts > 5) {
    http_response_code(429);
    exit('Too many attempts. Please try again later.');
}

$_SESSION[$key] = $attempts + 1;
```

### 10. Secure Session Configuration

Configure PHP sessions securely:

```php
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_secure', 1);
ini_set('session.cookie_samesite', 'Lax');
ini_set('session.use_strict_mode', 1);
ini_set('session.use_only_cookies', 1);
```

## Known Security Considerations

### Session Fixation

PHP sessions are vulnerable to session fixation. Regenerate session IDs after login:

```php
session_regenerate_id(true);
```

### Token Storage

- Store tokens server-side when possible
- Encrypt tokens if storing in database
- Use secure, HTTP-only cookies for web apps
- Never expose tokens in URLs or logs

### PKCE Implementation

This library implements PKCE (S256) by default. Do not disable it:

```php
// The library handles PKCE automatically
// Never try to disable it for "convenience"
```

## Vulnerability Disclosure Policy

When we receive a security bug report, we will:

1. Confirm the problem and determine affected versions
2. Audit code to find similar problems
3. Prepare fixes for all supported versions
4. Release new versions with the security patch
5. Publish a security advisory

## Security Updates

Security updates will be released as:

- **Critical**: Within 24-48 hours
- **High**: Within 1 week
- **Medium**: Within 2-4 weeks
- **Low**: In next regular release

## Compliance

This library follows:

- OAuth 2.0 RFC 6749
- OAuth 2.0 Bearer Token Usage RFC 6750
- PKCE RFC 7636
- OpenID Connect Core 1.0
- JWT RFC 7519

## Contact

For security concerns: chernegasergiy3@gmail.com

For general issues: https://github.com/Fyennyi/oauth2-vercel/issues

## Hall of Fame

We recognize security researchers who help make this project more secure:

<!-- This section will be updated as vulnerabilities are responsibly disclosed -->

*No vulnerabilities disclosed yet*

---

Thank you for helping keep the Vercel OAuth2 Provider and its users safe!
