# Code Comparison: PHP vs Next.js

This document compares the implementation of "Sign in with Vercel" using this PHP library versus the official Next.js implementation.

## Table of Contents

- [Installation](#installation)
- [Provider Initialization](#provider-initialization)
- [Authorization Flow](#authorization-flow)
- [Token Exchange](#token-exchange)
- [Getting User Information](#getting-user-information)
- [Token Refresh](#token-refresh)
- [Token Revocation](#token-revocation)
- [Key Differences](#key-differences)
- [Advantages of Each Approach](#advantages-of-each-approach)

## Installation

### PHP

```bash
composer require fyennyi/oauth2-vercel
```

### Next.js

No external package needed - use built-in Next.js features:
- API Routes
- Server Components
- Cookies

## Provider Initialization

### PHP

```php
<?php
require_once 'vendor/autoload.php';

$provider = new \Fyennyi\OAuth2\Client\Provider\Vercel([
    'clientId'     => $_ENV['VERCEL_APP_CLIENT_ID'],
    'clientSecret' => $_ENV['VERCEL_APP_CLIENT_SECRET'],
    'redirectUri'  => 'https://yourapp.com/callback',
]);
```

### Next.js

```typescript
// No provider initialization needed
// Configuration is done per-request in API routes
const clientId = process.env.NEXT_PUBLIC_VERCEL_APP_CLIENT_ID;
const clientSecret = process.env.VERCEL_APP_CLIENT_SECRET;
const redirectUri = `${req.nextUrl.origin}/api/auth/callback`;
```

**Comparison:**
- **PHP**: Single provider instance can be reused
- **Next.js**: Configuration is inline with each request
- **PHP**: Better for frameworks that support dependency injection
- **Next.js**: More explicit, easier to customize per-request

## Authorization Flow

### PHP

```php
<?php
session_start();

// Generate authorization URL
$authUrl = $provider->getAuthorizationUrl([
    'scope' => ['openid', 'email', 'profile', 'offline_access']
]);

// Store state for CSRF protection
$_SESSION['oauth2state'] = $provider->getState();

// Redirect user
header('Location: ' . $authUrl);
exit;
```

### Next.js

```typescript
// app/api/auth/authorize/route.ts
import crypto from 'node:crypto';
import { NextResponse } from 'next/server';
import { cookies } from 'next/headers';

export async function GET(req: NextRequest) {
  const state = generateSecureRandomString(43);
  const nonce = generateSecureRandomString(43);
  const code_verifier = crypto.randomBytes(43).toString('hex');
  const code_challenge = crypto
    .createHash('sha256')
    .update(code_verifier)
    .digest('base64url');

  const cookieStore = await cookies();
  
  // Store PKCE and state values
  cookieStore.set('oauth_state', state, {
    maxAge: 10 * 60,
    secure: true,
    httpOnly: true,
    sameSite: 'lax',
  });

  const queryParams = new URLSearchParams({
    client_id: process.env.NEXT_PUBLIC_VERCEL_APP_CLIENT_ID,
    redirect_uri: `${req.nextUrl.origin}/api/auth/callback`,
    state,
    nonce,
    code_challenge,
    code_challenge_method: 'S256',
    response_type: 'code',
    scope: 'openid email profile offline_access',
  });

  return NextResponse.redirect(
    `https://vercel.com/oauth/authorize?${queryParams.toString()}`
  );
}
```

**Comparison:**
- **PHP**: PKCE is automatically handled by the library
- **Next.js**: Manual PKCE implementation required
- **PHP**: Less boilerplate code (3 lines vs 30+)
- **Next.js**: More control over every parameter
- **Both**: Use cookies/sessions for state management

## Token Exchange

### PHP

```php
<?php
session_start();

// Verify state
if ($_GET['state'] !== $_SESSION['oauth2state']) {
    exit('Invalid state');
}

try {
    // Exchange code for token
    $accessToken = $provider->getAccessToken('authorization_code', [
        'code' => $_GET['code']
    ]);

    // Token is automatically validated
    echo $accessToken->getToken();
    echo $accessToken->getRefreshToken();
    echo $accessToken->getExpires();

} catch (\Exception $e) {
    exit('Error: ' . $e->getMessage());
}
```

### Next.js

```typescript
// app/api/auth/callback/route.ts
export async function GET(request: NextRequest) {
  const url = new URL(request.url);
  const code = url.searchParams.get('code');
  const state = url.searchParams.get('state');

  // Verify state
  const storedState = request.cookies.get('oauth_state')?.value;
  if (state !== storedState) {
    throw new Error('State mismatch');
  }

  // Get code_verifier
  const codeVerifier = request.cookies.get('oauth_code_verifier')?.value;

  // Exchange code for token
  const params = new URLSearchParams({
    grant_type: 'authorization_code',
    client_id: process.env.NEXT_PUBLIC_VERCEL_APP_CLIENT_ID,
    client_secret: process.env.VERCEL_APP_CLIENT_SECRET,
    code: code,
    code_verifier: codeVerifier,
    redirect_uri: `${request.nextUrl.origin}/api/auth/callback`,
  });

  const response = await fetch('https://api.vercel.com/login/oauth/token', {
    method: 'POST',
    body: params,
  });

  const tokenData = await response.json();

  // Validate nonce in ID token
  const decodedNonce = decodeNonce(tokenData.id_token);
  const storedNonce = request.cookies.get('oauth_nonce')?.value;
  if (decodedNonce !== storedNonce) {
    throw new Error('Nonce mismatch');
  }

  // Store tokens in cookies
  await setAuthCookies(tokenData);

  return Response.redirect(new URL('/profile', request.url));
}
```

**Comparison:**
- **PHP**: Token exchange is one method call
- **Next.js**: Manual HTTP request with URLSearchParams
- **PHP**: ID token validation is automatic (JWKS verification)
- **Next.js**: Manual nonce validation (but not signature verification)
- **PHP**: Exception handling built-in
- **Next.js**: Manual error handling needed

## Getting User Information

### PHP

```php
<?php
try {
    // Get user info
    $user = $provider->getResourceOwner($accessToken);

    echo 'ID: ' . $user->getId();
    echo 'Email: ' . $user->getEmail();
    echo 'Name: ' . $user->getName();
    echo 'Username: ' . $user->getPreferredUsername();
    echo 'Picture: ' . $user->getPicture();

    // Get all data as array
    $allData = $user->toArray();

} catch (\Exception $e) {
    exit('Error: ' . $e->getMessage());
}
```

### Next.js

```typescript
// app/profile/page.tsx
export default async function Profile() {
  const cookieStore = await cookies();
  const token = cookieStore.get('access_token')?.value;

  const result = await fetch('https://api.vercel.com/login/oauth/userinfo', {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });

  const user = await result.json();

  return (
    <div>
      <p>ID: {user.sub}</p>
      <p>Email: {user.email}</p>
      <p>Name: {user.name}</p>
      <p>Username: {user.preferred_username}</p>
      <p>Picture: {user.picture}</p>
    </div>
  );
}
```

**Comparison:**
- **PHP**: Typed resource owner object with helper methods
- **Next.js**: Raw JSON response
- **PHP**: Consistent property names via getters
- **Next.js**: Direct access to OpenID Connect claims
- **Both**: Single API call required

## Token Refresh

### PHP

```php
<?php
if ($accessToken->hasExpired()) {
    $newAccessToken = $provider->getAccessToken('refresh_token', [
        'refresh_token' => $accessToken->getRefreshToken()
    ]);
    
    // Update stored token
    $_SESSION['access_token'] = $newAccessToken;
}
```

### Next.js

```typescript
async function refreshAccessToken(refreshToken: string) {
  const params = new URLSearchParams({
    grant_type: 'refresh_token',
    client_id: process.env.NEXT_PUBLIC_VERCEL_APP_CLIENT_ID,
    client_secret: process.env.VERCEL_APP_CLIENT_SECRET,
    refresh_token: refreshToken,
  });

  const response = await fetch('https://api.vercel.com/login/oauth/token', {
    method: 'POST',
    body: params,
  });

  const tokenData = await response.json();
  
  // Update cookies
  await setAuthCookies(tokenData);
  
  return tokenData;
}
```

**Comparison:**
- **PHP**: Built-in `hasExpired()` check
- **Next.js**: Manual expiration checking
- **PHP**: Same method signature for all grant types
- **Next.js**: Manual parameter construction
- **Both**: Require storing refresh token securely

## Token Revocation

### PHP

```php
<?php
// Revoke access token
$provider->revokeToken($accessToken->getToken());

// Revoke refresh token
$provider->revokeToken($accessToken->getRefreshToken());
```

### Next.js

```typescript
// app/api/auth/signout/route.ts
export async function POST() {
  const cookieStore = await cookies();
  const accessToken = cookieStore.get('access_token')?.value;

  const credentials = `${process.env.NEXT_PUBLIC_VERCEL_APP_CLIENT_ID}:${process.env.VERCEL_APP_CLIENT_SECRET}`;

  await fetch('https://api.vercel.com/login/oauth/token/revoke', {
    method: 'POST',
    headers: {
      Authorization: `Basic ${Buffer.from(credentials).toString('base64')}`,
    },
    body: new URLSearchParams({ token: accessToken }),
  });

  // Clear cookies
  cookieStore.set('access_token', '', { maxAge: 0 });
  cookieStore.set('refresh_token', '', { maxAge: 0 });

  return Response.json({}, { status: 200 });
}
```

**Comparison:**
- **PHP**: Single method call
- **Next.js**: Manual HTTP request with Basic Auth
- **PHP**: Automatic credential encoding
- **Next.js**: Manual Base64 encoding
- **Both**: Need to clear stored tokens after revocation

## Key Differences

### 1. Abstraction Level

| Feature | PHP | Next.js |
|---------|-----|---------|
| HTTP Requests | Abstracted (Guzzle) | Manual (fetch API) |
| PKCE | Automatic | Manual implementation |
| Token Validation | Automatic (JWKS) | Manual (nonce only) |
| State Management | Built-in | Manual cookie management |
| Error Handling | Typed exceptions | Generic errors |

### 2. Code Volume

**PHP Implementation:**
- Authorization: ~10 lines
- Callback: ~15 lines
- User info: ~5 lines
- **Total: ~30 lines**

**Next.js Implementation:**
- Authorization: ~50 lines
- Callback: ~70 lines
- User info: ~20 lines
- **Total: ~140 lines**

### 3. Type Safety

**PHP:**
```php
// Runtime type checking via PHP 7.4+ type hints
function processUser(VercelUser $user): void {
    // $user has defined methods
    $user->getEmail();  // IDE autocomplete works
}
```

**Next.js (TypeScript):**
```typescript
// Compile-time type checking
interface VercelUser {
  sub: string;
  email?: string;
  name?: string;
}

function processUser(user: VercelUser): void {
  user.email;  // IDE autocomplete works
}
```

### 4. Security Features

| Feature | PHP Library | Next.js Manual |
|---------|-------------|----------------|
| PKCE (S256) | ✅ Automatic | ✅ Manual |
| State CSRF | ✅ Automatic | ✅ Manual |
| Nonce validation | ✅ Automatic | ✅ Manual |
| JWKS signature verification | ✅ Automatic | ❌ Not shown |
| Token expiration | ✅ Built-in check | ⚠️ Manual |

## Migration Example

### From Next.js to PHP

**Before (Next.js):**
```typescript
// ~140 lines across multiple files
```

**After (PHP):**
```php
<?php
// index.php
session_start();
$provider = new \Fyennyi\OAuth2\Client\Provider\Vercel([/*...*/]);

if (!isset($_GET['code'])) {
    $authUrl = $provider->getAuthorizationUrl();
    $_SESSION['oauth2state'] = $provider->getState();
    header('Location: ' . $authUrl);
    exit;
}

if ($_GET['state'] !== $_SESSION['oauth2state']) {
    exit('Invalid state');
}

$token = $provider->getAccessToken('authorization_code', [
    'code' => $_GET['code']
]);
$user = $provider->getResourceOwner($token);

echo "Welcome, " . $user->getName();
```

### From PHP to Next.js

Follow the official [Next.js integration guide](NEXTJS_INTEGRATION.md).

## Conclusion

**Use the PHP library when:**
- You want rapid development
- Security is critical (automatic JWKS validation)
- You prefer less boilerplate
- Working with traditional PHP frameworks

**Use Next.js manual approach when:**
- You need maximum control
- You want zero dependencies
- Working in serverless/edge environments
- You prefer explicit over implicit

Both approaches are valid and secure when implemented correctly. The choice depends on your project requirements, team expertise, and architectural preferences.
