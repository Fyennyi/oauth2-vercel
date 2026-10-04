<?php

namespace Fyennyi\OAuth2\Client\Provider\Tests;

use Firebase\JWT\JWT;
use Fyennyi\OAuth2\Client\Provider\Vercel;
use Fyennyi\OAuth2\Client\Provider\VercelUser;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Psr7\Response;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessToken;
use PHPUnit\Framework\TestCase;

class VercelTest extends TestCase
{
    protected Vercel $provider;
    protected array $options;

    protected function setUp(): void
    {
        $this->options = [
            'clientId' => 'mock_client_id',
            'clientSecret' => 'mock_secret',
            'redirectUri' => 'http://localhost/callback',
            'baseAuthorizationUrl' => 'https://vercel.com/oauth/authorize',
            'baseAccessTokenUrl' => 'https://api.vercel.com/login/oauth/token',
            'resourceOwnerDetailsUrl' => 'https://api.vercel.com/login/oauth/userinfo',
            'introspectUrl' => 'https://api.vercel.com/login/oauth/token/introspect',
            'revokeUrl' => 'https://api.vercel.com/login/oauth/token/revoke',
            'jwksUrl' => 'https://vercel.com/.well-known/jwks',
            'issuer' => 'https://vercel.com',
        ];

        $this->provider = new Vercel($this->options);
    }

    private function mockResponse(string $body, int $statusCode = 200, array $headers = [])
    {
        return new Response($statusCode, $headers, $body);
    }

    private function mockClient($response)
    {
        $mock = new MockHandler([$response]);
        $handlerStack = HandlerStack::create($mock);
        return new Client(['handler' => $handlerStack]);
    }

    public function testAuthorizationUrl(): void
    {
        $url = $this->provider->getAuthorizationUrl();
        $uri = parse_url($url);

        $this->assertEquals('vercel.com', $uri['host']);
        $this->assertEquals('/oauth/authorize', $uri['path']);

        parse_str($uri['query'], $query);

        $this->assertArrayHasKey('client_id', $query);
        $this->assertArrayHasKey('redirect_uri', $query);
        $this->assertArrayHasKey('state', $query);
        $this->assertArrayHasKey('scope', $query);
        $this->assertArrayHasKey('response_type', $query);
        $this->assertArrayHasKey('code_challenge', $query);
        $this->assertArrayHasKey('code_challenge_method', $query);

        $this->assertEquals('code', $query['response_type']);
        $this->assertEquals('S256', $query['code_challenge_method']);
    }

    public function testGetBaseAuthorizationUrl(): void
    {
        $url = $this->provider->getBaseAuthorizationUrl();
        $this->assertEquals('https://vercel.com/oauth/authorize', $url);
    }

    public function testGetBaseAuthorizationUrlThrowsWhenMissing(): void
    {
        $this->expectException(\RuntimeException::class);
        
        $provider = $this->getMockBuilder(Vercel::class)
            ->disableOriginalConstructor()
            ->onlyMethods(['discoverEndpoints'])
            ->getMock();
            
        $provider->getBaseAuthorizationUrl();
    }

    public function testGetBaseAccessTokenUrl(): void
    {
        $url = $this->provider->getBaseAccessTokenUrl([]);
        $this->assertEquals('https://api.vercel.com/login/oauth/token', $url);
    }
    
    public function testGetBaseAccessTokenUrlThrowsWhenMissing(): void
    {
        $this->expectException(\RuntimeException::class);
        
        $provider = $this->getMockBuilder(Vercel::class)
            ->disableOriginalConstructor()
            ->onlyMethods(['discoverEndpoints'])
            ->getMock();
            
        $provider->getBaseAccessTokenUrl([]);
    }

    public function testGetResourceOwnerDetailsUrl(): void
    {
        $token = new AccessToken(['access_token' => 'mock_token']);
        $url = $this->provider->getResourceOwnerDetailsUrl($token);
        $this->assertEquals('https://api.vercel.com/login/oauth/userinfo', $url);
    }

    public function testGetResourceOwnerDetailsUrlThrowsWhenMissing(): void
    {
        $this->expectException(\RuntimeException::class);
        
        $provider = $this->getMockBuilder(Vercel::class)
            ->disableOriginalConstructor()
            ->onlyMethods(['discoverEndpoints'])
            ->getMock();
            
        $token = new AccessToken(['access_token' => 'mock_token']);
        $provider->getResourceOwnerDetailsUrl($token);
    }

    public function testDefaultScopes(): void
    {
        $url = $this->provider->getAuthorizationUrl();
        $query = parse_url($url, PHP_URL_QUERY);
        parse_str($query, $params);

        $this->assertStringContainsString('openid', $params['scope']);
        $this->assertStringContainsString('email', $params['scope']);
        $this->assertStringContainsString('profile', $params['scope']);
    }

    public function testCheckResponseThrowsException(): void
    {
        $this->expectException(IdentityProviderException::class);
        $this->expectExceptionMessage('Invalid request');

        $response = $this->mockResponse(json_encode(['error' => 'Invalid request']), 400);
        
        $reflection = new \ReflectionClass(Vercel::class);
        $method = $reflection->getMethod('checkResponse');
        $method->setAccessible(true);
        $method->invokeArgs($this->provider, [$response, ['error' => 'invalid_request', 'error_description' => 'Invalid request']]);
    }
    
    public function testCheckResponseThrowsExceptionFallbackMessage(): void
    {
        $this->expectException(IdentityProviderException::class);
        $this->expectExceptionMessage('invalid_request');

        $response = $this->mockResponse(json_encode(['error' => 'invalid_request']), 400);
        
        $reflection = new \ReflectionClass(Vercel::class);
        $method = $reflection->getMethod('checkResponse');
        $method->setAccessible(true);
        $method->invokeArgs($this->provider, [$response, ['error' => 'invalid_request']]);
    }

    public function testCheckResponseThrowsExceptionFallbackUnknownMessage(): void
    {
        $this->expectException(IdentityProviderException::class);
        $this->expectExceptionMessage('An unknown error occurred');

        $response = $this->mockResponse(json_encode(['error' => ['nested']]), 400);
        
        $reflection = new \ReflectionClass(Vercel::class);
        $method = $reflection->getMethod('checkResponse');
        $method->setAccessible(true);
        $method->invokeArgs($this->provider, [$response, ['error' => ['nested']]]);
    }

    public function testCreateResourceOwner(): void
    {
        $response = [
            'sub' => '123456',
            'name' => 'Test User',
        ];
        $token = new AccessToken(['access_token' => 'mock_token']);

        $reflection = new \ReflectionClass(Vercel::class);
        $method = $reflection->getMethod('createResourceOwner');
        $method->setAccessible(true);
        
        $user = $method->invokeArgs($this->provider, [$response, $token]);

        $this->assertInstanceOf(VercelUser::class, $user);
        $this->assertEquals('123456', $user->getId());
    }

    public function testIntrospectToken(): void
    {
        $client = $this->mockClient($this->mockResponse(json_encode([
            'active' => true,
            'client_id' => 'mock_client_id'
        ]), 200, ['content-type' => 'application/json']));
        $this->provider->setHttpClient($client);

        $result = $this->provider->introspectToken('mock_token');

        $this->assertIsArray($result);
        $this->assertTrue($result['active']);
    }
    
    public function testIntrospectTokenThrowsOnInvalidFormat(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Unexpected token introspection response format.');

        $client = $this->mockClient($this->mockResponse('"not an array"', 200, ['content-type' => 'application/json']));
        $this->provider->setHttpClient($client);

        $this->provider->introspectToken('mock_token');
    }

    public function testIntrospectTokenThrowsOnMissingUrl(): void
    {
        $this->expectException(\RuntimeException::class);
        
        $provider = $this->getMockBuilder(Vercel::class)
            ->disableOriginalConstructor()
            ->onlyMethods(['discoverEndpoints'])
            ->getMock();

        $provider->introspectToken('mock_token');
    }

    public function testRevokeToken(): void
    {
        $client = $this->mockClient($this->mockResponse('', 200));
        $this->provider->setHttpClient($client);

        $this->provider->revokeToken('mock_token');
        $this->assertTrue(true);
    }
    
    public function testRevokeTokenThrowsOnMissingUrl(): void
    {
        $this->expectException(\RuntimeException::class);
        
        $provider = $this->getMockBuilder(Vercel::class)
            ->disableOriginalConstructor()
            ->onlyMethods(['discoverEndpoints'])
            ->getMock();

        $provider->revokeToken('mock_token');
    }
    
    public function testDiscoverEndpointsSuccess(): void
    {
        $provider = $this->getMockBuilder(Vercel::class)
            ->disableOriginalConstructor()
            ->onlyMethods(['getHttpClient'])
            ->getMock();
            
        $mockDiscovery = [
            'authorization_endpoint' => 'https://vercel.com/auth',
            'token_endpoint' => 'https://api.vercel.com/token',
            'userinfo_endpoint' => 'https://api.vercel.com/userinfo',
            'introspection_endpoint' => 'https://api.vercel.com/introspect',
            'revocation_endpoint' => 'https://api.vercel.com/revoke',
            'jwks_uri' => 'https://vercel.com/jwks'
        ];
        
        $client = $this->mockClient($this->mockResponse(json_encode($mockDiscovery), 200, ['content-type' => 'application/json']));
        $provider->method('getHttpClient')->willReturn($client);
        
        $reflection = new \ReflectionClass(Vercel::class);
        $method = $reflection->getMethod('discoverEndpoints');
        $method->setAccessible(true);
        $method->invokeArgs($provider, ['https://vercel.com']);
        
        $this->assertEquals('https://vercel.com/auth', $provider->baseAuthorizationUrl);
        $this->assertEquals('https://api.vercel.com/token', $provider->baseAccessTokenUrl);
        $this->assertEquals('https://api.vercel.com/userinfo', $provider->resourceOwnerDetailsUrl);
        $this->assertEquals('https://api.vercel.com/introspect', $provider->introspectUrl);
        $this->assertEquals('https://api.vercel.com/revoke', $provider->revokeUrl);
        $this->assertEquals('https://vercel.com/jwks', $provider->jwksUrl);
    }
    
    public function testDiscoverEndpointsThrowsOnJsonError(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Failed to discover OIDC endpoints: Failed to parse OIDC discovery document');
        
        $provider = $this->getMockBuilder(Vercel::class)
            ->disableOriginalConstructor()
            ->onlyMethods(['getHttpClient'])
            ->getMock();
            
        $client = $this->mockClient($this->mockResponse('invalid json', 200, ['content-type' => 'application/json']));
        $provider->method('getHttpClient')->willReturn($client);
        
        $reflection = new \ReflectionClass(Vercel::class);
        $method = $reflection->getMethod('discoverEndpoints');
        $method->setAccessible(true);
        $method->invokeArgs($provider, ['https://vercel.com']);
    }

    public function testDiscoverEndpointsThrowsOnNonArray(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Unexpected OIDC discovery document format');
        
        $provider = $this->getMockBuilder(Vercel::class)
            ->disableOriginalConstructor()
            ->onlyMethods(['getHttpClient'])
            ->getMock();
            
        $client = $this->mockClient($this->mockResponse('"string"', 200, ['content-type' => 'application/json']));
        $provider->method('getHttpClient')->willReturn($client);
        
        $reflection = new \ReflectionClass(Vercel::class);
        $method = $reflection->getMethod('discoverEndpoints');
        $method->setAccessible(true);
        $method->invokeArgs($provider, ['https://vercel.com']);
    }
    
    public function testConstructorThrowsWhenEndpointsNotDiscovered(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage("The 'baseAuthorizationUrl' option is required");
        
        $mock = new MockHandler([
            new Response(200, [], '{}')
        ]);
        $handlerStack = HandlerStack::create($mock);
        $client = new Client(['handler' => $handlerStack]);
        
        $providerClass = new class(['clientId' => 'c', 'clientSecret' => 's', 'redirectUri' => 'r'], $client) extends Vercel {
            private $mockClient;
            public function __construct($options, $mockClient) {
                $this->mockClient = $mockClient;
                parent::__construct($options);
            }
            public function getHttpClient() {
                return $this->mockClient;
            }
        };
    }
    
    public function testConstructorAcceptsCustomIssuer(): void
    {
        $providerClass = new class([
            'clientId' => 'c', 'clientSecret' => 's', 'redirectUri' => 'r', 'issuer' => 'https://custom.com',
            'baseAuthorizationUrl' => 'url', 'baseAccessTokenUrl' => 'url',
            'resourceOwnerDetailsUrl' => 'url', 'introspectUrl' => 'url',
            'revokeUrl' => 'url', 'jwksUrl' => 'url'
        ]) extends Vercel {
            protected function discoverEndpoints(string $issuer) : void {
                // Do nothing
            }
            public function getIssuer() {
                return $this->issuer;
            }
        };
        
        $this->assertEquals('https://custom.com', $providerClass->getIssuer());
    }

    public function testGetAccessTokenWithValidIdToken(): void
    {
        $key = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);
        openssl_pkey_export($key, $privateKey);
        $details = openssl_pkey_get_details($key);
        
        $n = strtr(rtrim(base64_encode($details['rsa']['n']), '='), '+/', '-_');
        $e = strtr(rtrim(base64_encode($details['rsa']['e']), '='), '+/', '-_');
        
        $jwks = [
            'keys' => [
                [
                    'kty' => 'RSA',
                    'alg' => 'RS256',
                    'use' => 'sig',
                    'kid' => 'test_kid',
                    'n' => $n,
                    'e' => $e
                ]
            ]
        ];

        $payload = [
            'iss' => 'https://vercel.com',
            'aud' => 'mock_client_id',
            'sub' => '12345',
            'nonce' => 'expected_nonce'
        ];
        
        $idToken = JWT::encode($payload, $privateKey, 'RS256', 'test_kid');
        
        $tokenResponse = [
            'access_token' => 'mock_access_token',
            'token_type' => 'Bearer',
            'expires_in' => 3600,
            'id_token' => $idToken
        ];
        
        $mock = new MockHandler([
            new Response(200, ['content-type' => 'application/json'], json_encode($tokenResponse)),
            new Response(200, ['content-type' => 'application/json'], json_encode($jwks))
        ]);
        $handlerStack = HandlerStack::create($mock);
        $client = new Client(['handler' => $handlerStack]);
        
        $this->provider->setHttpClient($client);
        
        $_SESSION['oauth2nonce'] = 'expected_nonce';
        
        $token = $this->provider->getAccessToken('authorization_code', ['code' => 'mock_code']);
        
        $this->assertInstanceOf(AccessToken::class, $token);
        $values = $token->getValues();
        $this->assertArrayHasKey('id_token_claims', $values);
        $this->assertEquals('12345', $values['id_token_claims']['sub']);
        
        unset($_SESSION['oauth2nonce']);
    }

    public function testGetValidatedClaimsThrowsOnInvalidIssuer(): void
    {
        $this->expectException(IdentityProviderException::class);
        $this->expectExceptionMessage('Invalid issuer claim in ID token');
        
        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        openssl_pkey_export($key, $privateKey);
        $details = openssl_pkey_get_details($key);
        $n = strtr(rtrim(base64_encode($details['rsa']['n']), '='), '+/', '-_');
        $e = strtr(rtrim(base64_encode($details['rsa']['e']), '='), '+/', '-_');
        $jwks = ['keys' => [['kty' => 'RSA', 'alg' => 'RS256', 'use' => 'sig', 'kid' => '1', 'n' => $n, 'e' => $e]]];

        $payload = ['iss' => 'https://invalid-issuer.com', 'aud' => 'mock_client_id'];
        $idToken = JWT::encode($payload, $privateKey, 'RS256', '1');

        $client = $this->mockClient($this->mockResponse(json_encode($jwks), 200));
        $this->provider->setHttpClient($client);

        $reflection = new \ReflectionClass(Vercel::class);
        $method = $reflection->getMethod('getValidatedClaims');
        $method->setAccessible(true);
        $method->invokeArgs($this->provider, [$idToken, null]);
    }

    public function testGetValidatedClaimsThrowsOnInvalidAudience(): void
    {
        $this->expectException(IdentityProviderException::class);
        $this->expectExceptionMessage('Invalid audience claim in ID token');
        
        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        openssl_pkey_export($key, $privateKey);
        $details = openssl_pkey_get_details($key);
        $n = strtr(rtrim(base64_encode($details['rsa']['n']), '='), '+/', '-_');
        $e = strtr(rtrim(base64_encode($details['rsa']['e']), '='), '+/', '-_');
        $jwks = ['keys' => [['kty' => 'RSA', 'alg' => 'RS256', 'use' => 'sig', 'kid' => '1', 'n' => $n, 'e' => $e]]];

        $payload = ['iss' => 'https://vercel.com', 'aud' => 'invalid_client_id'];
        $idToken = JWT::encode($payload, $privateKey, 'RS256', '1');

        $client = $this->mockClient($this->mockResponse(json_encode($jwks), 200));
        $this->provider->setHttpClient($client);

        $reflection = new \ReflectionClass(Vercel::class);
        $method = $reflection->getMethod('getValidatedClaims');
        $method->setAccessible(true);
        $method->invokeArgs($this->provider, [$idToken, null]);
    }

    public function testGetValidatedClaimsThrowsOnMissingNonce(): void
    {
        $this->expectException(IdentityProviderException::class);
        $this->expectExceptionMessage('ID token is missing nonce claim');
        
        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        openssl_pkey_export($key, $privateKey);
        $details = openssl_pkey_get_details($key);
        $n = strtr(rtrim(base64_encode($details['rsa']['n']), '='), '+/', '-_');
        $e = strtr(rtrim(base64_encode($details['rsa']['e']), '='), '+/', '-_');
        $jwks = ['keys' => [['kty' => 'RSA', 'alg' => 'RS256', 'use' => 'sig', 'kid' => '1', 'n' => $n, 'e' => $e]]];

        $payload = ['iss' => 'https://vercel.com', 'aud' => 'mock_client_id'];
        $idToken = JWT::encode($payload, $privateKey, 'RS256', '1');

        $client = $this->mockClient($this->mockResponse(json_encode($jwks), 200));
        $this->provider->setHttpClient($client);

        $reflection = new \ReflectionClass(Vercel::class);
        $method = $reflection->getMethod('getValidatedClaims');
        $method->setAccessible(true);
        $method->invokeArgs($this->provider, [$idToken, 'expected_nonce']);
    }

    public function testGetValidatedClaimsThrowsOnInvalidNonce(): void
    {
        $this->expectException(IdentityProviderException::class);
        $this->expectExceptionMessage('Invalid nonce in ID token');
        
        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        openssl_pkey_export($key, $privateKey);
        $details = openssl_pkey_get_details($key);
        $n = strtr(rtrim(base64_encode($details['rsa']['n']), '='), '+/', '-_');
        $e = strtr(rtrim(base64_encode($details['rsa']['e']), '='), '+/', '-_');
        $jwks = ['keys' => [['kty' => 'RSA', 'alg' => 'RS256', 'use' => 'sig', 'kid' => '1', 'n' => $n, 'e' => $e]]];

        $payload = ['iss' => 'https://vercel.com', 'aud' => 'mock_client_id', 'nonce' => 'invalid_nonce'];
        $idToken = JWT::encode($payload, $privateKey, 'RS256', '1');

        $client = $this->mockClient($this->mockResponse(json_encode($jwks), 200));
        $this->provider->setHttpClient($client);

        $reflection = new \ReflectionClass(Vercel::class);
        $method = $reflection->getMethod('getValidatedClaims');
        $method->setAccessible(true);
        $method->invokeArgs($this->provider, [$idToken, 'expected_nonce']);
    }

    public function testFetchJwksThrowsOnMissingUrl(): void
    {
        $this->expectException(\RuntimeException::class);
        
        $provider = $this->getMockBuilder(Vercel::class)
            ->disableOriginalConstructor()
            ->onlyMethods(['discoverEndpoints'])
            ->getMock();
            
        $reflection = new \ReflectionClass(Vercel::class);
        $method = $reflection->getMethod('fetchJwks');
        $method->setAccessible(true);
        $method->invokeArgs($provider, []);
    }

    public function testFetchJwksThrowsOnJsonError(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Failed to parse JWKS');
        
        $client = $this->mockClient($this->mockResponse('invalid json', 200));
        $this->provider->setHttpClient($client);

        $reflection = new \ReflectionClass(Vercel::class);
        $method = $reflection->getMethod('fetchJwks');
        $method->setAccessible(true);
        $method->invokeArgs($this->provider, []);
    }

    public function testFetchJwksThrowsOnNonArray(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Unexpected JWKS response format.');
        
        $client = $this->mockClient($this->mockResponse('"string"', 200));
        $this->provider->setHttpClient($client);

        $reflection = new \ReflectionClass(Vercel::class);
        $method = $reflection->getMethod('fetchJwks');
        $method->setAccessible(true);
        $method->invokeArgs($this->provider, []);
    }
}
