<?php

namespace Fyennyi\OAuth2\Client\Provider\Tests;

use Fyennyi\OAuth2\Client\Provider\Vercel;
use Fyennyi\OAuth2\Client\Provider\VercelUser;
use PHPUnit\Framework\TestCase;

class VercelTest extends TestCase
{
    protected Vercel $provider;

    protected function setUp(): void
    {
        $this->provider = new Vercel([
            'clientId' => 'mock_client_id',
            'clientSecret' => 'mock_secret',
            'redirectUri' => 'http://localhost/callback',
            'baseAuthorizationUrl' => 'https://vercel.com/oauth/authorize',
            'baseAccessTokenUrl' => 'https://api.vercel.com/login/oauth/token',
            'resourceOwnerDetailsUrl' => 'https://api.vercel.com/login/oauth/userinfo',
            'introspectUrl' => 'https://api.vercel.com/login/oauth/token/introspect',
            'revokeUrl' => 'https://api.vercel.com/login/oauth/token/revoke',
            'jwksUrl' => 'https://vercel.com/.well-known/jwks',
        ]);
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

    public function testGetBaseAccessTokenUrl(): void
    {
        $url = $this->provider->getBaseAccessTokenUrl([]);
        $this->assertEquals('https://api.vercel.com/login/oauth/token', $url);
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

    public function testUserData(): void
    {
        $userData = [
            'sub' => '123456',
            'email' => 'test@example.com',
            'email_verified' => true,
            'name' => 'Test User',
            'preferred_username' => 'testuser',
            'picture' => 'https://example.com/avatar.jpg',
        ];

        $user = new VercelUser($userData);

        $this->assertEquals('123456', $user->getId());
        $this->assertEquals('test@example.com', $user->getEmail());
        $this->assertTrue($user->isEmailVerified());
        $this->assertEquals('Test User', $user->getName());
        $this->assertEquals('testuser', $user->getPreferredUsername());
        $this->assertEquals('https://example.com/avatar.jpg', $user->getPicture());
        $this->assertEquals($userData, $user->toArray());
    }
}
