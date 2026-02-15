<?php

namespace Fyennyi\OAuth2\Client\Provider;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Token\AccessTokenInterface;
use League\OAuth2\Client\Tool\BearerAuthorizationTrait;
use Psr\Http\Message\ResponseInterface;

/**
 * Vercel OAuth 2.0 Provider for league/oauth2-client.
 * 
 * This provider implements the OAuth 2.0 and OpenID Connect flows for Vercel's
 * "Sign in with Vercel" authentication service.
 * 
 * @see https://vercel.com/docs/sign-in-with-vercel
 */
class Vercel extends AbstractProvider
{
    use BearerAuthorizationTrait;

    /**
     * @var string|null The authorization endpoint URL
     */
    public ?string $baseAuthorizationUrl = null;

    /**
     * @var string|null The token endpoint URL
     */
    public ?string $baseAccessTokenUrl = null;

    /**
     * @var string|null The userinfo endpoint URL
     */
    public ?string $resourceOwnerDetailsUrl = null;

    /**
     * @var string|null The token introspection endpoint URL
     */
    public ?string $introspectUrl = null;

    /**
     * @var string|null The token revocation endpoint URL
     */
    public ?string $revokeUrl = null;

    /**
     * @var string|null The JWKS endpoint URL
     */
    public ?string $jwksUrl = null;

    /**
     * @var array Provider options
     */
    protected array $options = [];

    /**
     * Initializes the Vercel provider.
     *
     * @param array $options Configuration options including:
     *   - clientId: Your Vercel app client ID (required)
     *   - clientSecret: Your Vercel app client secret (required)
     *   - redirectUri: Your authorization callback URL (required)
     *   - issuer: Vercel's issuer URL (optional, defaults to https://vercel.com)
     *   - baseAuthorizationUrl: Override authorization endpoint (optional)
     *   - baseAccessTokenUrl: Override token endpoint (optional)
     *   - resourceOwnerDetailsUrl: Override userinfo endpoint (optional)
     *   - introspectUrl: Override introspection endpoint (optional)
     *   - revokeUrl: Override revocation endpoint (optional)
     *   - jwksUrl: Override JWKS endpoint (optional)
     * @param array $collaborators Optional collaborators
     * 
     * @throws \InvalidArgumentException If required options are missing
     */
    public function __construct(array $options = [], array $collaborators = [])
    {
        parent::__construct($options, $collaborators);
        $this->options = array_merge($this->options, $options);

        // Set default issuer if not provided
        if (empty($this->options['issuer'])) {
            $this->options['issuer'] = 'https://vercel.com';
        }

        // Discover endpoints from issuer
        $this->discoverEndpoints($this->options['issuer']);

        // Allow manual override of endpoints
        $urlOptions = [
            'baseAuthorizationUrl',
            'baseAccessTokenUrl',
            'resourceOwnerDetailsUrl',
            'introspectUrl',
            'revokeUrl',
            'jwksUrl',
        ];

        foreach ($urlOptions as $option) {
            if (!empty($this->options[$option])) {
                $this->{$option} = $this->options[$option];
            }
        }

        // Validate that all required endpoints are set
        foreach ($urlOptions as $option) {
            if (empty($this->{$option})) {
                throw new \InvalidArgumentException(
                    "The '{$option}' option is required or must be discoverable from the 'issuer' URL."
                );
            }
        }
    }

    /**
     * Discovers OIDC endpoints from the issuer's .well-known configuration.
     *
     * @param string $issuer The issuer URL
     * @return void
     * 
     * @throws \RuntimeException If discovery fails
     */
    protected function discoverEndpoints(string $issuer): void
    {
        $wellKnownUrl = rtrim($issuer, '/') . '/.well-known/openid-configuration';

        try {
            $httpClient = $this->getHttpClient();
            $response = $httpClient->get($wellKnownUrl);
            $data = json_decode((string) $response->getBody(), true);

            if (json_last_error() !== JSON_ERROR_NONE) {
                throw new \RuntimeException('Failed to parse OIDC discovery document: ' . json_last_error_msg());
            }

            $this->baseAuthorizationUrl = $data['authorization_endpoint'] ?? null;
            $this->baseAccessTokenUrl = $data['token_endpoint'] ?? null;
            $this->resourceOwnerDetailsUrl = $data['userinfo_endpoint'] ?? null;
            $this->introspectUrl = $data['introspection_endpoint'] ?? null;
            $this->revokeUrl = $data['revocation_endpoint'] ?? null;
            $this->jwksUrl = $data['jwks_uri'] ?? null;

        } catch (\Exception $e) {
            throw new \RuntimeException('Failed to discover OIDC endpoints: ' . $e->getMessage(), 0, $e);
        }
    }

    /**
     * Requests an access token and validates the ID token if present.
     *
     * @param mixed $grant The grant type
     * @param array $options Additional options
     * @return AccessTokenInterface The access token with validated ID token claims
     * 
     * @throws IdentityProviderException If ID token validation fails
     */
    public function getAccessToken($grant, array $options = []): AccessTokenInterface
    {
        $accessToken = parent::getAccessToken($grant, $options);

        // Validate ID token if present
        $idToken = $accessToken->getValues()['id_token'] ?? null;

        if ($idToken) {
            $nonce = $_SESSION['oauth2nonce'] ?? null;
            unset($_SESSION['oauth2nonce']);

            $validatedClaims = $this->getValidatedClaims($idToken, $nonce);
            $values = array_merge($accessToken->getValues(), ['id_token_claims' => $validatedClaims]);
            $accessToken = new AccessToken(array_merge($accessToken->jsonSerialize(), $values));
        }

        return $accessToken;
    }

    /**
     * Validates the ID token's signature and claims.
     *
     * @param string $idToken The ID token JWT
     * @param string|null $expectedNonce The expected nonce value
     * @return array The decoded and validated claims
     * 
     * @throws IdentityProviderException If validation fails
     */
    private function getValidatedClaims(string $idToken, ?string $expectedNonce): array
    {
        $jwks = $this->fetchJwks();
        $keys = JWK::parseKeySet($jwks);

        $decoded = JWT::decode($idToken, $keys);

        // Validate issuer
        if ($decoded->iss !== $this->getConfiguredIssuer()) {
            throw new IdentityProviderException('Invalid issuer claim in ID token', 0, $idToken);
        }

        // Validate audience
        $aud = is_array($decoded->aud) ? $decoded->aud : [$decoded->aud];
        if (!in_array($this->options['clientId'], $aud, true)) {
            throw new IdentityProviderException('Invalid audience claim in ID token', 0, $idToken);
        }

        // Validate nonce if provided
        if ($expectedNonce !== null) {
            if (empty($decoded->nonce)) {
                throw new IdentityProviderException('ID token is missing nonce claim', 0, $idToken);
            }
            if ($decoded->nonce !== $expectedNonce) {
                throw new IdentityProviderException('Invalid nonce in ID token', 0, $idToken);
            }
        }

        return (array) $decoded;
    }

    /**
     * Fetches the JSON Web Key Set (JWKS) from Vercel.
     *
     * @return array The JWKS data
     * 
     * @throws \RuntimeException If fetching fails
     */
    private function fetchJwks(): array
    {
        $response = $this->getHttpClient()->get($this->jwksUrl);
        $data = json_decode((string) $response->getBody(), true);
        
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new \RuntimeException('Failed to parse JWKS: ' . json_last_error_msg());
        }

        return $data;
    }

    /**
     * Gets the configured issuer URL.
     *
     * @return string The issuer URL
     */
    private function getConfiguredIssuer(): string
    {
        return $this->options['issuer'];
    }

    /**
     * {@inheritdoc}
     */
    public function getBaseAuthorizationUrl(): string
    {
        return $this->baseAuthorizationUrl;
    }

    /**
     * {@inheritdoc}
     */
    public function getBaseAccessTokenUrl(array $params): string
    {
        return $this->baseAccessTokenUrl;
    }

    /**
     * {@inheritdoc}
     */
    public function getResourceOwnerDetailsUrl(AccessToken $token): string
    {
        return $this->resourceOwnerDetailsUrl;
    }

    /**
     * {@inheritdoc}
     */
    protected function getPkceMethod(): string
    {
        return 'S256';
    }

    /**
     * Introspects a token to check its validity and metadata.
     *
     * @param string $token The token to introspect
     * @return array The introspection result
     * 
     * @throws IdentityProviderException If the request fails
     */
    public function introspectToken(string $token): array
    {
        $params = [
            'token' => $token,
        ];

        $request = $this->createRequest(self::METHOD_POST, $this->introspectUrl, null, [
            'body' => $this->buildQueryString($params)
        ]);

        return $this->getParsedResponse($request);
    }

    /**
     * Revokes a token (access or refresh token).
     *
     * @param string $token The token to revoke
     * @return void
     * 
     * @throws IdentityProviderException If the request fails
     */
    public function revokeToken(string $token): void
    {
        $credentials = base64_encode($this->clientId . ':' . $this->clientSecret);

        $request = $this->createRequest(
            self::METHOD_POST,
            $this->revokeUrl,
            null,
            [
                'headers' => [
                    'Authorization' => 'Basic ' . $credentials,
                ],
                'body' => $this->buildQueryString(['token' => $token])
            ]
        );

        $this->getParsedResponse($request);
    }

    /**
     * {@inheritdoc}
     */
    protected function getDefaultScopes(): array
    {
        return ['openid', 'email', 'profile'];
    }

    /**
     * {@inheritdoc}
     */
    protected function getScopeSeparator(): string
    {
        return ' ';
    }

    /**
     * {@inheritdoc}
     */
    protected function checkResponse(ResponseInterface $response, $data): void
    {
        if (!empty($data['error'])) {
            $code = $response->getStatusCode();
            $error = $data['error_description'] ?? $data['error'];
            throw new IdentityProviderException($error, $code, $data);
        }
    }

    /**
     * {@inheritdoc}
     */
    protected function createResourceOwner(array $response, AccessToken $token): VercelUser
    {
        return new VercelUser($response);
    }
}
