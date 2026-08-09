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
     * @var array<string, mixed> Provider options
     */
    protected array $options = [];

    /**
     * @var string The OIDC issuer URL
     */
    protected string $issuer = 'https://vercel.com';

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
     * @param array<string, mixed> $options Configuration options
     * @param array<string, mixed> $collaborators Optional collaborators
     * 
     * @throws \InvalidArgumentException If required options are missing
     */
    public function __construct(array $options = [], array $collaborators = [])
    {
        parent::__construct($options, $collaborators);
        $this->options = array_merge($this->options, $options);

        // Set default issuer if not provided
        $issuer = $this->options['issuer'] ?? null;
        if (is_string($issuer) && $issuer !== '') {
            $this->issuer = $issuer;
        }
        $this->options['issuer'] = $this->issuer;

        // Discover endpoints from issuer
        $this->discoverEndpoints($this->issuer);

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
            $value = $this->options[$option] ?? null;
            if (is_string($value) && $value !== '') {
                $this->{$option} = $value;
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
            $response = $httpClient->request('GET', $wellKnownUrl);
            $data = json_decode((string) $response->getBody(), true);

            if (json_last_error() !== JSON_ERROR_NONE) {
                throw new \RuntimeException('Failed to parse OIDC discovery document: ' . json_last_error_msg());
            }

            if (!is_array($data)) {
                throw new \RuntimeException('Unexpected OIDC discovery document format.');
            }

            $this->baseAuthorizationUrl = $this->extractStringField($data, 'authorization_endpoint');
            $this->baseAccessTokenUrl = $this->extractStringField($data, 'token_endpoint');
            $this->resourceOwnerDetailsUrl = $this->extractStringField($data, 'userinfo_endpoint');
            $this->introspectUrl = $this->extractStringField($data, 'introspection_endpoint');
            $this->revokeUrl = $this->extractStringField($data, 'revocation_endpoint');
            $this->jwksUrl = $this->extractStringField($data, 'jwks_uri');

        } catch (\Exception $e) {
            throw new \RuntimeException('Failed to discover OIDC endpoints: ' . $e->getMessage(), 0, $e);
        }
    }

    /**
     * Extracts a string field from a decoded JSON array, if present.
     *
     * @param array<mixed, mixed> $data The decoded JSON data
     * @param string $key The field name to extract
     * @return string|null The string value, or null if missing/not a string
     */
    private function extractStringField(array $data, string $key): ?string
    {
        $value = $data[$key] ?? null;

        return is_string($value) && $value !== '' ? $value : null;
    }

    /**
     * Requests an access token and validates the ID token if present.
     *
     * @param mixed $grant The grant type
     * @param array<string, mixed> $options Additional options
     * @return AccessTokenInterface The access token with validated ID token claims
     * 
     * @throws IdentityProviderException If ID token validation fails
     */
    public function getAccessToken($grant, array $options = []): AccessTokenInterface
    {
        $accessToken = parent::getAccessToken($grant, $options);

        // Validate ID token if present
        $idToken = $accessToken->getValues()['id_token'] ?? null;

        if (is_string($idToken) && $idToken !== '') {
            $nonce = $_SESSION['oauth2nonce'] ?? null;
            unset($_SESSION['oauth2nonce']);
            $nonce = is_string($nonce) ? $nonce : null;

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
     * @return array<string, mixed> The decoded and validated claims
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
        $clientId = $this->options['clientId'] ?? null;
        if (!in_array($clientId, $aud, true)) {
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

        /** @var array<string, mixed> */
        return (array) $decoded;
    }

    /**
     * Fetches the JSON Web Key Set (JWKS) from Vercel.
     *
     * @return array<string, mixed> The JWKS data
     * 
     * @throws \RuntimeException If fetching fails
     */
    private function fetchJwks(): array
    {
        $jwksUrl = $this->jwksUrl ?? throw new \RuntimeException("The 'jwksUrl' option was not configured.");

        $response = $this->getHttpClient()->request('GET', $jwksUrl);
        $data = json_decode((string) $response->getBody(), true);

        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new \RuntimeException('Failed to parse JWKS: ' . json_last_error_msg());
        }

        if (!is_array($data)) {
            throw new \RuntimeException('Unexpected JWKS response format.');
        }

        /** @var array<string, mixed> $data */
        return $data;
    }

    /**
     * Gets the configured issuer URL.
     *
     * @return string The issuer URL
     */
    private function getConfiguredIssuer(): string
    {
        return $this->issuer;
    }

    /**
     * {@inheritdoc}
     */
    public function getBaseAuthorizationUrl(): string
    {
        return $this->baseAuthorizationUrl
            ?? throw new \RuntimeException("The 'baseAuthorizationUrl' option was not configured.");
    }

    /**
     * {@inheritdoc}
     *
     * @param array<string, mixed> $params
     */
    public function getBaseAccessTokenUrl(array $params): string
    {
        return $this->baseAccessTokenUrl
            ?? throw new \RuntimeException("The 'baseAccessTokenUrl' option was not configured.");
    }

    /**
     * {@inheritdoc}
     */
    public function getResourceOwnerDetailsUrl(AccessToken $token): string
    {
        return $this->resourceOwnerDetailsUrl
            ?? throw new \RuntimeException("The 'resourceOwnerDetailsUrl' option was not configured.");
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
     * @return array<string, mixed> The introspection result
     * 
     * @throws IdentityProviderException If the request fails
     */
    public function introspectToken(string $token): array
    {
        $introspectUrl = $this->introspectUrl
            ?? throw new \RuntimeException("The 'introspectUrl' option was not configured.");

        $params = [
            'token' => $token,
        ];

        $request = $this->createRequest(self::METHOD_POST, $introspectUrl, null, [
            'body' => $this->buildQueryString($params)
        ]);

        $result = $this->getParsedResponse($request);

        if (!is_array($result)) {
            throw new \RuntimeException('Unexpected token introspection response format.');
        }

        /** @var array<string, mixed> $result */
        return $result;
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
        $revokeUrl = $this->revokeUrl
            ?? throw new \RuntimeException("The 'revokeUrl' option was not configured.");

        $credentials = base64_encode($this->clientId . ':' . $this->clientSecret);

        $request = $this->createRequest(
            self::METHOD_POST,
            $revokeUrl,
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
