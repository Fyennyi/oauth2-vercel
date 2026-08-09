<?php

namespace Fyennyi\OAuth2\Client\Provider;

use League\OAuth2\Client\Provider\ResourceOwnerInterface;

/**
 * Represents a Vercel user resource owner.
 * 
 * This class contains user information returned from Vercel's userinfo endpoint
 * and ID token claims.
 */
class VercelUser implements ResourceOwnerInterface
{
    /**
     * @var array<string, mixed> Raw response data from the provider
     */
    protected array $response;

    /**
     * Creates a new Vercel user.
     *
     * @param array<string, mixed> $response The raw response data
     */
    public function __construct(array $response)
    {
        $this->response = $response;
    }

    /**
     * Extracts a string value from the response data, if present.
     *
     * @param string $key The field name to extract
     * @return string|null The string value, or null if missing/not a string
     */
    private function getStringValue(string $key): ?string
    {
        $value = $this->response[$key] ?? null;

        return is_string($value) ? $value : null;
    }

    /**
     * Gets the user's unique identifier (sub claim).
     *
     * @return string|null The user ID
     */
    public function getId(): ?string
    {
        return $this->getStringValue('sub');
    }

    /**
     * Gets the user's email address.
     *
     * @return string|null The email address
     */
    public function getEmail(): ?string
    {
        return $this->getStringValue('email');
    }

    /**
     * Gets whether the user's email is verified.
     *
     * @return bool|null True if verified, false if not, null if unknown
     */
    public function isEmailVerified(): ?bool
    {
        $value = $this->response['email_verified'] ?? null;

        return is_bool($value) ? $value : null;
    }

    /**
     * Gets the user's full name.
     *
     * @return string|null The full name
     */
    public function getName(): ?string
    {
        return $this->getStringValue('name');
    }

    /**
     * Gets the user's preferred username.
     *
     * @return string|null The username
     */
    public function getPreferredUsername(): ?string
    {
        return $this->getStringValue('preferred_username');
    }

    /**
     * Gets the URL to the user's profile picture.
     *
     * @return string|null The picture URL
     */
    public function getPicture(): ?string
    {
        return $this->getStringValue('picture');
    }

    /**
     * Gets all user data as an array.
     *
     * @return array<string, mixed> All response data
     */
    public function toArray(): array
    {
        return $this->response;
    }
}
