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
     * @var array Raw response data from the provider
     */
    protected array $response;

    /**
     * Creates a new Vercel user.
     *
     * @param array $response The raw response data
     */
    public function __construct(array $response)
    {
        $this->response = $response;
    }

    /**
     * Gets the user's unique identifier (sub claim).
     *
     * @return string|null The user ID
     */
    public function getId(): ?string
    {
        return $this->response['sub'] ?? null;
    }

    /**
     * Gets the user's email address.
     *
     * @return string|null The email address
     */
    public function getEmail(): ?string
    {
        return $this->response['email'] ?? null;
    }

    /**
     * Gets whether the user's email is verified.
     *
     * @return bool|null True if verified, false if not, null if unknown
     */
    public function isEmailVerified(): ?bool
    {
        return $this->response['email_verified'] ?? null;
    }

    /**
     * Gets the user's full name.
     *
     * @return string|null The full name
     */
    public function getName(): ?string
    {
        return $this->response['name'] ?? null;
    }

    /**
     * Gets the user's preferred username.
     *
     * @return string|null The username
     */
    public function getPreferredUsername(): ?string
    {
        return $this->response['preferred_username'] ?? null;
    }

    /**
     * Gets the URL to the user's profile picture.
     *
     * @return string|null The picture URL
     */
    public function getPicture(): ?string
    {
        return $this->response['picture'] ?? null;
    }

    /**
     * Gets all user data as an array.
     *
     * @return array All response data
     */
    public function toArray(): array
    {
        return $this->response;
    }
}
