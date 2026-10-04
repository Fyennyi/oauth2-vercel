<?php

namespace Fyennyi\OAuth2\Client\Provider\Tests;

use Fyennyi\OAuth2\Client\Provider\VercelUser;
use PHPUnit\Framework\TestCase;

class VercelUserTest extends TestCase
{
    public function testCompleteData() : void
    {
        $userData = [
            'sub' => 'sub123',
            'email' => 'test@example.com',
            'email_verified' => true,
            'name' => 'John Doe',
            'preferred_username' => 'johndoe',
            'picture' => 'https://example.com/pic.jpg',
        ];

        $user = new VercelUser($userData);

        $this->assertEquals('sub123', $user->getId());
        $this->assertEquals('test@example.com', $user->getEmail());
        $this->assertTrue($user->isEmailVerified());
        $this->assertEquals('John Doe', $user->getName());
        $this->assertEquals('johndoe', $user->getPreferredUsername());
        $this->assertEquals('https://example.com/pic.jpg', $user->getPicture());
        $this->assertEquals($userData, $user->toArray());
    }

    public function testMissingData() : void
    {
        $user = new VercelUser([]);

        $this->assertNull($user->getId());
        $this->assertNull($user->getEmail());
        $this->assertNull($user->isEmailVerified());
        $this->assertNull($user->getName());
        $this->assertNull($user->getPreferredUsername());
        $this->assertNull($user->getPicture());
        $this->assertEquals([], $user->toArray());
    }

    public function testWrongDataTypes() : void
    {
        $userData = [
            'sub' => 123, // should be string
            'email' => ['test@example.com'], // should be string
            'email_verified' => 'true', // should be boolean
            'name' => null,
            'preferred_username' => 123.45,
            'picture' => (object) ['url' => 'https://example.com'],
        ];

        $user = new VercelUser($userData);

        $this->assertNull($user->getId());
        $this->assertNull($user->getEmail());
        $this->assertNull($user->isEmailVerified());
        $this->assertNull($user->getName());
        $this->assertNull($user->getPreferredUsername());
        $this->assertNull($user->getPicture());
    }
}
