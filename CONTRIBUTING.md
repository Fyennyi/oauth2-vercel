# Contributing to OAuth2 Vercel Provider

First off, thank you for considering contributing to the OAuth2 Vercel Provider! It's people like you that make this library better for everyone.

## Code of Conduct

This project and everyone participating in it is governed by respect, inclusivity, and collaboration. Please be kind and courteous to others.

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check the [existing issues](https://github.com/fyennyi/oauth2-vercel/issues) to avoid duplicates. When you create a bug report, include as many details as possible:

- **Use a clear and descriptive title**
- **Describe the exact steps to reproduce the problem**
- **Provide specific examples** to demonstrate the steps
- **Describe the behavior you observed** and what you expected
- **Include your environment details**: PHP version, library version, OS

**Bug Report Template:**

```markdown
## Description
A clear and concise description of the bug.

## Steps to Reproduce
1. Initialize provider with...
2. Call method...
3. See error...

## Expected Behavior
What you expected to happen.

## Actual Behavior
What actually happened.

## Environment
- PHP Version: 8.1.2
- Library Version: 1.0.0
- OS: Ubuntu 22.04
- Vercel App Configuration: [relevant details]

## Additional Context
Any other information about the problem.
```

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion, include:

- **Use a clear and descriptive title**
- **Provide a detailed description** of the suggested enhancement
- **Explain why this enhancement would be useful**
- **List some examples** of how it would be used

### Pull Requests

1. **Fork the repository** and create your branch from `main`
2. **Make your changes** following the coding standards
3. **Add tests** if you've added code that should be tested
4. **Ensure the test suite passes** (`composer test`)
5. **Make sure your code lints** (`composer phpcs`)
6. **Update the documentation** if needed
7. **Write a clear commit message**

## Development Setup

### Prerequisites

- PHP 7.4 or higher
- Composer
- Git

### Setting Up Your Development Environment

1. Fork and clone the repository:
   ```bash
   git clone https://github.com/YOUR_USERNAME/oauth2-vercel.git
   cd oauth2-vercel
   ```

2. Install dependencies:
   ```bash
   composer install
   ```

3. Create a branch for your work:
   ```bash
   git checkout -b feature/your-feature-name
   ```

### Running Tests

```bash
# Run all tests
composer test

# Run tests with coverage
composer test -- --coverage-html coverage

# Run specific test
vendor/bin/phpunit tests/Provider/VercelTest.php
```

### Code Quality Checks

```bash
# Run PHPStan (static analysis)
composer phpstan

# Run PHP_CodeSniffer (coding standards)
composer phpcs

# Run all checks
composer check
```

### Fixing Code Style Issues

```bash
# Automatically fix coding standards issues
vendor/bin/phpcbf src --standard=PSR12
```

## Coding Standards

This project follows:

- **PSR-12** for coding style
- **PSR-4** for autoloading
- **PHPDoc** for documentation

### PHP Style Guide

```php
<?php

namespace Fyennyi\OAuth2\Client\Provider;

/**
 * Class description.
 * 
 * Detailed explanation of what this class does.
 */
class ExampleClass
{
    /**
     * @var string Description of property
     */
    protected string $property;

    /**
     * Method description.
     *
     * @param string $param Parameter description
     * @return bool Return value description
     * 
     * @throws \Exception When something goes wrong
     */
    public function exampleMethod(string $param): bool
    {
        // Implementation
        return true;
    }
}
```

### Commit Message Guidelines

We follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

```
<type>[optional scope]: <description>

[optional body]

[optional footer]
```

**Types:**
- `feat`: A new feature
- `fix`: A bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, missing semicolons, etc.)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

**Examples:**

```
feat(provider): add support for custom scopes

Add ability to pass custom scopes in the authorization URL
beyond the default openid, email, and profile scopes.

Closes #123
```

```
fix(token): handle missing refresh token gracefully

Previously the library would throw an exception when refresh_token
was not present in the response. Now it returns null instead.

Fixes #456
```

## Testing Guidelines

### Writing Tests

- Use descriptive test method names: `testMethodNameWithSpecificScenario()`
- Test both success and failure cases
- Use mocks for external dependencies (HTTP requests)
- Aim for high code coverage

**Example Test:**

```php
<?php

namespace Fyennyi\OAuth2\Client\Provider\Tests;

use Fyennyi\OAuth2\Client\Provider\Vercel;
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
        ]);
    }

    public function testAuthorizationUrlContainsRequiredParameters(): void
    {
        $url = $this->provider->getAuthorizationUrl();
        $query = parse_url($url, PHP_URL_QUERY);
        parse_str($query, $params);

        $this->assertArrayHasKey('client_id', $params);
        $this->assertArrayHasKey('redirect_uri', $params);
        $this->assertArrayHasKey('state', $params);
        $this->assertArrayHasKey('code_challenge', $params);
    }
}
```

## Documentation

### Updating Documentation

- Update `README.md` for user-facing changes
- Update `CHANGELOG.md` following [Keep a Changelog](https://keepachangelog.com/)
- Add PHPDoc comments for all public methods
- Include code examples where appropriate

### Documentation Style

- Use clear, concise language
- Provide practical examples
- Explain the "why" not just the "what"
- Link to relevant Vercel documentation

## Pull Request Process

1. **Update the README.md** with details of changes if applicable
2. **Update the CHANGELOG.md** under the "Unreleased" section
3. **Ensure all tests pass** and code quality checks succeed
4. **Request a review** from maintainers
5. **Address review comments** promptly
6. **Squash commits** if requested before merging

### Pull Request Template

```markdown
## Description
Brief description of what this PR does.

## Type of Change
- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update

## Testing
Describe the tests you ran and how to reproduce them.

## Checklist
- [ ] My code follows the style guidelines of this project
- [ ] I have performed a self-review of my own code
- [ ] I have commented my code, particularly in hard-to-understand areas
- [ ] I have made corresponding changes to the documentation
- [ ] My changes generate no new warnings
- [ ] I have added tests that prove my fix is effective or that my feature works
- [ ] New and existing unit tests pass locally with my changes

## Related Issues
Closes #(issue number)
```

## Release Process

(For maintainers)

1. Update version in `composer.json`
2. Update `CHANGELOG.md` with release date
3. Create a git tag: `git tag -a v1.0.0 -m "Release v1.0.0"`
4. Push tag: `git push origin v1.0.0`
5. Create GitHub release with changelog
6. Packagist will automatically update

## Questions?

Feel free to:
- Open a [GitHub Discussion](https://github.com/fyennyi/oauth2-vercel/discussions)
- Open an [issue](https://github.com/fyennyi/oauth2-vercel/issues)
- Email: chernegasergiy3@gmail.com

## Recognition

Contributors will be recognized in:
- The project's README
- Release notes
- GitHub's contributors page

Thank you for contributing!
