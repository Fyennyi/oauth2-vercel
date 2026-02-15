# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial release
- Vercel OAuth 2.0 provider implementation
- OIDC discovery support
- Automatic ID token validation with JWKS
- PKCE (S256) support
- Token introspection endpoint
- Token revocation endpoint
- VercelUser resource owner
- Comprehensive documentation
- Integration guides

### Security
- Automatic state verification for CSRF protection
- PKCE implementation for authorization code flow
- ID token signature verification using JWKS
- Nonce validation for replay attack prevention
- Claim validation (issuer, audience, expiration)

## [1.0.0] - 2026-02-15

### Added
- First stable release
- Full OAuth 2.0 Authorization Code Flow with PKCE
- OpenID Connect support with ID token validation
- Automatic endpoint discovery from issuer
- Manual endpoint configuration option
- Token introspection support
- Token revocation support
- Resource owner (user) information retrieval
- Comprehensive documentation:
  - README with quick start guide
  - CONTRIBUTING guidelines
  - TROUBLESHOOTING guide
  - ARCHITECTURE overview with diagrams
  - Next.js integration guide
  - PHP vs Next.js comparison
- PHPUnit test support
- PHPStan static analysis configuration
- PHP_CodeSniffer for coding standards
- CSSM Unlimited License v2.0

### Security
- State parameter for CSRF protection
- PKCE (Proof Key for Code Exchange) with S256
- ID token signature verification
- Nonce validation
- Issuer and audience claim validation
- Automatic token expiration checking

[Unreleased]: https://github.com/fyennyi/oauth2-vercel/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/fyennyi/oauth2-vercel/releases/tag/v1.0.0
