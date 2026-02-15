# Architecture Overview

This document describes the architecture of the Vercel OAuth2 Provider library.

## Table of Contents

- [High-Level Architecture](#high-level-architecture)
- [Component Diagram](#component-diagram)
- [OAuth 2.0 Flow](#oauth-20-flow)
- [Class Structure](#class-structure)
- [Sequence Diagrams](#sequence-diagrams)
- [Data Flow](#data-flow)
- [Security Architecture](#security-architecture)

## High-Level Architecture

```mermaid
graph TB
    subgraph "Your PHP Application"
        App[Your Application Code]
        Session[Session Management]
    end
    
    subgraph "fyennyi/oauth2-vercel"
        Provider[Vercel Provider]
        User[VercelUser]
        League[league/oauth2-client]
    end
    
    subgraph "External Services"
        Vercel[Vercel OAuth Server]
        JWKS[JWKS Endpoint]
        UserInfo[UserInfo Endpoint]
    end
    
    App --> Provider
    Provider --> League
    Provider --> User
    Provider --> Vercel
    Provider --> JWKS
    Provider --> UserInfo
    App --> Session
```

## Component Diagram

```mermaid
graph LR
    subgraph "Library Components"
        V[Vercel Provider]
        VU[VercelUser]
        AP[AbstractProvider]
        RO[ResourceOwnerInterface]
    end
    
    subgraph "Dependencies"
        Guzzle[Guzzle HTTP Client]
        JWT[Firebase PHP-JWT]
        League[league/oauth2-client]
    end
    
    V -->|extends| AP
    V -->|creates| VU
    VU -->|implements| RO
    V -->|uses| Guzzle
    V -->|uses| JWT
    AP -->|from| League
    RO -->|from| League
```

## OAuth 2.0 Flow

### Authorization Code Flow with PKCE

```mermaid
sequenceDiagram
    participant User
    participant App as Your PHP App
    participant Provider as Vercel Provider
    participant Vercel as Vercel OAuth
    participant JWKS as Vercel JWKS

    User->>App: Click "Sign in with Vercel"
    App->>Provider: getAuthorizationUrl()
    Provider->>Provider: Generate state, PKCE
    Provider-->>App: Authorization URL
    App->>App: Store state in session
    App->>User: Redirect to Authorization URL
    
    User->>Vercel: Authorize application
    Vercel->>User: Redirect to callback with code
    
    User->>App: GET /callback?code=xxx&state=yyy
    App->>App: Verify state matches session
    App->>Provider: getAccessToken(code)
    Provider->>Vercel: POST /token (with code_verifier)
    Vercel-->>Provider: access_token, refresh_token, id_token
    
    Provider->>JWKS: Fetch public keys
    JWKS-->>Provider: JWKS
    Provider->>Provider: Validate ID token signature
    Provider->>Provider: Verify claims (iss, aud, nonce)
    Provider-->>App: AccessToken object
    
    App->>Provider: getResourceOwner(token)
    Provider->>Vercel: GET /userinfo
    Vercel-->>Provider: User data
    Provider-->>App: VercelUser object
    App->>User: Display profile
```

## Class Structure

```mermaid
classDiagram
    class AbstractProvider {
        <<abstract>>
        +getAuthorizationUrl()
        +getAccessToken()
        +getResourceOwner()
        #getBaseAuthorizationUrl()
        #getBaseAccessTokenUrl()
        #getResourceOwnerDetailsUrl()
        #createResourceOwner()
    }
    
    class Vercel {
        -string baseAuthorizationUrl
        -string baseAccessTokenUrl
        -string resourceOwnerDetailsUrl
        -string introspectUrl
        -string revokeUrl
        -string jwksUrl
        -array options
        +__construct(array options)
        +introspectToken(string token)
        +revokeToken(string token)
        -discoverEndpoints(string issuer)
        -getValidatedClaims(string idToken)
        -fetchJwks()
        #getPkceMethod()
    }
    
    class VercelUser {
        -array response
        +__construct(array response)
        +getId()
        +getEmail()
        +isEmailVerified()
        +getName()
        +getPreferredUsername()
        +getPicture()
        +toArray()
    }
    
    class ResourceOwnerInterface {
        <<interface>>
        +getId()
        +toArray()
    }
    
    class AccessToken {
        -string token
        -string refreshToken
        -int expires
        -array values
        +getToken()
        +getRefreshToken()
        +hasExpired()
    }
    
    AbstractProvider <|-- Vercel
    ResourceOwnerInterface <|.. VercelUser
    Vercel ..> VercelUser : creates
    Vercel ..> AccessToken : returns
```

## Sequence Diagrams

### OIDC Discovery

```mermaid
sequenceDiagram
    participant App
    participant Provider as Vercel Provider
    participant OIDC as .well-known/openid-configuration

    App->>Provider: new Vercel(['issuer' => 'https://vercel.com'])
    Provider->>OIDC: GET /.well-known/openid-configuration
    OIDC-->>Provider: JSON configuration
    Provider->>Provider: Parse endpoints
    Provider->>Provider: Set authorization_endpoint
    Provider->>Provider: Set token_endpoint
    Provider->>Provider: Set userinfo_endpoint
    Provider->>Provider: Set introspection_endpoint
    Provider->>Provider: Set revocation_endpoint
    Provider->>Provider: Set jwks_uri
    Provider-->>App: Configured provider instance
```

### ID Token Validation

```mermaid
sequenceDiagram
    participant Provider as Vercel Provider
    participant JWKS as JWKS Endpoint
    participant JWT as Firebase JWT Library

    Provider->>Provider: Receive id_token from token endpoint
    Provider->>JWKS: GET /jwks
    JWKS-->>Provider: Public keys
    Provider->>JWT: JWK::parseKeySet(jwks)
    JWT-->>Provider: Parsed keys
    Provider->>JWT: JWT::decode(id_token, keys)
    JWT-->>Provider: Decoded claims
    Provider->>Provider: Validate issuer claim
    Provider->>Provider: Validate audience claim
    Provider->>Provider: Validate nonce claim
    Provider->>Provider: Check expiration
    Provider-->>Provider: ✓ Valid ID token
```

### Token Introspection

```mermaid
sequenceDiagram
    participant App
    participant Provider as Vercel Provider
    participant Introspect as Introspection Endpoint

    App->>Provider: introspectToken(token)
    Provider->>Introspect: POST /token/introspect
    Note over Provider,Introspect: token=xxx<br/>client_id=yyy<br/>client_secret=zzz
    Introspect-->>Provider: Introspection response
    Note over Provider,Introspect: {<br/>"active": true,<br/>"exp": 1234567890,<br/>...<br/>}
    Provider-->>App: array result
```

## Data Flow

### Token Storage and Retrieval

```mermaid
graph TD
    A[User clicks Sign in] -->|1. Generate state| B[Store in Session]
    B -->|2. Redirect| C[Vercel Authorization]
    C -->|3. User approves| D[Redirect with code]
    D -->|4. Verify state| E{State matches?}
    E -->|No| F[Error: Invalid state]
    E -->|Yes| G[Exchange code for tokens]
    G -->|5. Receive tokens| H[Store AccessToken object]
    H -->|6. Extract values| I[Access Token String]
    H -->|7. Extract values| J[Refresh Token String]
    H -->|8. Extract values| K[Expiration Timestamp]
    I --> L[Make API Requests]
    J --> M[Refresh when expired]
    K --> N[Check hasExpired]
```

### User Data Retrieval Flow

```mermaid
graph LR
    A[AccessToken] --> B[getResourceOwner]
    B --> C{Token valid?}
    C -->|No| D[Throw Exception]
    C -->|Yes| E[Request UserInfo]
    E --> F[Parse JSON Response]
    F --> G[Create VercelUser]
    G --> H[Return to App]
    H --> I[Display User Data]
```

## Security Architecture

### PKCE Implementation

```mermaid
graph TB
    subgraph "Authorization Phase"
        A[Generate code_verifier] --> B[Hash with SHA256]
        B --> C[Base64URL encode]
        C --> D[code_challenge]
        D --> E[Send in authorization request]
    end
    
    subgraph "Token Exchange Phase"
        F[Receive authorization code] --> G[Retrieve stored code_verifier]
        G --> H[Send code + code_verifier]
        H --> I[Vercel validates]
    end
    
    E -.->|User authorizes| F
```

### Multi-Layer Security

```mermaid
graph TD
    A[Request] --> B{State Valid?}
    B -->|No| X1[Reject: CSRF Attack]
    B -->|Yes| C{Code Valid?}
    C -->|No| X2[Reject: Invalid Code]
    C -->|Yes| D{PKCE Valid?}
    D -->|No| X3[Reject: Code Intercept]
    D -->|Yes| E[Issue Tokens]
    E --> F{ID Token Signature?}
    F -->|Invalid| X4[Reject: Tampered Token]
    F -->|Valid| G{Claims Valid?}
    G -->|No| X5[Reject: Wrong Audience/Issuer]
    G -->|Yes| H{Nonce Valid?}
    H -->|No| X6[Reject: Replay Attack]
    H -->|Yes| I[✓ Authenticated]
```

## System Integration

### Integration Points

```mermaid
graph TB
    subgraph "Your Application Layer"
        Routes[Routes/Controllers]
        Logic[Business Logic]
        Storage[Session/Database]
    end
    
    subgraph "Library Layer"
        Provider[Vercel Provider]
        User[VercelUser]
    end
    
    subgraph "Infrastructure Layer"
        HTTP[HTTP Client - Guzzle]
        Crypto[Cryptography - JWT]
        Cache[Cache - Optional]
    end
    
    subgraph "External Services"
        OAuth[Vercel OAuth APIs]
    end
    
    Routes --> Provider
    Logic --> Provider
    Provider --> User
    Provider --> HTTP
    Provider --> Crypto
    HTTP --> OAuth
    Storage -.->|Store tokens| Logic
    Cache -.->|Cache JWKS| Provider
```

## Error Handling Architecture

```mermaid
graph TD
    A[Provider Method Call] --> B{Try}
    B -->|Success| C[Return Result]
    B -->|HTTP Error| D[IdentityProviderException]
    B -->|Invalid Response| E[RuntimeException]
    B -->|Validation Error| F[IdentityProviderException]
    
    D --> G[App Catches]
    E --> G
    F --> G
    
    G --> H{Error Type}
    H -->|400 Bad Request| I[Show User Error]
    H -->|401 Unauthorized| J[Refresh Token/Re-auth]
    H -->|429 Rate Limit| K[Retry with Backoff]
    H -->|5xx Server Error| L[Log and Retry]
```

## Performance Considerations

### Caching Strategy

```mermaid
graph LR
    A[Request JWKS] --> B{JWKS Cached?}
    B -->|Yes| C[Use Cached JWKS]
    B -->|No| D[Fetch from Vercel]
    D --> E[Parse JWKS]
    E --> F[Cache for 24h]
    F --> C
    C --> G[Validate Token]
```

### Token Lifecycle

```mermaid
stateDiagram-v2
    [*] --> Fresh: Token issued
    Fresh --> Active: Within expiry time
    Active --> Expiring: < 5 min to expiry
    Expiring --> Expired: Time exceeded
    Expiring --> Refreshed: Refresh token used
    Refreshed --> Fresh: New token issued
    Expired --> Revoked: Explicit revocation
    Revoked --> [*]
    
    note right of Active
        Use token for API requests
    end note
    
    note right of Expiring
        Proactively refresh
    end note
```

## Extension Points

The library provides several extension points for customization:

```mermaid
graph TB
    A[AbstractProvider] --> B[Override Methods]
    B --> C[getDefaultScopes]
    B --> D[checkResponse]
    B --> E[createResourceOwner]
    B --> F[getAuthorizationParameters]
    
    G[HTTP Client] --> H[Custom Middleware]
    H --> I[Logging]
    H --> J[Retry Logic]
    H --> K[Rate Limiting]
    
    L[Vercel Provider] --> M[Custom Endpoints]
    M --> N[introspectToken]
    M --> O[revokeToken]
```

## Deployment Architecture

```mermaid
graph TB
    subgraph "Development"
        Dev[localhost:3000]
        DevSession[File-based Sessions]
    end
    
    subgraph "Staging"
        Staging[staging.yourapp.com]
        StagingSession[Redis Sessions]
        StagingDB[(Session DB)]
    end
    
    subgraph "Production"
        Prod1[app1.yourapp.com]
        Prod2[app2.yourapp.com]
        LoadBalancer[Load Balancer]
        ProdSession[Distributed Sessions]
        ProdDB[(Session Store)]
    end
    
    Dev --> DevSession
    Staging --> StagingSession
    StagingSession --> StagingDB
    
    LoadBalancer --> Prod1
    LoadBalancer --> Prod2
    Prod1 --> ProdSession
    Prod2 --> ProdSession
    ProdSession --> ProdDB
```

## Summary

The Vercel OAuth2 Provider architecture is designed with:

- **Separation of Concerns**: Clear boundaries between provider logic, HTTP communication, and user data
- **Security First**: Multiple layers of validation (state, PKCE, signature, claims)
- **Extensibility**: Built on league/oauth2-client standard with custom extensions
- **Error Handling**: Comprehensive exception handling at every layer
- **Performance**: Optional caching of JWKS and efficient token validation
- **Standards Compliance**: Follows OAuth 2.0, OIDC, and PSR standards

The architecture ensures secure, maintainable, and scalable integration with Vercel's authentication service.
