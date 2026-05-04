# ChefBook Backend Auth Service

The auth service owns identity, credentials, sessions, OAuth bindings, JWT issuing, account activation, password recovery, profile deletion state, and auth-related outgoing events.

## Responsibilities

- Account sign-up, activation, sign-in, refresh, and sign-out.
- RSA-signed JWT access token issuing.
- Refresh session storage and session termination.
- Google and VK OAuth connection and sign-in.
- Password reset and password change flows.
- Nickname availability and assignment.
- Profile deletion request state.
- Auth information lookup for other services.
- Public key exposure for gateway JWT validation.

## Main RPC Families

- `SignUp`, `ActivateProfile`, `SignIn`, `RefreshSession`, `SignOut`
- `RequestGoogleOAuth`, `SignInGoogle`, `ConnectGoogle`, `DeleteGoogleConnection`
- `RequestVkOAuth`, `SignInVk`, `ConnectVk`, `DeleteVkConnection`
- `GetSessions`, `EndSessions`
- `RequestPasswordReset`, `ResetPassword`, `ChangePassword`
- `GetProfileDeletionStatus`, `DeleteProfile`, `CancelProfileDeletion`
- `GetAccessTokenPublicKey`, `GetAuthInfo`, `GetVisibleNames`, `CheckNicknameAvailability`, `SetNickname`

## Dependencies

- Calls `subscription` for subscription-related auth behavior.
- Publishes auth/profile lifecycle messages through MQ when configured.
- Owns its PostgreSQL schema and migrations.

## Database Ownership

Owns:

- `users` - credentials, activation state, role, nickname, deletion timestamp.
- `activation_codes` - one active activation code per user.
- `sessions` - refresh token sessions.
- `password_resets` - password reset codes.
- `oauth` - Google and VK bindings.
- `firebase` - Firebase identity bindings.
- `delete_profile_requests` - pending profile deletion workflow.
- `outbox` - outgoing MQ events.

```mermaid
erDiagram
    AUTH_USERS {
        uuid user_id PK
        varchar email UK
        varchar nickname UK
        varchar password
        role role
        boolean activated
        timestamptz deletion_timestamp
    }

    ACTIVATION_CODES {
        uuid user_id FK,UK
        varchar activation_code
    }

    SESSIONS {
        serial session_id PK
        uuid user_id FK
        varchar refresh_token UK
        inet ip
        text user_agent
        timestamptz last_access
        timestamptz expires_at
    }

    PASSWORD_RESETS {
        uuid user_id FK
        varchar reset_code UK
        boolean used
        timestamptz expires_at
    }

    OAUTH {
        uuid user_id FK,UK
        text google_id UK
        bigint vk_id UK
    }

    FIREBASE {
        uuid user_id FK,UK
        text firebase_id UK
    }

    DELETE_PROFILE_REQUESTS {
        uuid user_id FK,UK
        boolean with_shared_data
        timestamptz deletion_timestamp
    }

    AUTH_OUTBOX {
        uuid message_id PK
        varchar exchange
        varchar type
        jsonb body
    }

    AUTH_USERS ||--o| ACTIVATION_CODES : owns
    AUTH_USERS ||--o{ SESSIONS : owns
    AUTH_USERS ||--o{ PASSWORD_RESETS : owns
    AUTH_USERS ||--o| OAUTH : owns
    AUTH_USERS ||--o| FIREBASE : owns
    AUTH_USERS ||--o| DELETE_PROFILE_REQUESTS : owns
```

Important constraints:

- `users.email` and `users.nickname` are unique.
- `activation_codes`, `oauth`, `firebase`, and `delete_profile_requests` are one-to-one with `users`.
- `password_resets.reset_code` and `sessions.refresh_token` are globally unique.
