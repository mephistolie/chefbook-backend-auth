# ChefBook Auth

Auth owns accounts, identities, sessions, typed authentication steps, security factors
and account lifecycle requests. The gateway exposes the shared `/v1` contract;
`AuthenticationService` is the typed internal gRPC boundary. The legacy `AuthService`
retains read RPCs needed by other microservices, backed by the new `accounts` schema.
Old sign-up/sign-in RPCs are not an alternate path around the new factor policy.

## Runtime and storage

- `internal/authentication`: PostgreSQL-backed state machine and account operations.
- `internal/transport/authenticationgrpc`: typed new RPCs and internal compatibility reads.
- `pkg/passkey`: go-webauthn verification; private keys never enter the server.
- `internal/authentication/provider`: Google and legacy VK network adapters.
- `internal/outbox`: oldest-first persistent, mandatory AMQP publication with confirms.
- `schema/initial.sql`: initial empty-database schema, embedded by the initializer.
- `services/mail`: separate SMTP delivery service; auth writes typed mail outbox events.

Starting registration accepts only its purpose and creates an authentication process.
A `registration` step collects only email; username is set after account creation.
An `emailVerification` step sends and verifies a code in its originating flow, with
identical pre-proof behavior for existing and free addresses. A proved existing email
terminates registration with `account_exists`, without changing that account.
After email proof, `passwordSetup` establishes the first credential. Registration
accepts only email and password; providers and passkeys can be linked after account
creation. The account UUID is generated at finalization. Account, password,
profile-created outbox event and one-use session grant are committed atomically.
Stale alternative steps are cancelled and final completion cannot be replayed.
`POST /steps/{stepId}/completion` receives typed flat public data;
the typed internal gRPC boundary uses a protobuf oneof.

Password/provider sign-in requires TOTP or a backup code when enabled. A verified,
user-verified passkey is sufficient. Real successful challenges in the same live
session can satisfy recent reauthentication; derived grants do not extend the trust
window. Sensitive actions consume purpose/account/session-bound grants atomically.
Credentials changes invalidate previous authentication evidence. Pending account
deletion restricts account mutations while retaining session management and deletion
cancellation/policy updates.

Refresh tokens, flow tokens, short email codes, grants and backup codes are hashed
with domain-separated HMAC. TOTP secrets and PKCE verifiers use AES-256-GCM with
context binding. Access JWTs retain the existing claims plus a string `sid`, avoiding
BIGINT precision loss. Live session validation is required; a valid signature alone
does not prove that a session remains active. Tokens without `sid` cannot authorize
the new session-bound API.

## Initial database only

Do not run the previous SQL migration chain against a new deployment. Build and run
the initializer with explicit `--initialize` against an **empty** schema. It refuses
existing tables and does not convert, drop, or reset a legacy database. Startup checks
the new schema and does not automatically initialize it. Historical SQL files remain
as reference only; the current initializer does not execute them.

Helm initialization is disabled by default. `initialization.enabled=true` explicitly
creates a pre-install initialization job; this is not an automatic upgrade migration.
Credentials/secrets must exist before that job. No live environment is changed by
local code generation or tests.

## Configuration

In addition to PostgreSQL, signing key and RabbitMQ settings:

| Variable | Meaning |
|---|---|
| `AUTH_HMAC_KEY` | Stable base64 HMAC key, at least 32 decoded bytes |
| `AUTH_ENCRYPTION_KEY` | Stable base64 AES key, exactly 32 decoded bytes |
| `PASSKEY_RP_ID` | Explicit relying-party domain |
| `PASSKEY_ORIGINS` | Comma-separated permitted WebAuthn origins |
| `PASSKEY_OPAQUE_ORIGINS` | Explicit native app origins, where supported |
| `OAUTH_REDIRECTS` | Exact allowlist of redirect URIs |
| `PASSWORD_RESET_URL` | HTTPS frontend URL that accepts a reset token |
| `EMAIL_CHANGE_URL` | HTTPS frontend URL that accepts a change token |
| `DB_SSLMODE` | `require` by default; `disable` only for isolated local tests |

The encryption/HMAC keys must survive restarts; generating new keys each boot would
invalidate credentials and flows. Store them outside source control. Mail SMTP
credentials, sender settings and environment subject prefix belong to the mail
service. Frontend confirmation pages must submit tokens to the API; GET requests do
not mutate account state. Native passkey deployment also needs platform association
files and the matching RP/origin configuration.

Build Docker images **from the backend workspace root** so local auth API and token
modules are included:

```sh
docker build -f services/auth/Dockerfile -t chefbook-auth .
docker build -f services/auth/migrations/Dockerfile -t chefbook-auth-initialize .
```

## Delivery and current operational limits

Outbox publication is at least once. Events are removed only after publisher confirms
and successful mandatory routing. Consumers must tolerate duplicates. SMTP can still
send twice if delivery succeeds but acknowledgement is lost. A missing consumer
binding retains the event; it is not silently discarded. Auth never logs mail bodies
or credentials. Cleanup expires temporary workflow state, not accounts or unsent
events. Account deletion commits its lifecycle event with the actual deletion.

Short database transitions currently share a transaction-scoped PostgreSQL advisory
lock, with a five-second lock timeout. This serializes revocation and grant races
across instances. Password verification currently holds that lock, limiting auth
throughput. OAuth network exchanges occur outside it. Partitioning locks is future
work and requires preserving the same race guarantees.

TOTP activation has a bounded per-instance attempt limiter. Durable per-flow and
per-challenge failed-attempt budgets protect authentication proofs. These are not a
complete distributed abuse/billing protection system: public registration, email
sending and multi-replica deployment still require the separately planned edge and
shared quotas. No `abuse_counters` table has been added.

Google code flow uses PKCE and a signed nonce; native ID-token flow uses the typed
`google_authentication_steps` nonce extension without invented redirect state.
Provider reauthentication additionally requires fresh `auth_time`. The legacy VK
adapter only supports allowlisted HTTPS confidential-client redirects and does not
claim PKCE or native custom-scheme security. It does not provide `auth_time`, so it
cannot independently satisfy fresh sensitive-action reauthentication. Use a password
or passkey for those actions until a verified modern VK ID adapter is introduced.

Firebase is not a fallback authentication dependency. The separately planned one-time
import needs verified legacy ID mapping and an idempotent executor; this service does
not guess a Firebase identity from an email or mark an import successful by itself.

## Validation

From this service:

```sh
go test ./...
go test -race ./internal/authentication ./pkg/passkey
```

`AUTH_TEST_DATABASE_URL` enables actual PostgreSQL integration tests. Supply only an
isolated disposable PostgreSQL instance. Each test creates and removes its own random
schema; no development/production database should be used. Tests without that variable
skip the database checks explicitly. The integration suite covers initial constraints,
registration/email binding, single-use grant and refresh races, TOTP/backup replay,
reauthentication evidence, session revocation and transactional mail outbox rollback.
Passkey tests exercise real signatures/attestations and reject invalid origins, RP IDs,
challenges, user handles, UV/UP and counters. Live Google/VK credentials and real SMTP
recipient delivery are separate deployment checks.
