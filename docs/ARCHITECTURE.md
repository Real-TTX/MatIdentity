# Architecture

The decisions behind MatIdentity, and why.

## What it is

The OpenID Connect server of the Mat family and nothing else: who a person is, and proof of it for the apps. It does not know what a person may do
**inside** an app beyond the role `admin` / `user`; each app keeps its own users (for its foreign keys and its data), its own roles, and links a person by the
claim `sub` (docs/PLATFORM.md of MatDesign, "Sign-in with MatIdentity").

## OpenIddict does the protocol, MatIdentity decides

[OpenIddict](https://documentation.openiddict.com/) 7 validates every request (client, redirect address, PKCE, scopes, codes, tokens) and writes the
answers. The endpoints run in *passthrough* mode: `Infrastructure/OidcEndpoints.cs` is called after the checks and decides who is signed in
(`/connect/authorize`), what goes into a token (`/connect/token`), what the user info says, and ends the session (`/connect/logout`). An error of the
protocol becomes the page `StatusCode` with the error in words, because a request with a wrong redirect address must not be sent anywhere.

- **Flows:** authorization code with PKCE (required for every app), refresh tokens, client credentials. No implicit flow, no password flow.
- **No consent screen:** every app is the family's own (`ConsentTypes.Implicit`). An administrator decides which apps exist; that is the consent.
- **Single sign-on** is the cookie session of MatIdentity: `/connect/authorize` with a valid session answers at once. `prompt=login` shows the form anyway,
  `prompt=none` answers `login_required` instead of showing it.
- **The person is read again** at every token request (code and refresh): a disabled account, a new role or a new name take effect at the next renewal.

## Tokens and keys

- Access tokens are **signed, not encrypted** JWTs, so an app (a resource server) can check them with the public key at `/.well-known/jwks` without asking MatIdentity.
  Codes and refresh tokens are encrypted; only MatIdentity reads them.
- The keys are created on the first start and kept in `/data/token-keys` (`Infrastructure/TokenKeys.cs`): an RSA key (its key id is a hash of the public key) and a
  256-bit key for the encryption. Losing them signs every app out; whoever has them can make tokens for every app.
- The audience of a token is the app it is for. A person's access token is for the app that asked (`aud` = its client id). A machine asks for the scope
  `app:<id>` and gets the audience `<id>`. Every app has such a scope (`ClientService.EnsureAppScopeAsync`); an app that may call others gets the scopes of
  all apps, also of the ones added later. MatIdentity's own API is `app:matidentity`.
- Ending sign-ins: `TokenRevoker` revokes the refresh tokens of a person (disabled, deleted, new password, "sign out on other devices") or of everyone.
  Access tokens are short (30 minutes by default) and are not revoked.

## Data

The conventions of the family: JSON for configuration (`config/system.json`), SQLite for logic, tables in PascalCase and singular, the key `Id` as BIGINT,
audit columns and soft delete through `MatIdentityDbContext`, a `Token` UUID for a security key (`UserSession`). The person's `Subject` (the claim `sub`) is a UUID
of its own, never the `Id` and never the user name.

**The exception:** the four tables of OpenIddict (`OidcApplication`, `OidcAuthorization`, `OidcScope`, `OidcToken`) have the BIGINT key and PascalCase names,
but OpenIddict's columns and no soft delete: OpenIddict prunes its tokens itself, and a removed app must really be gone.

## The platform contract

MatIdentity is the first app with the contract of docs/PLATFORM.md (MatDesign). `Platform/MatApiDefinition.cs` holds the types of the contract and knows nothing of
MatIdentity; `Platform/PlatformEndpoints.cs` maps them to the endpoints; `Platform/IdentityPlatform.cs` is MatIdentity's part (its tiles, settings and buttons).
The first two are meant to become the shared package `MatPlatform` once a second app uses them. The settings of `/api/configure` are checked by the same
`SystemConfigService` as the Settings page.

## Security

- Passwords: PBKDF2-SHA256, 210,000 iterations, a dummy check for unknown names (no timing difference).
- Rate limits per address: the sign-in form (20/min), the token endpoint (120/min), the anonymous API (240/min).
- `X-Forwarded-*` only from known proxies (`MatIdentity__TrustedProxies`, else the private networks), so nobody picks the address that is limited and logged.
- The image runs as the unprivileged user `app` and needs no Docker socket.
- A secret is never stored in plain text (OpenIddict keeps a hash), shown once and never written to the activity list, a log or a cookie.
