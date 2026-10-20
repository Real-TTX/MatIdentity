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
  all apps, also of the ones added later. MatIdentity's own API is `app:matidentity`: it can change the apps and their secrets, so it is never part of
  "every app" and is given to an app by name only.
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

## Permissions

`Core/Access/PermissionService.cs` decides, for one person and one app, whether they may sign in and with which role; `/connect/authorize` asks it before
a code is made and `/connect/token` asks it again at every code and refresh, so taking an app away ends it at the next renewal of the token.

1. An administrator of MatIdentity may sign in to every app; without a grant of their own they get the first (most powerful) role of the app.
2. A person given the app directly or through a group may sign in. Role: their own grant, else the most powerful of their groups' grants, else the default (the last role).
3. An app opened to everyone lets every active person in with the default role.
4. Everyone else is sent to `/Account/NoAccess`, not back to the app (the app would only show an error of its own).

Per app, `RoleMode` says who decides the roles: `MatIdentity` (the claim `role` is the role of the app) or `App` (no claim `role`; the app gives rights
itself). The roles of an app are the field `roles` of its MatApiDefinition (read on request from `<address>/api`), sent by Mattiverse through the client API,
or written down; without any, `admin` and `user`. Machine tokens follow `AppPolicy.CallsAllApps` and `AppCallGrant`: `ClientService.SyncCallScopesAsync` writes
the allowed `app:<id>` scopes into the permissions of the OpenIddict application.

## The second step

Optional for everyone. Who has an authenticator app (`TotpEnabled`) or a passkey is asked for it after the password (`TwoFactorService.NeedsSecondStepAsync`).
Between the password and the second step there is no session, only a cookie of its own (`SignInFlow.TwoFactorScheme`, five minutes) that says whose password
was right; five wrong codes and the person starts again. `SignInFlow.CompleteAsync` ends every way of signing in the same way (session, cookie, activity).

- **TOTP** (`Core/Security/Totp.cs`, RFC 6238: HMAC-SHA1, 30 s, 6 digits, ±1 step, a step never twice). The secret is encrypted with Data Protection.
  Ten recovery codes (50 bits each), only their SHA-256 hashes are kept, each works once.
- **Passkeys** (`Infrastructure/PasskeyEndpoints.cs`, Fido2NetLib 4): discoverable credentials, user verification required, so a passkey alone is two factors
  and signs in without a user name and without a password; after a password it is the second step. The relying party is the host the browser sees, so a
  passkey belongs to the public address of MatIdentity: changing that address loses the passkeys. The options of a ceremony stay on the server (two minutes,
  used once). The browser side is `wwwroot/js/matidentity.js`.
- An administrator resets the second step of a person (authenticator off, passkeys removed) when a device is lost.

## Mail and the links in it

`Core/Mail/MailService` sends through **MatSMTP** when the environment names it (`MATSMTP_*`, read by MatPlatform's `MatSmtpSettings`, a copy in
`src/MatIdentity.Web/MatPlatform/`, never edited here) and the own SMTP settings are then fixed (page and `/api/configure`); else through the SMTP server of
the settings (its password encrypted with Data Protection); else there is no mail and every feature that needs it is hidden. Mail that anybody can trigger
goes out after the answer (`MailQueue`), so an existing account does not answer slower than an unknown one.

`AccountToken` is the key behind a link: 256 random bits, only its SHA-256 hash stored, used once, a new one replaces the old. Purposes: password reset
(30 minutes, at most three an hour per account), invitation (7 days), e-mail verification (48 hours; it confirms only the address it was sent to, a new
address is unconfirmed again). "Forgot your password?" and self-registration are offered only with a **public address**: their links never use the `Host`
of a request (reset poisoning). A password set by link ends every other sign-in and counts as confirming the address. Self-registration (off by default)
makes a disabled account that works after the confirmation; unconfirmed ones are removed after 7 days.

## Sign-out reaches the apps

OpenID Connect Back-Channel Logout 1.0. The ID token carries `sid`, the public id of the session (`SessionIds.Of`: a hash of the session token, never the
token). A session remembers the apps it signed in to (`UserSession.ClientIds`). Whenever sessions end, `SessionService` tells its `ISessionEndListener`;
the web project's `BackchannelLogout` sends every app with a sign-out address (`BackchannelLogoutUri`) a logout token (JWT `logout+jwt`, signed with the key
of the ID tokens, `iss`, `aud`, `sub`, `sid`, `events`, `jti`, two minutes) after the answer; a person out everywhere (disabled, new password set by an
administrator, signed out by one) is announced to every such app with `sub` alone. Front-channel logout is not offered: its iframes need third-party
cookies. A `GET /connect/logout` without the person's `id_token_hint` asks first (a link from another site must not sign anyone out).

## Brute force

Per address: the rate limits. Per account: ten wrong passwords or second-step codes in a row lock the password sign-in for 15 minutes; the answer stays
"Incorrect username or password", so a right password does not show through. The count resets only after a complete sign-in. A passkey alone still signs in.
