# Review (October 2026)

A review of MatIdentity against what a small self-hosted identity provider is expected to do (Authentik, Authelia, Keycloak): every page in light, dark
and at 390 px, a security review of the OpenID Connect endpoints, and the gaps that were closed. Branch `feature/review`.

## Findings and fixes

### Security

| # | Finding | Fix |
|---|---|---|
| 1 | **Open redirect after a passkey sign-in:** `/api/passkeys/signin` accepted `returnUrl` values like `/\evil.example` (only `//` was refused); browsers read them as another host. | `LocalUrl` follows the rule of `Url.IsLocalUrl` (tests). |
| 2 | **Sign-out by link:** a plain `GET /connect/logout` from any site ended the session (logout CSRF). | Without an `id_token_hint` of the signed-in person the person confirms on `/Account/Logout` first and goes on to the app afterwards; with it, out at once (test). `/Account/Logout` GET asks too. |
| 3 | **"Calls every app" included MatIdentity's own API** (`app:matidentity`): any app with that rule could create apps, renew their secrets and change the settings through `/api/v1/clients` and `/api/configure`. | `app:matidentity` is given by name only (page, `callTargets` in the client API); the scopes of existing apps are synced at start (test). Mattiverse uses `X-Api-Key` and is not affected. |
| 4 | **Brute force per account:** only per address (20/min); with a known password the five-code limit of the second step could be restarted forever. | Ten wrong passwords or codes in a row lock the password sign-in for 15 minutes, with the same answer as a wrong password; the count resets only after a complete sign-in (test). |
| 5 | **Password reset poisoning** (new feature, avoided by design): a reset link built from the `Host` header would point to the attacker's host. | "Forgot your password?" is offered only with a public address (Settings or `MatIdentity__Issuer`); its links use only that. |
| 6 | Refresh token reuse: OpenIddict rolls refresh tokens and revokes the chain when a used one comes back, but nothing held it. | A test holds it; the leeway (30 s, for apps renewing twice in parallel) is a setting (`MatIdentity__RefreshTokenReuseLeewaySeconds`). |
| 7 | `email_verified` was always `false` – an app could not tell a proven address from a typed one (the account-linking rule of MatPlatform relies on the address). | Verification by mail; the claim is the account's (see below). |
| 8 | A new theme or a password change rewrote the cookie as a session cookie: "Stay signed in" was lost. | `SignInFlow.RenewCookieAsync` keeps it. |
| 9 | Public apps could not revoke their own tokens. | Revocation allowed for every app; introspection stays for apps with a secret. |

Checked and fine: exact redirect URI matching and PKCE (S256) for every app (OpenIddict, tests); client secrets hashed by OpenIddict and shown once;
`returnUrl` of the sign-in, second step and account pages through `Url.IsLocalUrl`; anti-forgery on every form and on the passkey and theme endpoints;
constant-time API key; forwarded headers only from known proxies; rate limits on sign-in, token and anonymous API; TOTP (±1 step, no reuse, encrypted
secret, hashed recovery codes); passkeys (user verification required, ceremony state on the server, used once, user handle checked); the person and the
app's rules are read again at every token request; no secret in logs, cookies or the activity list.

Remaining notes (accepted): the passkey relying party is the host of the request (changing the public address loses passkeys, documented); `http`
redirect URIs are allowed (home networks); access tokens are not revoked before they expire (30 minutes by default).

### Pages and texts

- Second step for a person with passkeys only: the page offered a recovery code field although such a person has none (dead end). Now: the passkey, and a
  hint that an administrator can reset the second step. "Cancel" keeps the app's request.
- Sign-in: "Username or e-mail" (both work, case does not matter), "Forgot your password?" and "Create an account" when they are on.
- The two account pages had a subtitle that did not name the second step; the Settings subtitle names the mail; placeholders use one example address.
- A "Second step reset" was written as "Signed out" in the activity list; the activity now names the administrator as *who* and the person as detail.
- Empty states and 390 px checked for every new page (no horizontal overflow).

## Gaps against the yardstick

| Feature | Before | Now | Size | Note |
|---|---|---|---|---|
| OIDC: discovery, code + PKCE, refresh, client credentials, user info, revocation, introspection | has | has | – | |
| Refresh token rotation and reuse detection | partly (untested) | has | S | test, leeway setting |
| RP-initiated logout | has | has | – | CSRF fixed |
| Back-channel logout (OIDC Back-Channel Logout 1.0) | missing | has | M | `sid` in the ID token, logout tokens to the apps |
| Front-channel logout | missing | dropped | – | the iframes need third-party cookies, which browsers block; back-channel reaches the apps reliably |
| Consent screen | missing | dropped | – | every app is added by an administrator (no dynamic registration): that is the consent |
| Password policy | partly (8 characters) | has | S | length setting, not the name, not a common password |
| Brute-force protection per address | has | has | – | |
| Brute-force protection per account | missing | has | S | lockout 10 / 15 min |
| TOTP, recovery codes, passkeys | has | has | – | passkey-only dead end fixed |
| Self-service password reset by mail | missing | has | M | single-use, 30 min, hashed, no enumeration |
| Invitations by mail | missing | has | S | 7 days |
| E-mail verification, `email_verified` | missing | has | S | |
| Self-registration (off by default) | missing | has | M | needs mail and the public address; account works after confirmation |
| Mail (MatSMTP or own SMTP) | missing | has | M | MatPlatform 1.3.0 |
| Groups and per-app access, roles | has | has | – | |
| Admin audit log | partly (apps only) | has | S | people, groups, settings, exports |
| Session management | partly (own devices) | has | S | administrators see and end a person's sessions |
| Branding | partly (name) | partly | – | logo/colours stay the family's (MatUi) |
| Health endpoint | has | has | – | `/api/health` |
| Configuration export | missing | has | S | JSON without secrets; the backup is the volume |
| Configuration import | missing | missing | L | restore = the volume; an import would need secrets and keys anyway |
| External identity providers (Google, Entra …) | missing | missing | L | outside the purpose today (the family's own sign-in) |
| LDAP / SCIM | missing | missing | L | no app of the family needs it |

## What the apps need for back-channel logout

MatPlatform (MatDesign `src/MatPlatform/MatIdentitySignIn.cs`, 1.3.0) signs people in with the OpenID Connect handler and keeps only the ID token for the
sign-out; it has no back-channel endpoint, so an app keeps its own cookie until it expires. To end it when MatIdentity says so, MatPlatform needs:

1. An endpoint `POST /signout-backchannel` (form field `logout_token`), anonymous, no anti-forgery.
2. Validation of the logout token with the JWKS of the authority (through `MATIDENTITY_INTERNAL_URL` like the other calls): `typ` = `logout+jwt`, `iss` = the
   authority, `aud` = the client id, `iat` recent, an `events` claim with `http://schemas.openid.net/event/backchannel-logout`, `sub` and/or `sid`, no `nonce`;
   a `jti` replay cache of a few minutes. Answer `200`, or `400` for a bad token.
3. Ending the sessions: keep the `sid` claim of the ID token with the local session (`MatIdentityPerson.Principal` has it) and, per local user, a "signed out at"
   time; `IMatIdentityUsers` gets a method like `SignOutAsync(subject, sid)`, and the cookie's `OnValidatePrincipal` rejects a session started before that time
   (or matching the `sid`).
4. Registration: Mattiverse passes `backchannelLogoutUri` (the app's internal address, e.g. `http://mattiverse-matsplit:8080/signout-backchannel`) in
   `PUT /api/v1/clients/{id}` – MatIdentity accepts it already.
