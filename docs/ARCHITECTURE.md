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

MatIdentity speaks contract 2 of docs/PLATFORM.md (MatDesign) through the shared package **MatPlatform** (a copy in `src/MatIdentity.Web/MatPlatform/`, never edited
here): `AddMatPlatform` / `MapMatPlatform` in Program.cs serve `/api`, `/api/health`, `/api/state`, `/api/configure`, `/api/actions/{id}`, `/api/bindings`,
`/api/connections` and the form of the Connections area. `Platform/IdentityPlatform.cs` is MatIdentity's part: its description (tiles, settings, buttons; it provides
`identity.oidc` and consumes `mail.smtp`) and its values. The settings of `/api/configure` are checked by the same `SystemConfigService` as the Settings page
(`CheckValues` is off). Access: the same key as `/api/v1` (`MatIdentity__ApiKey`, else `MAT_API_KEY`), or a token MatIdentity issued for its own API (audience
`matidentity`): MatPlatform asks the scheme `MatIdentityBearer`, which is `IdentityBearerHandler` here (its own validation, the same check as `ApiAccess`).

**The capability `identity.oidc`.** A binding is an OpenID Connect client (`Platform/IdentityBindings.cs`, an `IMatBindingHandler`), made the one way every managed app
is made: `ClientService.UpsertAsync` (rules, roles, call targets, then the client; what is not given is kept) and `ClientService.RemoveManagedAsync` (only with the
caller's mark), which `/api/v1/clients` uses too. Client id = the consumer id (`-app` added below two characters); for every public address of the consumer
`<address><callback>` and `<address><signedOut>`; the back-channel logout at `<internalUrl><backchannel>` (none without an internal address or with an empty
`backchannel`); the roles from the consumer's `/api` (`AppRolesReader`, the internal address first; kept when it cannot be read); a secret only when the client is
new or renewed. A request without addresses (a new key from the Connections area) keeps the client's addresses. The values: the public address as the authority
(else the address the broker names), the provider's internal address, the client id and the secret. **Listed** are the clients with a mark (`managedBy`: bindings,
and `/api/v1` with a mark, Mattiverse's own client too); an app added under Apps has none, so it is no binding and a binding endpoint never removes it. *Since* is
when the app's rules were written first (`AppPolicy.CreateDate`), *last used* the last app sign-in or machine token of the activity list (90 days).
**By hand:** the Connections area (`/Connections`, `<mat-connections />`, administrators) makes a client from a name alone, marked `manual`
(`ClientRules.ManagedByHand`): it may be without sign-in addresses until an administrator adds them under Apps. The area is English like the rest of MatIdentity
(the UI culture is set for its page and its form).

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
itself). The roles of an app are the field `roles` of its MatApiDefinition (read on request from `<address>/api`, and with every binding of `identity.oidc`),
sent through the client API, or written down; without any, `admin` and `user`. Machine tokens follow `AppPolicy.CallsAllApps` and `AppCallGrant`: `ClientService.SyncCallScopesAsync` writes
the allowed `app:<id>` scopes into the permissions of the OpenIddict application.

**Permissions and quotas** (MatDesign docs/ACCESS.md, PLATFORM.md "People, permissions and quotas"). An app names them in its MatApiDefinition next to its roles
(`permissions`: rights on top of a role, some of them coming with roles; `quotas`: numbers per person with a unit and maybe a period); MatIdentity reads them with the roles
(`AppRolesReader.ReadCatalogAsync`, kept in `AppPermission` and `AppQuota`). A grant (`AppGrant`) gives on top of its role a list of permissions and a JSON object of quotas
(`GrantValues`; `null` = no limit). What a person ends up with (`AccessDecision`): the permissions **add up** (the role's, their own grant's, every group's); a quota is
their own grant's value, else the **largest** of their groups' (no limit wins), else none, which means the app's own setting. With the role they go into the ID token, the
access token and the user info as `entitlements` (RFC 9068) and `mat_quotas`, each app only its own; with `RoleMode.App` none of the three. An app whose rules send groups (`AppPolicy.SendsGroups`, off by default) also gets
`groups`, the names of all the person's groups (`AccessDecision.Groups`, in the signature), with the scope `roles` and whoever decides the roles; a change of a group's
members or name then also reaches every such app (`GroupService.ClientsOfAsync`). The decision reads everything it
needs at once (`PermissionService.LoadAsync`, then `Decide` in memory), so a whole snapshot of who has what is cheap.

**A change reaches the app at once.** Every change that can change what someone ends up with goes through `PermissionService.WatchAsync`: a grant, the rules, the roles,
permissions or quotas of an app, the members of a group, a person's administrator flag or account. It takes a snapshot of the decisions (the signature of each) before and
after, and for every person and app that differ it revokes the person's refresh tokens for that app (`TokenRevoker.RevokeForSubjectAndClientAsync`) and tells
`IAccessChangeListener`: the web project's `BackchannelLogout` sends that app a logout token with the subject alone. The app ends the person's sessions, and the next request
signs them in again without a password, with the new claims. (OpenIddict keeps the type of a token as its URN, `urn:ietf:params:oauth:token-type:refresh_token`; the revoker
compares both forms.)

**SCIM 2.0** (RFC 7643, 7644) at `/scim/v2` (`Infrastructure/ScimEndpoints.cs`, the changes of a person in `ScimPeople`, the same as the pages of People): `Users` (id = the
subject), `Groups` (id = the number), `ServiceProviderConfig`, `Schemas`, `ResourceTypes`. Filters `attribute eq "value"` only, paging, `PATCH` add/replace/remove (also the
way Entra ID writes it: `"Replace"`, `"False"`), no bulk, no sorting, no ETags. The extension `urn:mat:scim:schemas:extension:access:1.0:User` / `:Group` carries the `grants`
(written as a whole) and, read only, `access` (what the person ends up with per app, with `via`) and `administrator`; the core `roles` and `entitlements` carry the same with the
app as `type`. MatIdentity's key (`X-Api-Key` or bearer) reads and writes everything (`X-Mat-Actor: <sub>` names the person who acted, for the activity list); the key of a
binding of **`people.scim`** (a key capability MatIdentity provides; MatPlatform's generic handler) only reads, and only the people who may use that app with their values
there. The last active administrator can be neither disabled, demoted nor deleted. What SCIM has no word for is `POST /api/v1/people/{subject}/actions/{action}`
(`invite`, `resetPassword`, `signOut`, `unlock`, `resetSecondStep`), and `GET /api/v1/clients` answers each app with its role mode, *open to everyone*, roles,
permissions and quotas (what a shell draws its forms from).

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

## Branded sign-in

A broker can give the sign-in of an app it manages a look of its own, so that a person signs in **to that app** and never sees MatIdentity (MatOS: "Sign in to MatOS",
its logo, its accent; the apps it installs keep MatIdentity's own sign-in, "Sign in once, for all your apps"). The sign-in itself still happens here, so its session lets
every other app in without a password: single sign-on stays.

- **Where it is set.** `PUT /api/v1/clients/{id}` with `branding` (missing keeps it, `null` removes it):
  `{ name, accent: "#rrggbb"?, hideIdentity, logo: { contentType: "image/svg+xml"|"image/png", data: Base64 }?, background: { contentType: "image/jpeg"|"image/png"|"image/webp", data: Base64 }? }`.
  The name, accent and `hideIdentity` are set as a whole; a picture that is missing is kept, `null` removes it. Logo at most 256 KiB, background 2 MiB; the bytes must be of
  the type they claim (`BrandingRules`); anything wrong is a 400 with `errors["branding.*"]` and nothing is saved. Only the one who manages the app brands it: the request's
  `managedBy` must be the app's mark (none for an app an administrator made), else 409. `GET` answers `branding` without the pictures:
  `{ name, accent, hideIdentity, hasLogo, hasBackground, logoContentType, backgroundContentType, logoUrl, backgroundUrl }` (absolute, with `?v=`), or null. Removing the app
  removes its look. The table is `ClientBranding` (`Core/Clients/BrandingService`); the pictures live in it, never on disk.
- **Served from here.** `/branding/{clientId}/logo`, `/background`, `/icon.svg` (the first letters of the name on the accent: the logo and the tab's icon of a brand without a
  logo) and `/theme.css` (the accent as `--mat-app-accent` of `[data-app="brand"]`, the background as `--mi-brand-image`; without one `matidentity.css` lays a calm gradient from
  the accent). Each with an ETag (304), a year of caching with the current `?v=`, an hour without, `X-Content-Type-Options: nosniff`; the pictures with
  `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; sandbox`: an SVG is only ever shown through `<img>`, and opened by itself it runs nothing.
- **Which pages.** Login, Forgot, Reset, TwoFactor, Register, Verify, NoAccess, AccessDenied, ChangePassword (the forced change of a password during a branded
  sign-in), the sign-out question (Logout) and the error pages (`StatusCode/*`, `Error`) use the layout `_SignIn`: `_Bare` as before, unless `SignInBranding` finds a
  brand; then the whole document is the app's (title "Sign in · MatOS", its icon, no manifest, `data-app="brand"`, its theme.css) and `_AuthLogo` shows its logo. With
  `hideIdentity` no word, logo, footer, version or link of MatIdentity is on those pages (a link home goes to the app's `homeUrl`, or is left out); without it the sign-in says
  "With your MatIdentity account".
- **Where the brand comes from** (`Infrastructure/SignInBranding`, first match wins): the `client_id` of the app's request in the `returnUrl` (a local
  `/connect/authorize` or `/connect/logout`; query or form; an app without a brand ends the brand), the OpenID Connect request an error page answers, `?brand=<clientId>`
  (the links of the mails), `?app=` of NoAccess, else the cookie `mid.brand` (the client id, 30 minutes, HttpOnly, SameSite=Lax),
  which the pages set whenever a request names a brand. A brand is looked up only for the id of a registered app. The app's request always wins over `?brand`: a page never
  shows one app's brand while it signs the person in to another. A middleware works it out at the start of those pages, so
  the cookie is set before the answer begins.
- **Through the flow.** Forgot -> the mail -> Reset -> the sign-in stays branded: the links of the reset and verification mails carry `&brand=<clientId>`, and with
  `hideIdentity` the mails speak of the app ("MatOS: set a new password"). A sign-in that has no request of an app to go back to (after a new password) ends at the app's
  `homeUrl` instead of MatIdentity's home page (`SignInBranding.ContinueTo`, also after the second step and a passkey); the app then starts its sign-in and finds the session.
- **Mails a broker triggers.** The invitation and the new password a broker asks for (`POST /api/v1/people/{subject}/actions/invite|resetPassword`, SCIM
  `POST /scim/v2/Users` without a password) take the brand the header `X-Mat-Brand: <clientId>` names (a registered app with a brand, else ignored): the mail speaks of
  the app when it hides MatIdentity and its link carries `&brand=`. MatOS sends its own client id.
- **The forced password change.** `PasswordChangeGuardMiddleware` sends a person who must change their password to `/Account/ChangePassword`: with a brand a step of the
  sign-in in its look, without one it hands over to the password tab of the account, as before.
- **Not branded:** the account pages, Setup, invitations sent by an administrator in the UI.

## Sign-out reaches the apps

OpenID Connect Back-Channel Logout 1.0. The ID token carries `sid`, the public id of the session (`SessionIds.Of`: a hash of the session token, never the
token). A session remembers the apps it signed in to (`UserSession.ClientIds`). Whenever sessions end, `SessionService` tells its `ISessionEndListener`;
the web project's `BackchannelLogout` sends every app with a sign-out address (`BackchannelLogoutUri`) a logout token (JWT `logout+jwt`, signed with the key
of the ID tokens, `iss`, `aud`, `sub`, `sid`, `events`, `jti`, two minutes) after the answer; a person out everywhere (disabled, new password set by an
administrator, signed out by one) is announced to every such app with `sub` alone. A change of what a person is given in an app (see "Permissions") is announced to that
app the same way. Front-channel logout is not offered: its iframes need third-party
cookies. A `GET /connect/logout` without the person's `id_token_hint` asks first (a link from another site must not sign anyone out).

## Brute force

Per address: the rate limits. Per account: ten wrong passwords or second-step codes in a row lock the password sign-in for 15 minutes; the answer stays
"Incorrect username or password", so a right password does not show through. The count resets only after a complete sign-in. A passkey alone still signs in.
