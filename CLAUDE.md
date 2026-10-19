# CLAUDE.md

Guidance for working in this repository. Keep it in sync with the code: update it whenever architecture, persistence,
interfaces or major data flow change.

## What MatIdentity is

The **OpenID Connect server** of the Mat family (single sign-on): people sign in here once, the apps let them in. Optional for every app: an app that has
`MATIDENTITY_AUTHORITY` / `_CLIENT_ID` / `_CLIENT_SECRET` sends people here; without them it keeps its own sign-in. Apps that call each other get machine tokens
here (client credentials, scope `app:<id>`). The contract with the apps is MatDesign's [docs/PLATFORM.md](https://github.com/Real-TTX/MatDesign/blob/main/docs/PLATFORM.md);
MatIdentity is also the first app that implements its `/api` (the MatApiDefinition).

Stack (the same as Mattiverse): ASP.NET Core on **.NET 10**, C#, **Razor Pages** + TagHelper controls, EF Core + **SQLite**, **OpenIddict 7** (server + validation),
plain JavaScript (no build step), Docker-first, runs as the unprivileged user `app`. Web port **2300**.

The look and the controls are **MatUi**, the toolkit of [MatDesign](https://github.com/Real-TTX/MatDesign) (port 8060): the pages are built from its classes and follow its
rulebook. The accent is `#a21a50` (registered in MatDesign's `AppRegistry`; `#9d174d` failed AA in dark mode). Read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) before changing the design.

## Build / run / test

- **Build:** `dotnet build MatIdentity.slnx` (note: `.slnx`). SDK 10 (see `global.json`). Expected: 0 warnings.
- **Tests:** `dotnet test`: xunit. `ClientRulesTests` (rules without the site), `MigrationLockTests` (a stale EF migration lock is removed at start),
  `WebUiTests` (the source of the pages: icons of the sprite, no inline style or script, tokens only in the stylesheet), and the whole site in memory (`IdentityFactory`, a `WebApplicationFactory` on its own temp data folder, Development, key `test-key-…`):
  `OidcFlowTests` (discovery, code + PKCE end to end with the real sign-in form, single sign-on, refresh, machine tokens and audiences, wrong secret = 401)
  and `PlatformApiTests` (the contract, access, configure, the client API, every page opens). The site tests share one collection (environment variables).
- **Run / test the app: always rebuild the container and redeploy the stack** (project rule): `./scripts/redeploy.ps1` (`-Fresh` wipes the volume and with it the token keys,
  `-Port` changes the host port). Dev stack: `docker-compose.dev.yml` (app + `sqlite-web` on 2309, subnet `10.253.24.0/24` because the PC has its Docker address pools used up).
  In `Development` the account `admin@example.com` / `Start12345` exists and `MAT_API_KEY` is `dev-key`.
- **Release stack:** `docker-compose.yml`, image `ghcr.io/real-ttx/matidentity`, one service and one volume: keep it that simple.
- **The volume and a non-root image:** the image has a placeholder file in `/data` so that Docker copies the folder's owner (`app`) into a new named volume; without it the
  volume is root's and the app cannot write. `sqlite-web` (root) starts only when MatIdentity is healthy, else it creates an empty database first.
- **Screenshots** (the `screenshots` skill): Playwright with the installed Edge; demo apps through `PUT /api/v1/clients/<id>` with `X-Api-Key: dev-key`, demo people through
  the real form. Never real data in `docs/images`.
- **Updating the toolkit:** `./scripts/update-matui.ps1` copies the files from a running MatDesign (default http://localhost:8060) into `wwwroot/matui` (a copy, rule CODE-03:
  never edit them here).
- **New schema:** `dotnet ef migrations add <Name> --project src/MatIdentity.Core --startup-project src/MatIdentity.Web --output-dir Data/Migrations`.

## Map

```
src/MatIdentity.Core       domain, no web types
  Entities/ Data/            User (Subject = the claim sub), UserSession, ActivityEntry; DbContext (+ OpenIddict's tables Oidc*), migrations
  Auth/ Users/ Security/     sign-in, sessions in SQLite, TwoFactorService (TOTP, recovery codes), PasskeyService, Totp (RFC 6238), PBKDF2 hasher, secret protector
  Access/                    PermissionService (who may sign in where, with which role; app roles; which apps an app may call), GroupService
  Clients/                   ClientModels (ClientInfo, ClientRules), ClientService (the apps over OpenIddict, their scopes app:<id>), TokenRevoker
  Activity/                  ActivityService (the activity list, 90 days)
  Configuration/             options, AppPaths, JsonConfigStore, SystemConfig(+Service: the settings and their rules)
src/MatIdentity.Web        Razor Pages, controls, endpoints, Program.cs (OpenIddict, cookie, rate limits, forwarded headers)
  Infrastructure/            OidcEndpoints (authorize, token, userinfo, logout), SignInFlow (the end of every sign-in, the second step), PasskeyEndpoints (WebAuthn), TokenKeys, ApiAccess (X-Api-Key or token for app:matidentity),
                             ClientApiEndpoints (/api/v1/clients for Mattiverse), RateLimits, session validation, setup and password guards, health check
  Platform/                  MatApiDefinition (the contract's types), PlatformEndpoints (/api, health, state, configure, actions), IdentityPlatform (MatIdentity's part)
  Pages/                     Index (your apps; figures for an administrator), Apps/ (Edit, Access), Users/ (People), Groups/, Activity/, Settings/, Account/ (Login, TwoFactor,
                             NoAccess, Logout, Profile: general, password, devices; Security: authenticator app, recovery codes, passkeys), Setup, StatusCode (also the errors of the protocol), Error
  Support/ Controls/         Ui (icons, logo, app letters and hues), Navigation, Crumbs, Format, Authority, Toolkit; tag helpers (mat-field, icon, tab-bar), ListModels
  wwwroot/                   matui/ (the toolkit, a copy), css/matidentity.css (mi-* only), js/matidentity.js, img/ (logo, favicon, PWA icons), manifest
tests/MatIdentity.Tests     unit tests + the site in memory
```

## Conventions

**Code**
- Microsoft C# guidelines, file-scoped namespaces, `.editorconfig`. Few nested types; several business functions per class are fine.
- A secret is never written in plain text anywhere: not in the database (OpenIddict hashes it), not in a cookie or TempData (a new secret is shown on the page of the POST
  itself), not in the activity list or a log.
- No DbContext, no EF Core and no SQL in MatIdentity.Web (`WebUiTests` checks; only Program.cs registers the context): the pages and endpoints call the services of Core.
- The sign-in limit (20 attempts a minute per address) counts POSTs only; `MatIdentity__RateLimits__SignIn` changes it (the tests raise it).
- Whatever ends a person's access ends it everywhere: sessions here (`SessionService.InvalidateAllAsync`) **and** the refresh tokens of the apps (`TokenRevoker`).
- The page and the API share their rules (`ClientRules`, `SystemConfigService`): never check a value only in one of them.
- `/api/v1/clients`: `managedBy` marks what a caller created; a caller deletes only what carries its own mark.

**Database**
- JSON for configuration, SQLite for logic. Tables PascalCase and singular, key `Id` (64 bit), `CreateDate`, `CreateUserId`, `UpdateDate`, `UpdateUserId`, `UpdateState`
  (0 deleted, 1 created, 2 updated); security keys are a `Token` UUID. The exception are OpenIddict's tables (see docs/ARCHITECTURE.md).

**UI** (the rules are MatDesign's; where this list and the rulebook differ, the rulebook wins)
- Only toolkit classes (`mat-*`) plus `mi-*` in `wwwroot/css/matidentity.css` (tokens only). **No inline style, no inline script, no event-handler attribute** (`WebUiTests`).
- CRUD = a list (toolbar on top, table, `_Pager` directly under it, actions below) plus a page for create/edit; forms are `mat-form novalidate`, `_ValidationSummary`, `mat-field`,
  then Save, Back, (space) the dangerous action. Confirmations are `data-confirm`, dependent fields `data-show-if`.
- The logo (`img/logo.svg`): the flat accent tile with a keyhole whose top is a head, in an open ring with one dot. The PNGs are rendered from it with Edge (see the screenshots
  skill); change the SVG and render them again.
- Mobile matters: check 390 px for every new page; secondary table columns get `mat-hide-sm`.

**Git**
- Commit and push **under the user's name**, never add a Claude/Anthropic co-author trailer or "generated with" line.
- Branches: `main` = release, `dev` = development. Versions: release `<major>.<minor>.<build>-<date>`, development `nightly-<build>-<date>`, local `local-<date>`
  (`Directory.Build.props`, `.github/workflows/build.yml`).
