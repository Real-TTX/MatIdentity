<div align="center">

<img src="src/MatIdentity.Web/wwwroot/img/logo.svg" width="96" alt="MatIdentity" />

# MatIdentity

**One sign-in for all your Mat apps.**

The OpenID Connect server of the Mat family: people sign in once, here, and every app (MatSplit, MatPaper, MatFile, Mattiverse, …)
lets them in. Apps that talk to each other get their tokens here too. Self-hosted, one container, one volume.

</div>

![The start page: figures, the apps of the person, what happened recently](docs/images/home.png)

---

## What this is about

Every Mat app has its own users and its own sign-in form. MatIdentity is the optional shared one: set
`MATIDENTITY_AUTHORITY` (and the client id and secret) in an app, and a person who is not signed in goes straight here and comes back
signed in, **without a second form** in any other app. Without the variable an app works exactly as before.
The contract every app follows is [docs/PLATFORM.md of MatDesign](https://github.com/Real-TTX/MatDesign/blob/main/docs/PLATFORM.md).

With [Mattiverse](https://github.com/Real-TTX/Mattiverse) you do not even set the variables: install MatIdentity from its store, and Mattiverse
registers every app it installs here and gives it its sign-in.

## At a glance

**Sign-in**
- **OpenID Connect** with authorization code and **PKCE** (enforced), refresh tokens, sign-out at every app (end session)
- **Single sign-on**: a session here signs a person into the next app without the form
- Sessions live in SQLite and **survive a restart**; a person sees their devices and signs out the others
- The tokens carry `sub` (a stable UUID), `name`, `preferred_username`, `email` and the `role` **of the app** (see Permissions)

**Second step (optional for everyone)**
- **Authenticator app** (TOTP, RFC 6238) with a QR code and 10 **recovery codes**, shown once
- **Passkeys** (WebAuthn: Windows Hello, Touch ID, phone, security key): sign in **without a password**, or use one as the second step after it
- Whoever has an authenticator app or a passkey is asked for it after the password; five wrong codes and it starts again
- An administrator sees who uses what and resets it when a phone is lost

**Permissions**
- **Groups** (Family, Guests): apps and roles for many people at once
- **Who may sign in** to an app: a new app is open to nobody but the administrators until people or groups are given to it (or it is opened to everyone)
- **Who decides the roles**, per app: *Admin* (MatIdentity gives each person or group a role of the app, the token carries it) or *Managed by the app* (no role in the token, the app decides)
- The roles of an app come from its MatApiDefinition (`roles`) or are written down; the rules are asked at every sign-in and every renewal
- **Which apps an app may call** (machine tokens): all, or the ones chosen

**Apps**
- Add an app in the UI, or let **Mattiverse** add it when it installs one (`/api/v1/clients`, marked *Managed by mattiverse*)
- The **secret is shown once** with the variables the app needs, ready to copy; MatIdentity keeps only its hash
- **Apps calling apps**: an app with *calls other apps* gets a token for `app:<id>` (client credentials) whose audience is the other app

**Administration**
- **People**: create, change, disable; a disabled account or a new password signs the person out **everywhere** (sessions and the refresh tokens of the apps)
- **Activity**: sign-ins, failed sign-ins (a badge in the menu), app sign-ins, machine tokens, changes to apps; kept for 90 days
- **Sign everyone out**: the emergency button
- Rate limits on the sign-in form, the token endpoint and the API; forwarded headers only from known proxies

**The Mat platform**
- `/api` describes MatIdentity (the **MatApiDefinition**: tiles, settings, buttons), `/api/health`, `/api/state`, `/api/configure`, `/api/actions/{id}`, so Mattiverse shows and configures it without knowing it
- Built on **MatUi** of [MatDesign](https://github.com/Real-TTX/MatDesign): the same menu, lists, forms and dark mode as every Mat app

## Screenshots

### Signing in – with a password, a passkey, or both

The form every app sends people to. A passkey signs in without the password; whoever set up a second step is asked for it after the password.

| Sign-in | Dark |
|---|---|
| ![The sign-in form](docs/images/login.png) | ![The sign-in form, dark](docs/images/login-dark.png) |

| With a passkey | The second step after the password |
|---|---|
| ![Signing in with a passkey](docs/images/login-passkey.png) | ![The code of the authenticator app after the password](docs/images/second-step.png) |

### The apps

Every app that signs in here, with its id, what it may do and who added it. *Managed by mattiverse* marks the apps Mattiverse registered when it installed them.

![The list of apps](docs/images/apps.png)

| An app: its addresses and what it may do | Its secret, once, with the variables to copy |
|---|---|
| ![An app](docs/images/app-edit.png) | ![The new secret and the variables of the app](docs/images/app-secret.png) |

### Who may sign in, and with which role

Per app: whether MatIdentity gives the roles (*Admin*) or the app keeps its own (*Managed by the app*), whether everyone may sign in, and which people
and groups may – each with a role of the app. The roles come from the app's own description (`/api`) with one click.

![The access of MatSplit: rules, people and groups with their roles](docs/images/app-access.png)

### Groups

Many people, one entry: give an app to *Family* and everyone in it may sign in, with the role of the group (or their own, when they have one).

| Groups | A group and its people |
|---|---|
| ![The list of groups](docs/images/groups.png) | ![A group with its people](docs/images/group-edit.png) |

### People

Create, change, disable. A new password or a disabled account ends every session and every refresh token of the apps at once.
An administrator sees who uses an authenticator app or a passkey, and resets it when a phone is lost.

| People | Who uses a second step | A lost phone |
|---|---|---|
| ![The list of people](docs/images/people.png) | ![People with their second step](docs/images/people-second-step.png) | ![Resetting the second step of a person](docs/images/person-reset.png) |

### The security of an account

Each person sets up their own second step: an authenticator app (with recovery codes, shown once) and as many passkeys as they like.
Their devices are listed too; one click signs out the others.

| Authenticator app and passkeys | Setting up the app | The recovery codes, once |
|---|---|---|
| ![Authenticator app and passkeys of an account](docs/images/security-on.png) | ![The QR code of the authenticator app](docs/images/security-setup.png) | ![The recovery codes](docs/images/security-codes.png) |

![The devices that are signed in](docs/images/account-devices.png)

### Activity and settings

Sign-ins, failed sign-ins, app sign-ins, machine tokens and every change to an app, kept for 90 days. The settings hold the public address,
how long a sign-in lasts and the emergency button that signs everyone out.

| Activity | Settings |
|---|---|
| ![The activity list](docs/images/activity.png) | ![The settings](docs/images/settings.png) |

### Dark, and on a phone

| Dark | The access page, dark |
|---|---|
| ![The start page, dark](docs/images/home-dark.png) | ![The access of an app, dark](docs/images/app-access-dark.png) |

| Start page | Apps | Menu |
|---|---|---|
| ![The start page on a phone](docs/images/mobile-home.png) | ![The apps on a phone](docs/images/mobile-apps.png) | ![The menu on a phone](docs/images/mobile-menu.png) |

## Quick start

Ready-made images are published to the GitHub Container Registry:

| Tag | Built from | Use it for |
|---|---|---|
| `ghcr.io/real-ttx/matidentity:latest` | `main` | releases |
| `ghcr.io/real-ttx/matidentity:nightly` | `dev` | the newest features |

### 1. Just run it

Copy this into `docker-compose.yml` and start it – nothing else needed:

```yaml
services:
  matidentity:
    image: ghcr.io/real-ttx/matidentity:latest
    container_name: matidentity
    restart: unless-stopped
    ports:
      - "2300:2300"
    volumes:
      - matidentity-data:/data

volumes:
  matidentity-data:
```

```bash
docker compose up -d
```

Open **http://localhost:2300**: the first start asks for the administrator (health check: `/api/health`). The `matidentity-data` volume keeps
the database, the settings and the keys that sign the tokens, so an update is just `docker compose pull && docker compose up -d`.

Without Compose:

```bash
docker run -d --name matidentity --restart unless-stopped -p 2300:2300 \
  -v matidentity-data:/data ghcr.io/real-ttx/matidentity:latest
```

> **The volume holds the keys that sign every token.** Whoever has them can sign anyone in to every app: back it up like a password safe, and never share it.

### 2. Behind your reverse proxy, with HTTPS

OpenID Connect needs HTTPS outside of localhost, and every token names the public address of MatIdentity as its issuer. So put it behind your
reverse proxy (Matcad, Caddy, Traefik, nginx …) and tell it that address:

```yaml
services:
  matidentity:
    image: ghcr.io/real-ttx/matidentity:latest
    container_name: matidentity
    restart: unless-stopped
    environment:
      MatIdentity__Issuer: https://id.example.com      # the public address: the iss of every token
      # MatIdentity__TrustedProxies: 10.0.0.0/8        # who may send X-Forwarded-* (default: the private networks)
      # MAT_API_KEY: <a long random key>               # the key of the platform API; Mattiverse sets it
    ports:
      - "2300:2300"                                    # or no port at all, when the proxy is in the same Docker network
    volumes:
      - matidentity-data:/data

volumes:
  matidentity-data:
```

The public address can also be set in *Settings*; the setting in the UI wins over the variable. Change it only before the apps are connected:
an app checks that the issuer of a token is the address it knows.

### 3. With Mattiverse

Install **MatIdentity** from the store of Mattiverse (or tick it in the setup wizard). Mattiverse sets the public address, registers itself and
every app that can use it (MatSplit, MatTrakr, MatPaper, MatFile, Matdo, MatPlay, MatBu, MatDock, Matcad, Matddns …), fills in their `MATIDENTITY_*`
variables and redeploys them. When MatIdentity goes, the apps go back to their own sign-in. Who may open which app is set here, in MatIdentity.

### 4. From source

```bash
git clone https://github.com/Real-TTX/MatIdentity.git && cd MatIdentity
docker compose -f docker-compose.dev.yml up -d --build    # development stack (app + SQLite web viewer on 2309)
```

### Connecting an app

In *Apps → Add an app*: the id (`matsplit`), the address and the sign-in address of the app (ASP.NET Core: `https://split.example.com/signin-oidc`).
MatIdentity shows the variables once:

```
MATIDENTITY_AUTHORITY=https://id.example.com
MATIDENTITY_CLIENT_ID=matsplit
MATIDENTITY_CLIENT_SECRET=...
```

Then, in *Access*, give the app to the people or groups who may open it. Any other app that speaks OpenID Connect finds everything at
`https://id.example.com/.well-known/openid-configuration` (scopes `openid profile email roles offline_access`).

### Settings that matter

| Variable | Default | Meaning |
|---|---|---|
| `MatIdentity__DataPath` | `/data` | Database, settings, the keys of cookies and tokens |
| `MatIdentity__Issuer` | – | The public address (`iss`); the setting in the UI wins. Empty: the address of the request |
| `MatIdentity__TrustedProxies` | private networks | Who may send `X-Forwarded-*` (addresses or networks, comma-separated) |
| `MAT_API_KEY` | – | The key of the platform API (`X-Api-Key`); Mattiverse sets it |
| `MatIdentity__Admin__Seed` | `false` | Create the admin from `__Username` / `__Password` (headless installs; the password must be changed at the first sign-in) |
| `MatIdentity__RateLimits__SignIn` | `20` | Sign-in attempts a minute per address |
| `MATIDENTITY_PORT` | `2300` | Host port in the compose files |

## Mat platform: API and the apps of the family

MatIdentity speaks the platform contract of the Mat apps (MatDesign [docs/PLATFORM.md](https://github.com/Real-TTX/MatDesign/blob/main/docs/PLATFORM.md)):

| Address | What |
|---|---|
| `GET /api` | The MatApiDefinition: tiles (people, apps, sessions, sign-ins and failed sign-ins today, the last sign-in), settings, buttons. Anonymous |
| `GET /api/health` | `ok` / `degraded` / `down` with the checks. Anonymous; the Docker health check asks it |
| `GET /api/state[/key]` | The values of the tiles |
| `GET/PUT /api/configure` | The settings Mattiverse may change |
| `POST /api/actions/{id}` | The buttons: sign everyone out (the links open MatIdentity and its apps) |
| `/api/v1/clients` | The apps, for Mattiverse (create, change, remove what it created) |

Access with `X-Api-Key: <MAT_API_KEY>` or a token of MatIdentity whose audience is `app:matidentity`.

The apps use the shared .NET package **MatPlatform** of MatDesign for their side: the endpoints, the sign-in through MatIdentity (auto-login, `?local=1`
for the local form, sign-out at MatIdentity, the scheme behind a TLS proxy) and the rule for existing accounts: an account of the app that has the
same address is linked only after the person signed in to it once with its own password.

## How it works

```
/data
├─ matidentity.db         SQLite: people, sessions, groups, access, activity, and OpenIddict's apps, scopes, authorizations, tokens
├─ config/system.json     JSON: name, public address, how long a sign-in lasts, the lifetime of an access token
├─ dataprotection-keys/   the keys of the cookies (so sessions survive restarts)
└─ token-keys/            the RSA key that signs the tokens and the key that encrypts codes and refresh tokens
```

- [OpenIddict](https://documentation.openiddict.com/) checks the protocol; MatIdentity decides who is signed in, who may enter an app and what goes into the tokens (`Infrastructure/OidcEndpoints.cs`, `Access/PermissionService.cs`).
- Access tokens are signed JWTs (not encrypted), so an app checks them itself with the published keys (`/.well-known/jwks`).
- More in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Development

Stack: ASP.NET Core 10 (Razor Pages), C#, SQLite via EF Core, OpenIddict, plain JavaScript. No Node build step.

```bash
dotnet build MatIdentity.slnx         # 0 warnings expected
dotnet test                           # unit tests and the whole site in memory: the OpenID Connect flow end to end, the API, the pages
./scripts/redeploy.ps1                # rebuild the container and redeploy the dev stack
./scripts/redeploy.ps1 -Fresh         # ... with a clean data volume (new keys: every app signs out)
./scripts/update-matui.ps1            # bring a newer MatUi from a running MatDesign into wwwroot/matui
```

The dev stack is the app plus a SQLite web viewer on `http://localhost:2309`. In `Development` the account **`admin@example.com` / `Start12345`** exists and the
platform key is `dev-key`.

### Branches and versions

| Branch | Purpose | Image tag | Version |
|---|---|---|---|
| `main` | Release | `latest`, `release`, `<version>` | `<major>.<minor>.<build>-<yyyyMMdd>` |
| `dev` | Development | `nightly`, `<version>` | `nightly-<build>-<yyyyMMdd>` |
| local | – | – | `local-<yyyyMMdd>` |

## Status

| Area | Status |
|---|---|
| OpenID Connect server (code + PKCE, refresh, client credentials, user info, end session) | ✅ |
| People, sessions, devices, activity, sign everyone out | ✅ |
| Apps in the UI and through the API for Mattiverse | ✅ |
| The platform contract (`/api`, health, state, configure, actions) | ✅ |
| Authenticator app (TOTP), recovery codes, passkeys (passwordless and as second step) | ✅ |
| Groups, access and roles per app, which apps an app may call | ✅ |
| The apps of the family signing in through it (`MATIDENTITY_*`) | ✅ MatSplit, MatTrakr, MatPlay, MatBu, Matdo, MatFile, MatPaper, MatDock, Matcad, Matddns · MatMail in progress |

## License

No license file is included yet. If you intend others to reuse this, add a `LICENSE` (for example MIT) at the repo root.
