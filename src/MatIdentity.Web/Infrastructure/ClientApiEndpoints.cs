using System.Text.Json;
using System.Text.Json.Nodes;
using MatIdentity.Core.Access;
using MatIdentity.Core.Activity;
using MatIdentity.Core.Auth;
using MatIdentity.Core.Clients;
using MatIdentity.Core.Configuration;
using MatIdentity.Core.Entities;
using MatIdentity.Core.Users;
using MatPlatform;

namespace MatIdentity.Web.Infrastructure;

/// <summary>
/// The API of the apps (docs/PLATFORM.md, "Sign-in with MatIdentity"): Mattiverse registers itself here (client <c>mattiverse</c>, calls every app); the apps it installs are
/// bound through <c>/api/bindings/identity.oidc/...</c> (<see cref="Platform.IdentityBindings"/>), which goes the same way (<see cref="ClientService.UpsertAsync"/>,
/// <see cref="ClientService.RemoveManagedAsync"/>). The same rules as the pages, the same key or token as the rest of <c>/api</c>. Like the engines' APIs: an upsert by id,
/// <c>managedBy</c> marks what a caller created, and a caller only deletes what carries its own mark.
/// <code>
/// GET    /api/v1/status                      { ok, app, version, apiVersion: 1 } (as the engines of Mattiverse answer it)
/// GET    /api/v1/clients                     the apps (never a secret), each with roleMode, openToEveryone, roles, permissions and quotas (what a shell draws its forms from)
/// GET    /api/v1/clients/{clientId}
/// PUT    /api/v1/clients/{clientId}          { displayName, homeUrl, redirectUris, postLogoutRedirectUris, allowSignIn, allowMachine, isPublic, managedBy, renewSecret,
///                                              roleMode: "matidentity" or "app", roles: [{ key, label }], openToEveryone, callsAllApps,
///                                              permissions: [{ key, label, hint, roles }], quotas: [{ key, label, unit, period, min, max, hint }],
///                                              callTargets: ["matsplit", "matidentity"] (by name; MatIdentity's own API only so),
///                                              backchannelLogoutUri: where the app hears that a person signed out ("" removes it),
///                                              branding: the look of its sign-in (docs/ARCHITECTURE.md "Branded sign-in"; missing keeps it, null removes it):
///                                                { name, accent: "#rrggbb"?, hideIdentity, logo: { contentType: "image/svg+xml"|"image/png", data: Base64 }?,
///                                                  background: { contentType: "image/jpeg"|"image/png"|"image/webp", data: Base64 }? }
///                                                logo at most 256 KiB, background 2 MiB; a picture that is missing is kept, null removes it; 400 when it is not
///                                                valid, 409 when the app carries another mark than managedBy (only its manager brands it) }
///                                            200 { client, clientSecret?, ..., branding? }: the secret only when it was made now (a new app, or renewSecret: true)
/// GET answers branding as { name, accent, hideIdentity, hasLogo, hasBackground, logoContentType, backgroundContentType, logoUrl, backgroundUrl } (never the data), or null.
/// DELETE /api/v1/clients/{clientId}?managedBy=mattiverse   204, 404, or 409 when the app carries another mark
/// POST   /api/v1/people/{subject}/actions/{action}          what SCIM has no word for: invite, resetPassword, signOut, unlock, resetSecondStep
///                                            200 { ok, message }, 404 for an unknown person or action, 409 when it cannot run now
/// </code>
/// </summary>
public static class ClientApiEndpoints
{
    public static void MapClientApi(this WebApplication app)
    {
        var options = MatApiDefinition.Json;

        // The status every engine of Mattiverse answers (Mattiverse docs/ENGINES.md): it waits for this before it registers anything.
        app.MapGet("/api/v1/status", () => Results.Json(new { ok = true, app = MatIdentity.Web.Support.Ui.App.Id, version = MatIdentity.Core.AppVersion.Current, apiVersion = 1 }, options))
            .AllowAnonymous().AddEndpointFilter(ApiAccess.RequireAsync).DisableAntiforgery();

        var api = app.MapGroup("/api/v1/clients").AllowAnonymous().AddEndpointFilter(ApiAccess.RequireAsync).DisableAntiforgery();

        api.MapGet("/", async (HttpContext http, ClientService clients, PermissionService permissions, BrandingService branding, CancellationToken ct) =>
        {
            var all = new JsonArray();
            var list = await clients.GetAllAsync(ct);
            var brands = await branding.GetManyAsync(list.Select(c => c.ClientId).ToList(), ct);
            var baseUrl = await BaseUrlAsync(http);
            foreach (var client in list)
            {
                all.Add(await WithAccessAsync(client, permissions, brands.GetValueOrDefault(client.ClientId), baseUrl, ct));
            }

            return Results.Text(all.ToJsonString(options), "application/json");
        });

        api.MapGet("/{clientId}", async (string clientId, HttpContext http, ClientService clients, PermissionService permissions, BrandingService branding, CancellationToken ct) =>
            await clients.GetAsync(clientId, ct) is { } client
                ? Results.Text((await WithAccessAsync(client, permissions, await branding.GetAsync(clientId, ct), await BaseUrlAsync(http), ct)).ToJsonString(options), "application/json")
                : NotFound(clientId));

        api.MapPut("/{clientId}", async (string clientId, ClientBody body, HttpContext http, ClientService clients, PermissionService permissions, BrandingService branding, ActivityService activity, CancellationToken ct) =>
        {
            // The same way as a binding of identity.oidc (ClientService.UpsertAsync): the rules first, the id and the roles checked before anything is saved.
            var roleMode = body.RoleMode switch { "app" => RoleMode.App, "matidentity" => RoleMode.MatIdentity, _ => (RoleMode?)null };
            var upsert = new ClientUpsert
            {
                ClientId = clientId,
                DisplayName = body.DisplayName,
                HomeUrl = body.HomeUrl,
                AllowSignIn = body.AllowSignIn,
                AllowMachine = body.AllowMachine,
                IsPublic = body.IsPublic,
                RedirectUris = body.RedirectUris,
                PostLogoutRedirectUris = body.PostLogoutRedirectUris,
                BackchannelLogoutUri = body.BackchannelLogoutUri,
                ManagedBy = body.ManagedBy,
                RenewSecret = body.RenewSecret == true,
                RoleMode = roleMode,
                Roles = body.Roles?.Select(r => new RoleInfo(r.Key ?? string.Empty, r.Label ?? r.Key ?? string.Empty)).ToList(),
                Permissions = body.Permissions?.Select(p => new PermissionInfo(p.Key ?? string.Empty, p.Label ?? p.Key ?? string.Empty, p.Hint, p.Roles)).ToList(),
                Quotas = body.Quotas?.Select(q => new QuotaInfo(q.Key ?? string.Empty, q.Label ?? q.Key ?? string.Empty, q.Unit ?? string.Empty, q.Period, q.Min, q.Max, q.Hint)).ToList(),
                OpenToEveryone = body.OpenToEveryone,
                CallsAllApps = body.CallsAllApps,
                SendsGroups = body.SendsGroups,
                CallTargets = body.CallTargets,
            };

            // The look of its sign-in (docs/ARCHITECTURE.md "Branded sign-in"): checked with the rest, before anything is saved.
            var brandChange = ParseBranding(body.Branding);
            var brandErrors = brandChange.Errors;
            if (brandChange.Input is { } brandInput)
            {
                foreach (var (key, message) in BrandingRules.Check(brandInput).Errors)
                {
                    brandErrors[key] = message;
                }
            }

            if ((body.RoleMode is not null && roleMode is null) || brandErrors.Count > 0)
            {
                var errors = ClientService.CheckUpsert(upsert);
                if (body.RoleMode is not null && roleMode is null)
                {
                    errors["roleMode"] = "Use \"matidentity\" or \"app\".";
                }

                foreach (var (key, message) in brandErrors)
                {
                    errors[key] = message;
                }

                return Results.Json(new { errors }, options, statusCode: StatusCodes.Status400BadRequest);
            }

            // Only the one who manages an app gives it a look: an app an administrator made (no mark) without a mark, a broker's app with the broker's mark.
            if (brandChange.Given && await clients.GetAsync(clientId, ct) is { } current
                && !string.Equals(current.ManagedBy ?? string.Empty, body.ManagedBy ?? string.Empty, StringComparison.Ordinal))
            {
                return Results.Json(new { errors = new Dictionary<string, string> { ["branding"] = "Only the caller that manages this app sets the look of its sign-in: send its managedBy." } },
                    options, statusCode: StatusCodes.Status409Conflict);
            }

            var (result, created) = await clients.UpsertAsync(upsert, ct);
            if (!result.Succeeded)
            {
                return Results.Json(new { errors = result.Errors }, options, statusCode: StatusCodes.Status400BadRequest);
            }

            if (brandChange.Input is { } input)
            {
                await branding.SaveAsync(clientId, input, ct);
            }
            else if (brandChange.Remove)
            {
                await branding.RemoveAsync(clientId, ct);
            }

            var caller = http.Items[ApiAccess.CallerKey] as string;
            await activity.WriteAsync(created ? ActivityKind.ClientCreated : result.Secret is null ? ActivityKind.ClientChanged : ActivityKind.ClientSecretRenewed,
                username: caller, clientId: clientId, ipAddress: http.Connection.RemoteIpAddress?.ToString(), detail: "Through the API", ct: ct);
            var saved = await permissions.PolicyAsync(clientId, ct);
            return Results.Json(new
            {
                client = result.Client,
                clientSecret = result.Secret,
                roleMode = saved.RoleMode == RoleMode.App ? "app" : "matidentity",
                roles = await permissions.RolesAsync(clientId, ct),
                permissions = await permissions.PermissionsAsync(clientId, ct),
                quotas = await permissions.QuotasAsync(clientId, ct),
                saved.OpenToEveryone,
                saved.CallsAllApps,
                saved.SendsGroups,
                branding = BrandingNode(await branding.GetAsync(clientId, ct), await BaseUrlAsync(http)),
            }, options);
        });

        api.MapDelete("/{clientId}", async (string clientId, string? managedBy, HttpContext http, ClientService clients, ActivityService activity, CancellationToken ct) =>
        {
            // Never delete what the caller did not create.
            // No mark and an empty mark are the same (an app added in the UI is deleted with ?managedBy=).
            switch (await clients.RemoveManagedAsync(clientId, managedBy ?? string.Empty, ct))
            {
                case ClientRemoval.NotFound:
                    return NotFound(clientId);
                case ClientRemoval.OtherMark:
                    return Results.Json(new { errors = new Dictionary<string, string> { ["managedBy"] = "This app was not created by this caller." } }, options, statusCode: StatusCodes.Status409Conflict);
            }

            await activity.WriteAsync(ActivityKind.ClientDeleted, username: http.Items[ApiAccess.CallerKey] as string, clientId: clientId,
                ipAddress: http.Connection.RemoteIpAddress?.ToString(), detail: "Through the API", ct: ct);
            return Results.NoContent();
        });

        IResult NotFound(string clientId)
            => Results.Json(new { errors = new Dictionary<string, string> { ["clientId"] = $"There is no app \"{clientId}\"." } }, options, statusCode: StatusCodes.Status404NotFound);

        // What SCIM has no word for (MatDesign docs/PLATFORM.md "SCIM at MatIdentity"): the same as the buttons on the page of a person.
        app.MapPost("/api/v1/people/{subject}/actions/{action}", PersonActionAsync)
            .AllowAnonymous().AddEndpointFilter(ApiAccess.RequireAsync).DisableAntiforgery();
    }

    /// <summary>A client with what decides who may use it: role mode, open to everyone, roles, permissions and quotas; and the look of its sign-in (null: none).</summary>
    private static async Task<JsonObject> WithAccessAsync(ClientInfo client, PermissionService permissions, BrandInfo? brand, string baseUrl, CancellationToken ct)
    {
        var node = JsonSerializer.SerializeToNode(client, MatApiDefinition.Json)!.AsObject();
        var policy = await permissions.PolicyAsync(client.ClientId, ct);
        node["roleMode"] = policy.RoleMode == RoleMode.App ? "app" : "matidentity";
        node["openToEveryone"] = policy.OpenToEveryone;
        node["sendsGroups"] = policy.SendsGroups;
        node["roles"] = JsonSerializer.SerializeToNode(await permissions.RolesAsync(client.ClientId, ct), MatApiDefinition.Json);
        node["permissions"] = JsonSerializer.SerializeToNode(await permissions.PermissionsAsync(client.ClientId, ct), MatApiDefinition.Json);
        node["quotas"] = JsonSerializer.SerializeToNode(await permissions.QuotasAsync(client.ClientId, ct), MatApiDefinition.Json);
        node["branding"] = BrandingNode(brand, baseUrl);
        return node;
    }

    /// <summary>
    /// The look of a sign-in as the API answers it: never the pictures themselves, only whether there are any and their addresses (absolute, with the version, so they
    /// may be cached for a year).
    /// </summary>
    private static JsonObject? BrandingNode(BrandInfo? brand, string baseUrl)
    {
        if (brand is null)
        {
            return null;
        }

        return new JsonObject
        {
            ["name"] = brand.Name,
            ["accent"] = brand.Accent,
            ["hideIdentity"] = brand.HideIdentity,
            ["hasLogo"] = brand.HasLogo,
            ["hasBackground"] = brand.HasBackground,
            ["logoContentType"] = brand.LogoContentType,
            ["backgroundContentType"] = brand.BackgroundContentType,
            ["logoUrl"] = brand.LogoHash is { } logo ? baseUrl + BrandingEndpoints.Path(brand.ClientId, "logo", logo) : null,
            ["backgroundUrl"] = brand.BackgroundHash is { } background ? baseUrl + BrandingEndpoints.Path(brand.ClientId, "background", background) : null,
        };
    }

    /// <summary>The address of MatIdentity for the addresses of the pictures: the public one, else the one of the request.</summary>
    private static Task<string> BaseUrlAsync(HttpContext http)
        => Support.Authority.GetAsync(http, http.RequestServices.GetRequiredService<SystemConfigService>(), http.RequestServices.GetRequiredService<IConfiguration>());

    /// <summary>What a PUT says about the look of the sign-in.</summary>
    private sealed record BrandingChange(bool Given, bool Remove, BrandingInput? Input, Dictionary<string, string> Errors);

    /// <summary>
    /// <c>branding</c> of a PUT: missing keeps the look, <c>null</c> removes it, an object sets it: <c>name</c>, <c>accent</c> (<c>#rrggbb</c> or null),
    /// <c>hideIdentity</c>, and the pictures <c>logo</c> and <c>background</c> (<c>{ contentType, data }</c>, data as Base64), each kept when missing and removed with null.
    /// </summary>
    private static BrandingChange ParseBranding(JsonElement branding)
    {
        var errors = new Dictionary<string, string>();
        switch (branding.ValueKind)
        {
            case JsonValueKind.Undefined:
                return new BrandingChange(false, false, null, errors);
            case JsonValueKind.Null:
                return new BrandingChange(true, true, null, errors);
            case JsonValueKind.Object:
                break;
            default:
                errors["branding"] = "Give the look of the sign-in as an object, or null to remove it.";
                return new BrandingChange(true, false, null, errors);
        }

        string? Text(string name, string field)
        {
            if (!Property(branding, name, out var value) || value.ValueKind == JsonValueKind.Null)
            {
                return null;
            }

            if (value.ValueKind != JsonValueKind.String)
            {
                errors[field] = $"\"{name}\" must be text.";
                return null;
            }

            return value.GetString();
        }

        var hide = false;
        if (Property(branding, "hideIdentity", out var hideValue) && hideValue.ValueKind != JsonValueKind.Null)
        {
            if (hideValue.ValueKind is JsonValueKind.True or JsonValueKind.False)
            {
                hide = hideValue.GetBoolean();
            }
            else
            {
                errors["branding.hideIdentity"] = "\"hideIdentity\" must be true or false.";
            }
        }

        var (logo, removeLogo) = Picture("logo");
        var (background, removeBackground) = Picture("background");
        var input = new BrandingInput
        {
            Name = Text("name", "branding.name"),
            Accent = Text("accent", "branding.accent"),
            HideIdentity = hide,
            Logo = logo,
            RemoveLogo = removeLogo,
            Background = background,
            RemoveBackground = removeBackground,
        };
        return new BrandingChange(true, false, errors.Count == 0 ? input : null, errors);

        (BrandImageInput? Image, bool Remove) Picture(string name)
        {
            if (!Property(branding, name, out var value))
            {
                return (null, false);
            }

            if (value.ValueKind == JsonValueKind.Null)
            {
                return (null, true);
            }

            if (value.ValueKind != JsonValueKind.Object)
            {
                errors["branding." + name] = $"Give the {name} as {{ contentType, data }} (data as Base64), or null to remove it.";
                return (null, false);
            }

            var type = Property(value, "contentType", out var t) && t.ValueKind == JsonValueKind.String ? t.GetString() : null;
            var data = Property(value, "data", out var d) && d.ValueKind == JsonValueKind.String ? d.GetString() : null;
            return (new BrandImageInput(type, data), false);
        }

        static bool Property(JsonElement element, string name, out JsonElement value)
        {
            foreach (var property in element.EnumerateObject())
            {
                if (string.Equals(property.Name, name, StringComparison.OrdinalIgnoreCase))
                {
                    value = property.Value;
                    return true;
                }
            }

            value = default;
            return false;
        }
    }

    /// <summary><c>invite</c>, <c>resetPassword</c>, <c>signOut</c>, <c>unlock</c> or <c>resetSecondStep</c> for the person with the subject <paramref name="subject"/>.</summary>
    private static async Task<IResult> PersonActionAsync(
        string subject,
        string action,
        HttpContext http,
        UserService users,
        AccountMailService accounts,
        SessionService sessions,
        TokenRevoker revoker,
        AuthService auth,
        TwoFactorService twoFactor,
        PasskeyService passkeys,
        ActivityService activity,
        SystemConfigService config,
        IConfiguration configuration,
        CancellationToken ct)
    {
        var options = MatApiDefinition.Json;
        if (await users.GetBySubjectAsync(subject, ct) is not { } user)
        {
            return Results.Json(new { errors = new Dictionary<string, string> { ["subject"] = $"There is no person \"{subject}\"." } }, options, statusCode: StatusCodes.Status404NotFound);
        }

        // The person who acted, when a broker names them (as SCIM does), else the caller.
        var actor = http.Request.Headers[ScimEndpoints.ActorHeader].ToString() is { Length: > 0 } sub && await users.GetBySubjectAsync(sub.Trim(), ct) is { } person
            ? person.Username
            : http.Items[ApiAccess.CallerKey] as string;
        var ip = http.Connection.RemoteIpAddress?.ToString();
        var linkBase = await Support.Authority.GetAsync(http, config, configuration);

        (bool Ok, string Message)? result = action switch
        {
            "invite" => await accounts.InviteAsync(user, linkBase, actor, ct) is { } error
                ? (false, "The invitation was not sent. " + error)
                : (true, $"The invitation is on its way to {user.Email}."),
            "resetPassword" => string.IsNullOrEmpty(user.Email)
                ? (false, "The person has no e-mail address.")
                : await accounts.RequestPasswordResetAsync(user.Username, linkBase, ct: ct) is not null
                    ? (true, $"A link for a new password is on its way to {user.Email}.")
                    : (false, $"No link was sent: the account is disabled, or it got {AccountMailService.MaxResetsPerHour} links in the last hour."),
            "signOut" => (true, $"Signed out everywhere ({await sessions.InvalidateAllAsync(user.Id, ct: ct)} sessions, {await revoker.RevokeForSubjectAsync(user.Subject, ct)} app sign-ins)."),
            "unlock" => await UnlockAsync(auth, user, ct),
            "resetSecondStep" => await ResetSecondStepAsync(twoFactor, passkeys, user, ct),
            _ => null,
        };

        if (result is not { } done)
        {
            return Results.Json(new { errors = new Dictionary<string, string> { ["action"] = $"There is no action \"{action}\"." } }, options, statusCode: StatusCodes.Status404NotFound);
        }

        if (done.Ok)
        {
            var kind = action switch
            {
                "invite" => ActivityKind.InvitationSent,
                "resetPassword" => ActivityKind.PasswordResetSent,
                "resetSecondStep" => ActivityKind.SecondStepReset,
                _ => ActivityKind.PersonChanged,
            };
            await activity.WriteAsync(kind, username: actor, ipAddress: ip, detail: $"{user.Username}: {action} (API)", ct: ct);
        }

        return Results.Json(new { ok = done.Ok, message = done.Message }, options, statusCode: done.Ok ? StatusCodes.Status200OK : StatusCodes.Status409Conflict);

        static async Task<(bool, string)> UnlockAsync(AuthService auth, User user, CancellationToken ct)
        {
            await auth.ClearFailuresAsync(user.Id, ct);
            return (true, $"{user.DisplayName} can sign in again.");
        }

        static async Task<(bool, string)> ResetSecondStepAsync(TwoFactorService twoFactor, PasskeyService passkeys, User user, CancellationToken ct)
        {
            await twoFactor.DisableAsync(user.Id, ct);
            var removed = await passkeys.DeleteAllAsync(user.Id, ct);
            return (true, $"The second step is reset (authenticator app off, {removed} passkeys removed).");
        }
    }

    /// <summary>The body of a PUT: every field is optional; what is missing keeps its value (or the default for a new app).</summary>
    public sealed record ClientBody(
        string? DisplayName,
        string? HomeUrl,
        IReadOnlyList<string>? RedirectUris,
        IReadOnlyList<string>? PostLogoutRedirectUris,
        bool? AllowSignIn,
        bool? AllowMachine,
        bool? IsPublic,
        string? ManagedBy,
        bool? RenewSecret,
        string? RoleMode,
        IReadOnlyList<RoleBody>? Roles,
        bool? OpenToEveryone,
        bool? CallsAllApps,
        IReadOnlyList<string>? CallTargets = null,
        string? BackchannelLogoutUri = null,
        IReadOnlyList<PermissionBody>? Permissions = null,
        IReadOnlyList<QuotaBody>? Quotas = null,
        bool? SendsGroups = null,
        JsonElement Branding = default);

    public sealed record RoleBody(string? Key, string? Label);

    public sealed record PermissionBody(string? Key, string? Label, string? Hint = null, IReadOnlyList<string>? Roles = null);

    public sealed record QuotaBody(string? Key, string? Label, string? Unit, string? Period = null, long? Min = null, long? Max = null, string? Hint = null);
}
