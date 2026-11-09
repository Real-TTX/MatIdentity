using MatIdentity.Core.Access;
using MatIdentity.Core.Activity;
using MatIdentity.Core.Clients;
using MatIdentity.Core.Entities;
using MatPlatform;

namespace MatIdentity.Web.Infrastructure;

/// <summary>
/// The API of the apps (docs/PLATFORM.md, "Sign-in with MatIdentity"): Mattiverse registers itself here (client <c>mattiverse</c>, calls every app); the apps it installs are
/// bound through <c>/api/bindings/identity.oidc/...</c> (<see cref="Platform.IdentityBindings"/>), which goes the same way (<see cref="ClientService.UpsertAsync"/>,
/// <see cref="ClientService.RemoveManagedAsync"/>). The same rules as the pages, the same key or token as the rest of <c>/api</c>. Like the engines' APIs: an upsert by id,
/// <c>managedBy</c> marks what a caller created, and a caller only deletes what carries its own mark.
/// <code>
/// GET    /api/v1/status                      { ok, app, version, apiVersion: 1 } (as the engines of Mattiverse answer it)
/// GET    /api/v1/clients                     the apps (never a secret)
/// GET    /api/v1/clients/{clientId}
/// PUT    /api/v1/clients/{clientId}          { displayName, homeUrl, redirectUris, postLogoutRedirectUris, allowSignIn, allowMachine, isPublic, managedBy, renewSecret,
///                                              roleMode: "matidentity" or "app", roles: [{ key, label }], openToEveryone, callsAllApps,
///                                              callTargets: ["matsplit", "matidentity"] (by name; MatIdentity's own API only so),
///                                              backchannelLogoutUri: where the app hears that a person signed out ("" removes it) }
///                                            200 { client, clientSecret? }: the secret only when it was made now (a new app, or renewSecret: true)
/// DELETE /api/v1/clients/{clientId}?managedBy=mattiverse   204, 404, or 409 when the app carries another mark
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

        api.MapGet("/", async (ClientService clients, CancellationToken ct) => Results.Json(await clients.GetAllAsync(ct), options));

        api.MapGet("/{clientId}", async (string clientId, ClientService clients, CancellationToken ct) =>
            await clients.GetAsync(clientId, ct) is { } client ? Results.Json(client, options) : NotFound(clientId));

        api.MapPut("/{clientId}", async (string clientId, ClientBody body, HttpContext http, ClientService clients, PermissionService permissions, ActivityService activity, CancellationToken ct) =>
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
                OpenToEveryone = body.OpenToEveryone,
                CallsAllApps = body.CallsAllApps,
                CallTargets = body.CallTargets,
            };

            if (body.RoleMode is not null && roleMode is null)
            {
                var errors = ClientService.CheckUpsert(upsert);
                errors["roleMode"] = "Use \"matidentity\" or \"app\".";
                return Results.Json(new { errors }, options, statusCode: StatusCodes.Status400BadRequest);
            }

            var (result, created) = await clients.UpsertAsync(upsert, ct);
            if (!result.Succeeded)
            {
                return Results.Json(new { errors = result.Errors }, options, statusCode: StatusCodes.Status400BadRequest);
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
                saved.OpenToEveryone,
                saved.CallsAllApps,
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
        string? BackchannelLogoutUri = null);

    public sealed record RoleBody(string? Key, string? Label);
}
