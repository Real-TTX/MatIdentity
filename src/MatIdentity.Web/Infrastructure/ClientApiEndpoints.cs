using MatIdentity.Core.Activity;
using MatIdentity.Core.Clients;
using MatIdentity.Core.Entities;
using MatIdentity.Web.Platform;

namespace MatIdentity.Web.Infrastructure;

/// <summary>
/// The API Mattiverse uses to register an app when it installs it (docs/PLATFORM.md, "Sign-in with MatIdentity"): the same rules as the
/// pages, the same key or token as the rest of <c>/api</c>. Like the engines' APIs: an upsert by id, <c>managedBy</c> marks what a caller created,
/// and a caller only deletes what carries its own mark.
/// <code>
/// GET    /api/v1/clients                     the apps (never a secret)
/// GET    /api/v1/clients/{clientId}
/// PUT    /api/v1/clients/{clientId}          { displayName, homeUrl, redirectUris, postLogoutRedirectUris, allowSignIn, allowMachine, isPublic, managedBy, renewSecret }
///                                            200 { client, clientSecret? }: the secret only when it was made now (a new app, or renewSecret: true)
/// DELETE /api/v1/clients/{clientId}?managedBy=mattiverse   204, 404, or 409 when the app carries another mark
/// </code>
/// </summary>
public static class ClientApiEndpoints
{
    public static void MapClientApi(this WebApplication app)
    {
        var options = MatApiDefinition.Json;
        var api = app.MapGroup("/api/v1/clients").AllowAnonymous().AddEndpointFilter(ApiAccess.RequireAsync).DisableAntiforgery();

        api.MapGet("/", async (ClientService clients, CancellationToken ct) => Results.Json(await clients.GetAllAsync(ct), options));

        api.MapGet("/{clientId}", async (string clientId, ClientService clients, CancellationToken ct) =>
            await clients.GetAsync(clientId, ct) is { } client ? Results.Json(client, options) : NotFound(clientId));

        api.MapPut("/{clientId}", async (string clientId, ClientBody body, HttpContext http, ClientService clients, ActivityService activity, CancellationToken ct) =>
        {
            var existing = await clients.GetAsync(clientId, ct);
            var input = new ClientInfo
            {
                ClientId = clientId,
                DisplayName = body.DisplayName ?? existing?.DisplayName ?? clientId,
                HomeUrl = body.HomeUrl ?? existing?.HomeUrl,
                AllowSignIn = body.AllowSignIn ?? existing?.AllowSignIn ?? true,
                AllowMachine = body.AllowMachine ?? existing?.AllowMachine ?? false,
                IsPublic = body.IsPublic ?? existing?.IsPublic ?? false,
                RedirectUris = body.RedirectUris ?? existing?.RedirectUris ?? [],
                PostLogoutRedirectUris = body.PostLogoutRedirectUris ?? existing?.PostLogoutRedirectUris ?? [],
                ManagedBy = body.ManagedBy ?? existing?.ManagedBy,
            };

            var result = await clients.SaveAsync(input, body.RenewSecret == true, ct);
            if (!result.Succeeded)
            {
                return Results.Json(new { errors = result.Errors }, options, statusCode: StatusCodes.Status400BadRequest);
            }

            var caller = http.Items[ApiAccess.CallerKey] as string;
            await activity.WriteAsync(existing is null ? ActivityKind.ClientCreated : result.Secret is null ? ActivityKind.ClientChanged : ActivityKind.ClientSecretRenewed,
                username: caller, clientId: clientId, ipAddress: http.Connection.RemoteIpAddress?.ToString(), detail: "Through the API", ct: ct);
            return Results.Json(new { client = result.Client, clientSecret = result.Secret }, options);
        });

        api.MapDelete("/{clientId}", async (string clientId, string? managedBy, HttpContext http, ClientService clients, ActivityService activity, CancellationToken ct) =>
        {
            var existing = await clients.GetAsync(clientId, ct);
            if (existing is null)
            {
                return NotFound(clientId);
            }

            // Never delete what the caller did not create.
            if (!string.Equals(existing.ManagedBy, managedBy, StringComparison.Ordinal))
            {
                return Results.Json(new { errors = new Dictionary<string, string> { ["managedBy"] = "This app was not created by this caller." } }, options, statusCode: StatusCodes.Status409Conflict);
            }

            await clients.DeleteAsync(clientId, ct);
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
        bool? RenewSecret);
}
