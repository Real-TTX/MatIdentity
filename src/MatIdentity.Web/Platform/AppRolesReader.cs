using System.Net.Http.Json;
using MatIdentity.Core.Access;
using MatIdentity.Core.Clients;

namespace MatIdentity.Web.Platform;

/// <summary>
/// Reads the roles an app announces in its MatApiDefinition (<c>GET &lt;address&gt;/api</c>, field <c>roles</c>), so an administrator does not have to type them.
/// Only on request of an administrator, only from the address of the app, short timeout, nothing followed but the answer.
/// </summary>
public sealed class AppRolesReader
{
    private readonly IHttpClientFactory _http;

    public AppRolesReader(IHttpClientFactory http)
    {
        _http = http;
    }

    /// <summary>The roles, or an error for a person.</summary>
    public async Task<(IReadOnlyList<RoleInfo>? Roles, string? Error)> ReadAsync(ClientInfo app, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(app.HomeUrl) || !Uri.TryCreate(app.HomeUrl.TrimEnd('/') + "/api", UriKind.Absolute, out var url))
        {
            return (null, "The app has no address to ask.");
        }

        try
        {
            using var client = _http.CreateClient(nameof(AppRolesReader));
            client.Timeout = TimeSpan.FromSeconds(5);
            var definition = await client.GetFromJsonAsync<RolesOnly>(url, MatApiDefinition.Json, ct);
            var roles = definition?.Roles?.Where(r => !string.IsNullOrWhiteSpace(r.Key)).Select(r => new RoleInfo(r.Key, string.IsNullOrWhiteSpace(r.Label) ? r.Key : r.Label)).ToList();
            return roles is { Count: > 0 } ? (roles, null) : (null, $"{url} names no roles (the field \"roles\" of the MatApiDefinition).");
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or System.Text.Json.JsonException or NotSupportedException)
        {
            return (null, $"{url} could not be read: {ex.Message}");
        }
    }

    private sealed record RolesOnly(IReadOnlyList<MatRole>? Roles);
}
