using System.Net.Http.Json;
using MatIdentity.Core.Access;
using MatIdentity.Core.Clients;
using MatPlatform;

namespace MatIdentity.Web.Platform;

/// <summary>What an app announces it can give people: its roles (null: none usable), permissions and quotas (empty: none), or why it could not be read.</summary>
public sealed record AppCatalogRead(IReadOnlyList<RoleInfo>? Roles, IReadOnlyList<PermissionInfo> Permissions, IReadOnlyList<QuotaInfo> Quotas, string? Error)
{
    public bool Succeeded => Error is null;
}

/// <summary>
/// Reads the roles, permissions and quotas an app announces in its MatApiDefinition (<c>GET &lt;address&gt;/api</c>, fields <c>roles</c>, <c>permissions</c>,
/// <c>quotas</c>), so an administrator does not have to type them. Only on request of an administrator or of a binding of <c>identity.oidc</c>, only from the address
/// of the app, short timeout, nothing followed but the answer. It reads these fields and nothing else: a definition of any contract version will do (a consumer
/// ignores what it does not know; a definition without permissions or quotas has none).
/// </summary>
public sealed class AppRolesReader
{
    private readonly IHttpClientFactory _http;

    public AppRolesReader(IHttpClientFactory http)
    {
        _http = http;
    }

    /// <summary>The roles, or an error for a person.</summary>
    public Task<(IReadOnlyList<RoleInfo>? Roles, string? Error)> ReadAsync(ClientInfo app, CancellationToken ct)
        => ReadAsync(app.HomeUrl, ct);

    /// <summary>The roles of the app at <paramref name="address"/> (its root), or an error for a person.</summary>
    public async Task<(IReadOnlyList<RoleInfo>? Roles, string? Error)> ReadAsync(string? address, CancellationToken ct)
    {
        var read = await ReadCatalogAsync(address, ct);
        return !read.Succeeded ? (null, read.Error)
            : read.Roles is { Count: > 0 } roles ? (roles, null)
            : (null, $"{address?.Trim().TrimEnd('/')}/api names no roles (the field \"roles\" of the MatApiDefinition).");
    }

    /// <summary>The roles, permissions and quotas of the app.</summary>
    public Task<AppCatalogRead> ReadCatalogAsync(ClientInfo app, CancellationToken ct) => ReadCatalogAsync(app.HomeUrl, ct);

    /// <summary>The roles, permissions and quotas of the app at <paramref name="address"/> (its root), or an error for a person.</summary>
    public async Task<AppCatalogRead> ReadCatalogAsync(string? address, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(address) || !Uri.TryCreate(address.Trim().TrimEnd('/') + "/api", UriKind.Absolute, out var url) || url.Scheme is not ("http" or "https"))
        {
            return new AppCatalogRead(null, [], [], "The app has no address to ask.");
        }

        try
        {
            using var client = _http.CreateClient(nameof(AppRolesReader));
            client.Timeout = TimeSpan.FromSeconds(5);
            var definition = await client.GetFromJsonAsync<CatalogOnly>(url, MatApiDefinition.Json, ct);
            var roles = definition?.Roles?.Where(r => !string.IsNullOrWhiteSpace(r.Key)).Select(r => new RoleInfo(r.Key, string.IsNullOrWhiteSpace(r.Label) ? r.Key : r.Label)).ToList();
            var permissions = (definition?.Permissions ?? []).Where(p => !string.IsNullOrWhiteSpace(p.Key))
                .Select(p => new PermissionInfo(p.Key, string.IsNullOrWhiteSpace(p.Label) ? p.Key : p.Label, p.Hint, p.Roles)).ToList();
            var quotas = (definition?.Quotas ?? []).Where(q => !string.IsNullOrWhiteSpace(q.Key))
                .Select(q => new QuotaInfo(q.Key, string.IsNullOrWhiteSpace(q.Label) ? q.Key : q.Label, q.Unit, q.Period, q.Min, q.Max, q.Hint)).ToList();
            return new AppCatalogRead(roles is { Count: > 0 } ? roles : null, permissions, quotas, null);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or System.Text.Json.JsonException or NotSupportedException)
        {
            return new AppCatalogRead(null, [], [], $"{url} could not be read: {ex.Message}");
        }
    }

    private sealed record CatalogOnly(IReadOnlyList<MatRole>? Roles, IReadOnlyList<MatPermission>? Permissions, IReadOnlyList<MatQuota>? Quotas);
}
