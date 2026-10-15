using System.Security.Cryptography;
using System.Text.Json;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace MatIdentity.Core.Clients;

/// <summary>
/// The apps (OpenID Connect clients) of MatIdentity: list, create, change, renew the secret, remove. Stores them through OpenIddict and keeps,
/// for every app, its scope <c>app:&lt;id&gt;</c> whose audience is the app, so another app can ask for a token to call it (docs/PLATFORM.md,
/// "Apps talking to each other"). An app that may call others gets the scopes of all apps, also of those added later.
/// </summary>
public sealed class ClientService
{
    // Our own values in the properties of an OpenIddict application.
    private const string HomeProperty = "mat_home";
    private const string ManagedByProperty = "mat_managed_by";

    private readonly IOpenIddictApplicationManager _applications;
    private readonly IOpenIddictScopeManager _scopes;

    public ClientService(IOpenIddictApplicationManager applications, IOpenIddictScopeManager scopes)
    {
        _applications = applications;
        _scopes = scopes;
    }

    public async Task<List<ClientInfo>> GetAllAsync(CancellationToken ct = default)
    {
        var list = new List<ClientInfo>();
        await foreach (var app in _applications.ListAsync(count: null, offset: null, ct))
        {
            list.Add(await ToInfoAsync(app, ct));
        }

        return list.OrderBy(c => c.DisplayName, StringComparer.OrdinalIgnoreCase).ToList();
    }

    public async Task<ClientInfo?> GetAsync(string clientId, CancellationToken ct = default)
        => await _applications.FindByClientIdAsync(clientId, ct) is { } app ? await ToInfoAsync(app, ct) : null;

    public async Task<int> CountAsync(CancellationToken ct = default) => (int)await _applications.CountAsync(ct);

    /// <summary>
    /// Creates the app or changes it (by its client id). A new confidential app gets a secret, which is returned once; a change keeps the
    /// secret unless <paramref name="renewSecret"/> is set. The id of an existing app never changes.
    /// </summary>
    public async Task<ClientSaveResult> SaveAsync(ClientInfo input, bool renewSecret = false, CancellationToken ct = default)
    {
        var client = Normalize(input);
        var errors = ClientRules.Validate(client);
        if (errors.Count > 0)
        {
            return new ClientSaveResult(null, null, errors);
        }

        var existing = await _applications.FindByClientIdAsync(client.ClientId, ct);
        var descriptor = new OpenIddictApplicationDescriptor();
        if (existing is not null)
        {
            await _applications.PopulateAsync(descriptor, existing, ct);
            if (descriptor.ClientType == ClientTypes.Public != client.IsPublic)
            {
                return new ClientSaveResult(null, null, new Dictionary<string, string> { ["isPublic"] = "An app cannot change between public and with a secret; remove it and add it again." });
            }
        }

        await EnsureAppScopeAsync(client.ClientId, client.DisplayName, ct);

        string? secret = null;
        if (!client.IsPublic && (existing is null || renewSecret))
        {
            secret = NewSecret();
            descriptor.ClientSecret = secret;
        }

        descriptor.ClientId = client.ClientId;
        descriptor.DisplayName = client.DisplayName;
        descriptor.ClientType = client.IsPublic ? ClientTypes.Public : ClientTypes.Confidential;
        // The apps belong to the family: no consent screen, the person signed in at MatIdentity is signed in to the app.
        descriptor.ConsentType = ConsentTypes.Implicit;

        descriptor.RedirectUris.Clear();
        foreach (var uri in client.RedirectUris)
        {
            descriptor.RedirectUris.Add(new Uri(uri));
        }

        descriptor.PostLogoutRedirectUris.Clear();
        foreach (var uri in client.PostLogoutRedirectUris)
        {
            descriptor.PostLogoutRedirectUris.Add(new Uri(uri));
        }

        descriptor.Permissions.Clear();
        descriptor.Requirements.Clear();
        if (client.AllowSignIn)
        {
            descriptor.Permissions.UnionWith(
            [
                Permissions.Endpoints.Authorization,
                Permissions.Endpoints.Token,
                Permissions.Endpoints.EndSession,
                Permissions.GrantTypes.AuthorizationCode,
                Permissions.GrantTypes.RefreshToken,
                Permissions.ResponseTypes.Code,
                Permissions.Scopes.Email,
                Permissions.Scopes.Profile,
                Permissions.Scopes.Roles,
            ]);
            descriptor.Requirements.Add(Requirements.Features.ProofKeyForCodeExchange);
        }

        if (client.AllowMachine)
        {
            descriptor.Permissions.Add(Permissions.Endpoints.Token);
            descriptor.Permissions.Add(Permissions.GrantTypes.ClientCredentials);
            foreach (var scope in await AppScopeNamesAsync(ct))
            {
                descriptor.Permissions.Add(Permissions.Prefixes.Scope + scope);
            }
        }

        if (!client.IsPublic)
        {
            descriptor.Permissions.Add(Permissions.Endpoints.Introspection);
            descriptor.Permissions.Add(Permissions.Endpoints.Revocation);
        }

        descriptor.Properties.Remove(HomeProperty);
        descriptor.Properties.Remove(ManagedByProperty);
        if (!string.IsNullOrWhiteSpace(client.HomeUrl))
        {
            descriptor.Properties[HomeProperty] = JsonSerializer.SerializeToElement(client.HomeUrl);
        }

        if (!string.IsNullOrWhiteSpace(client.ManagedBy))
        {
            descriptor.Properties[ManagedByProperty] = JsonSerializer.SerializeToElement(client.ManagedBy);
        }

        if (existing is null)
        {
            await _applications.CreateAsync(descriptor, ct);
            // Every app that may call other apps may call this new one too.
            await GrantNewScopeToMachinesAsync(ClientRules.AppScope(client.ClientId), ct);
        }
        else
        {
            await _applications.UpdateAsync(existing, descriptor, ct);
        }

        return new ClientSaveResult(await GetAsync(client.ClientId, ct), secret, new Dictionary<string, string>());
    }

    /// <summary>Makes a new secret for a confidential app (the old one stops working at once). Null for an unknown or public app.</summary>
    public async Task<string?> RenewSecretAsync(string clientId, CancellationToken ct = default)
    {
        var app = await _applications.FindByClientIdAsync(clientId, ct);
        if (app is null || await _applications.GetClientTypeAsync(app, ct) == ClientTypes.Public)
        {
            return null;
        }

        var descriptor = new OpenIddictApplicationDescriptor();
        await _applications.PopulateAsync(descriptor, app, ct);
        var secret = NewSecret();
        descriptor.ClientSecret = secret;
        await _applications.UpdateAsync(app, descriptor, ct);
        return secret;
    }

    /// <summary>Removes the app and its scope (its tokens stop working). False when it does not exist.</summary>
    public async Task<bool> DeleteAsync(string clientId, CancellationToken ct = default)
    {
        var app = await _applications.FindByClientIdAsync(clientId, ct);
        if (app is null)
        {
            return false;
        }

        await _applications.DeleteAsync(app, ct);
        if (await _scopes.FindByNameAsync(ClientRules.AppScope(clientId), ct) is { } scope)
        {
            await _scopes.DeleteAsync(scope, ct);
        }

        return true;
    }

    /// <summary>The scope <c>app:&lt;id&gt;</c> of an app: a token for it carries the audience <c>&lt;id&gt;</c>.</summary>
    public async Task EnsureAppScopeAsync(string clientId, string displayName, CancellationToken ct = default)
    {
        var name = ClientRules.AppScope(clientId);
        if (await _scopes.FindByNameAsync(name, ct) is not null)
        {
            return;
        }

        var descriptor = new OpenIddictScopeDescriptor
        {
            Name = name,
            DisplayName = $"Call the API of {displayName}",
        };
        descriptor.Resources.Add(clientId);
        await _scopes.CreateAsync(descriptor, ct);
    }

    /// <summary>The names of the scopes of all apps (<c>app:*</c>).</summary>
    public async Task<List<string>> AppScopeNamesAsync(CancellationToken ct = default)
    {
        var names = new List<string>();
        await foreach (var scope in _scopes.ListAsync(count: null, offset: null, ct))
        {
            if (await _scopes.GetNameAsync(scope, ct) is { } name && name.StartsWith(ClientRules.AppScopePrefix, StringComparison.Ordinal))
            {
                names.Add(name);
            }
        }

        return names;
    }

    private async Task GrantNewScopeToMachinesAsync(string scope, CancellationToken ct)
    {
        var permission = Permissions.Prefixes.Scope + scope;
        var machines = new List<object>();
        await foreach (var app in _applications.ListAsync(count: null, offset: null, ct))
        {
            var permissions = await _applications.GetPermissionsAsync(app, ct);
            if (permissions.Contains(Permissions.GrantTypes.ClientCredentials) && !permissions.Contains(permission))
            {
                machines.Add(app);
            }
        }

        foreach (var app in machines)
        {
            var descriptor = new OpenIddictApplicationDescriptor();
            await _applications.PopulateAsync(descriptor, app, ct);
            descriptor.Permissions.Add(permission);
            await _applications.UpdateAsync(app, descriptor, ct);
        }
    }

    private async Task<ClientInfo> ToInfoAsync(object app, CancellationToken ct)
    {
        var permissions = await _applications.GetPermissionsAsync(app, ct);
        var properties = await _applications.GetPropertiesAsync(app, ct);
        return new ClientInfo
        {
            ClientId = await _applications.GetClientIdAsync(app, ct) ?? string.Empty,
            DisplayName = await _applications.GetDisplayNameAsync(app, ct) ?? string.Empty,
            IsPublic = await _applications.GetClientTypeAsync(app, ct) == ClientTypes.Public,
            AllowSignIn = permissions.Contains(Permissions.GrantTypes.AuthorizationCode),
            AllowMachine = permissions.Contains(Permissions.GrantTypes.ClientCredentials),
            RedirectUris = [.. await _applications.GetRedirectUrisAsync(app, ct)],
            PostLogoutRedirectUris = [.. await _applications.GetPostLogoutRedirectUrisAsync(app, ct)],
            HomeUrl = properties.TryGetValue(HomeProperty, out var home) && home.ValueKind == JsonValueKind.String ? home.GetString() : null,
            ManagedBy = properties.TryGetValue(ManagedByProperty, out var by) && by.ValueKind == JsonValueKind.String ? by.GetString() : null,
        };
    }

    private static ClientInfo Normalize(ClientInfo client) => client with
    {
        ClientId = client.ClientId?.Trim() ?? string.Empty,
        DisplayName = client.DisplayName?.Trim() ?? string.Empty,
        HomeUrl = string.IsNullOrWhiteSpace(client.HomeUrl) ? null : client.HomeUrl.Trim(),
        ManagedBy = string.IsNullOrWhiteSpace(client.ManagedBy) ? null : client.ManagedBy.Trim(),
        RedirectUris = client.RedirectUris.Select(u => u.Trim()).Where(u => u.Length > 0).Distinct(StringComparer.Ordinal).ToList(),
        PostLogoutRedirectUris = client.PostLogoutRedirectUris.Select(u => u.Trim()).Where(u => u.Length > 0).Distinct(StringComparer.Ordinal).ToList(),
    };

    /// <summary>A new secret: 32 random bytes, URL-safe Base64 (43 characters).</summary>
    public static string NewSecret()
        => Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
