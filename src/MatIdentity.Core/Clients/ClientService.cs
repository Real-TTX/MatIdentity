using System.Security.Cryptography;
using System.Text.Json;
using MatIdentity.Core.Access;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace MatIdentity.Core.Clients;

/// <summary>
/// The apps (OpenID Connect clients) of MatIdentity: list, create, change, renew the secret, remove. Stores them through OpenIddict and keeps,
/// for every app, its scope <c>app:&lt;id&gt;</c> whose audience is the app, so another app can ask for a token to call it (docs/PLATFORM.md,
/// "Apps talking to each other"). Which apps an app may call is its rule in <see cref="PermissionService"/>: all (also those added later) or the ones given to it.
/// </summary>
public sealed class ClientService
{
    // Our own values in the properties of an OpenIddict application.
    private const string HomeProperty = "mat_home";
    private const string ManagedByProperty = "mat_managed_by";
    private const string BackchannelProperty = "mat_backchannel_logout";

    private readonly IOpenIddictApplicationManager _applications;
    private readonly IOpenIddictScopeManager _scopes;
    private readonly PermissionService _permissions;

    public ClientService(IOpenIddictApplicationManager applications, IOpenIddictScopeManager scopes, PermissionService permissions)
    {
        _applications = applications;
        _scopes = scopes;
        _permissions = permissions;
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
            foreach (var scope in await MachineScopesAsync(client.ClientId, ct))
            {
                descriptor.Permissions.Add(Permissions.Prefixes.Scope + scope);
            }
        }

        // Every app may give its own tokens back (a public one too: it signs out without a secret); only an app with a secret may look into tokens.
        descriptor.Permissions.Add(Permissions.Endpoints.Revocation);
        if (!client.IsPublic)
        {
            descriptor.Permissions.Add(Permissions.Endpoints.Introspection);
        }

        descriptor.Properties.Remove(HomeProperty);
        descriptor.Properties.Remove(ManagedByProperty);
        descriptor.Properties.Remove(BackchannelProperty);
        if (!string.IsNullOrWhiteSpace(client.BackchannelLogoutUri))
        {
            descriptor.Properties[BackchannelProperty] = JsonSerializer.SerializeToElement(client.BackchannelLogoutUri);
        }

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
            // Every app that may call all apps may call this new one too.
            await SyncAllCallersAsync(ct);
        }
        else
        {
            await _applications.UpdateAsync(existing, descriptor, ct);
        }

        return new ClientSaveResult(await GetAsync(client.ClientId, ct), secret, new Dictionary<string, string>());
    }

    /// <summary>
    /// Creates or changes an app as a caller registers it (<see cref="ClientUpsert"/>): what is given, the rest kept. Its rules come first (saving the app writes the scopes
    /// it may ask for from them); the id and the roles are checked before anything is saved. The one way of <c>/api/v1/clients</c> and of the bindings of <c>identity.oidc</c>.
    /// </summary>
    public async Task<ClientUpsertResult> UpsertAsync(ClientUpsert upsert, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(upsert);
        var errors = CheckUpsert(upsert);
        if (errors.Count > 0)
        {
            return new ClientUpsertResult(new ClientSaveResult(null, null, errors), Created: false);
        }

        var clientId = upsert.ClientId;
        var existing = await GetAsync(clientId, ct);
        var policy = await _permissions.PolicyAsync(clientId, ct);
        await _permissions.SavePolicyAsync(clientId, upsert.RoleMode ?? policy.RoleMode, upsert.OpenToEveryone ?? policy.OpenToEveryone, upsert.CallsAllApps ?? policy.CallsAllApps, ct);
        if (upsert.Roles is not null)
        {
            await _permissions.SaveRolesAsync(clientId, upsert.Roles, ct);
        }

        if (upsert.Permissions is not null || upsert.Quotas is not null)
        {
            await _permissions.SaveCatalogAsync(clientId, upsert.Permissions, upsert.Quotas, ct);
        }

        // The apps it may call by name (also MatIdentity's own API, which "every app" leaves out).
        if (upsert.CallTargets is not null)
        {
            await _permissions.SetCallTargetsAsync(clientId, upsert.CallTargets.Where(ClientRules.IsValidClientId).Distinct(StringComparer.Ordinal), ct);
        }

        var saved = await SaveAsync(new ClientInfo
        {
            ClientId = clientId,
            DisplayName = upsert.DisplayName ?? existing?.DisplayName ?? clientId,
            HomeUrl = upsert.HomeUrl ?? existing?.HomeUrl,
            AllowSignIn = upsert.AllowSignIn ?? existing?.AllowSignIn ?? true,
            AllowMachine = upsert.AllowMachine ?? existing?.AllowMachine ?? false,
            IsPublic = upsert.IsPublic ?? existing?.IsPublic ?? false,
            RedirectUris = upsert.RedirectUris ?? existing?.RedirectUris ?? [],
            PostLogoutRedirectUris = upsert.PostLogoutRedirectUris ?? existing?.PostLogoutRedirectUris ?? [],
            BackchannelLogoutUri = upsert.BackchannelLogoutUri ?? existing?.BackchannelLogoutUri,
            ManagedBy = upsert.ManagedBy ?? existing?.ManagedBy,
        }, upsert.RenewSecret, ct);
        return new ClientUpsertResult(saved, Created: existing is null && saved.Succeeded);
    }

    /// <summary>What <see cref="UpsertAsync"/> checks before it saves anything: the id and the roles (the field, camelCase, and a message).</summary>
    public static Dictionary<string, string> CheckUpsert(ClientUpsert upsert)
    {
        ArgumentNullException.ThrowIfNull(upsert);
        var errors = upsert.Roles is null ? new Dictionary<string, string>() : PermissionService.ValidateRoles(upsert.Roles);
        foreach (var (key, message) in PermissionService.ValidateCatalog(upsert.Permissions, upsert.Quotas))
        {
            errors[key] = message;
        }

        if (!ClientRules.IsValidClientId(upsert.ClientId))
        {
            errors["clientId"] = "Use 2 to 63 small letters, digits, - or _, starting with a letter or digit.";
        }

        return errors;
    }

    /// <summary>
    /// Removes an app a caller registered, only when it carries the caller's mark: <paramref name="managedBy"/> "" stands for no mark (an app added under Apps), null for
    /// any mark. Never deletes what another caller created. The one way of <c>DELETE /api/v1/clients</c> and of the bindings of <c>identity.oidc</c>.
    /// </summary>
    public async Task<ClientRemoval> RemoveManagedAsync(string clientId, string? managedBy, CancellationToken ct = default)
    {
        var existing = await GetAsync(clientId, ct);
        if (existing is null)
        {
            return ClientRemoval.NotFound;
        }

        if (managedBy is not null && !string.Equals(existing.ManagedBy ?? string.Empty, managedBy, StringComparison.Ordinal))
        {
            return ClientRemoval.OtherMark;
        }

        await DeleteAsync(clientId, ct);
        return ClientRemoval.Removed;
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
        await _permissions.RemoveAppAsync(clientId, ct);
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

    /// <summary>
    /// The scopes an app may ask for with client credentials: of every app when it calls all, else of the apps given to it (and only those that exist).
    /// MatIdentity's own API (<c>app:matidentity</c>: the apps, their secrets, the settings) is never part of "all": it is given to an app by name only.
    /// </summary>
    public async Task<List<string>> MachineScopesAsync(string clientId, CancellationToken ct = default)
    {
        var all = await AppScopeNamesAsync(ct);
        var self = ClientRules.AppScope(ClientRules.SelfId);
        var wanted = (await _permissions.CallTargetsAsync(clientId, ct)).Select(ClientRules.AppScope).ToHashSet(StringComparer.Ordinal);
        var callsAll = (await _permissions.PolicyAsync(clientId, ct)).CallsAllApps;
        return all.Where(s => s == self ? wanted.Contains(s) : callsAll || wanted.Contains(s)).ToList();
    }

    /// <summary>Writes the scopes an app may ask for into its permissions again (after its call rules changed). Nothing for an app that calls no app.</summary>
    public async Task SyncCallScopesAsync(string clientId, CancellationToken ct = default)
    {
        var app = await _applications.FindByClientIdAsync(clientId, ct);
        if (app is null)
        {
            return;
        }

        var descriptor = new OpenIddictApplicationDescriptor();
        await _applications.PopulateAsync(descriptor, app, ct);
        descriptor.Permissions.RemoveWhere(p => p.StartsWith(Permissions.Prefixes.Scope + ClientRules.AppScopePrefix, StringComparison.Ordinal));
        if (descriptor.Permissions.Contains(Permissions.GrantTypes.ClientCredentials))
        {
            foreach (var scope in await MachineScopesAsync(clientId, ct))
            {
                descriptor.Permissions.Add(Permissions.Prefixes.Scope + scope);
            }
        }

        await _applications.UpdateAsync(app, descriptor, ct);
    }

    /// <summary>Brings the scopes of every app that calls all apps up to date (a new app was added, or at start after a change of the rule).</summary>
    public async Task SyncAllCallersAsync(CancellationToken ct = default)
    {
        var callers = new List<string>();
        await foreach (var app in _applications.ListAsync(count: null, offset: null, ct))
        {
            if (await _applications.GetClientIdAsync(app, ct) is { } id && (await _permissions.PolicyAsync(id, ct)).CallsAllApps)
            {
                callers.Add(id);
            }
        }

        foreach (var id in callers)
        {
            await SyncCallScopesAsync(id, ct);
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
            BackchannelLogoutUri = properties.TryGetValue(BackchannelProperty, out var back) && back.ValueKind == JsonValueKind.String ? back.GetString() : null,
        };
    }

    private static ClientInfo Normalize(ClientInfo client) => client with
    {
        ClientId = client.ClientId?.Trim() ?? string.Empty,
        DisplayName = client.DisplayName?.Trim() ?? string.Empty,
        HomeUrl = string.IsNullOrWhiteSpace(client.HomeUrl) ? null : client.HomeUrl.Trim(),
        ManagedBy = string.IsNullOrWhiteSpace(client.ManagedBy) ? null : client.ManagedBy.Trim(),
        BackchannelLogoutUri = string.IsNullOrWhiteSpace(client.BackchannelLogoutUri) ? null : client.BackchannelLogoutUri.Trim(),
        RedirectUris = client.RedirectUris.Select(u => u.Trim()).Where(u => u.Length > 0).Distinct(StringComparer.Ordinal).ToList(),
        PostLogoutRedirectUris = client.PostLogoutRedirectUris.Select(u => u.Trim()).Where(u => u.Length > 0).Distinct(StringComparer.Ordinal).ToList(),
    };

    /// <summary>A new secret: 32 random bytes, URL-safe Base64 (43 characters).</summary>
    public static string NewSecret()
        => Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
