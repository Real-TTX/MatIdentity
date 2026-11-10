using MatIdentity.Core.Clients;
using MatIdentity.Core.Data;
using MatIdentity.Core.Entities;
using Microsoft.EntityFrameworkCore;

namespace MatIdentity.Core.Access;

/// <summary>Who may sign in where, with which role, permissions and quotas (docs/ARCHITECTURE.md, "Permissions"; MatDesign docs/ACCESS.md).</summary>
/// <remarks>
/// The rules, in this order:
/// <list type="number">
/// <item>An administrator of MatIdentity may sign in to every app. Without a grant of their own they get the first (most powerful) role.</item>
/// <item>A person given to the app directly, or through one of their groups, may sign in. Their role: the one of their own grant, else the most powerful of their groups' grants, else the default role.</item>
/// <item>When the app is open to everyone, every active person may sign in, with the default role (the last, least powerful one).</item>
/// <item>Everyone else may not. A new app is open to nobody but the administrators.</item>
/// </list>
/// Permissions only add up: those the role brings, those of the person's own grant and those of every grant of their groups. A quota is the value of the person's own
/// grant, else the largest of their groups' grants (no limit beats every number), else none (the app's own setting). When the app decides the roles itself
/// (<see cref="RoleMode.App"/>) the token carries no role, no permissions and no quotas.
/// Every change that can change what a person ends up with goes through <see cref="WatchAsync"/>: the apps hear of the people whose values changed
/// (<see cref="IAccessChangeListener"/>), and their refresh tokens for those apps are revoked.
/// </remarks>
public sealed class PermissionService
{
    /// <summary>The roles of an app that has not said which it has.</summary>
    public static readonly IReadOnlyList<RoleInfo> DefaultRoles = [new("admin", "Administrator"), new("user", "User")];

    /// <summary>The most permissions and quotas an app may have.</summary>
    public const int MaxCatalog = 100;

    private readonly MatIdentityDbContext _db;
    private readonly IAccessChangeListener _listener;
    private readonly TokenRevoker? _revoker;

    public PermissionService(MatIdentityDbContext db, IAccessChangeListener? listener = null, TokenRevoker? revoker = null)
    {
        _db = db;
        _listener = listener ?? new NoAccessChangeListener();
        _revoker = revoker;
    }

    // ---- the rules of an app ---------------------------------------------------------------------------------------------------------

    /// <summary>The rules of an app (the defaults when it has none yet; not saved).</summary>
    public async Task<AppPolicy> PolicyAsync(string clientId, CancellationToken ct = default)
        => await _db.AppPolicies.AsNoTracking().FirstOrDefaultAsync(p => p.ClientId == clientId, ct) ?? new AppPolicy { ClientId = clientId };

    public Task SavePolicyAsync(string clientId, RoleMode roleMode, bool openToEveryone, bool callsAllApps, CancellationToken ct = default)
        => WatchAsync([clientId], null, async () =>
        {
            var policy = await _db.AppPolicies.FirstOrDefaultAsync(p => p.ClientId == clientId, ct);
            if (policy is null)
            {
                policy = new AppPolicy { ClientId = clientId };
                _db.AppPolicies.Add(policy);
            }

            policy.RoleMode = roleMode;
            policy.OpenToEveryone = openToEveryone;
            policy.CallsAllApps = callsAllApps;
            await _db.SaveChangesAsync(ct);
        }, ct);

    /// <summary>
    /// When the rules of each of these apps were written first, which is when the app was registered (the API, a binding and the page write them before the app);
    /// an app without rules is missing.
    /// </summary>
    public Task<Dictionary<string, DateTime>> RegisteredAsync(IReadOnlyCollection<string> clientIds, CancellationToken ct = default)
        => _db.AppPolicies.AsNoTracking()
            .Where(p => clientIds.Contains(p.ClientId))
            .GroupBy(p => p.ClientId)
            .Select(g => new { ClientId = g.Key, First = g.Min(p => p.CreateDate) })
            .ToDictionaryAsync(g => g.ClientId, g => g.First, ct);

    /// <summary>Every app that has rules (every registered app: the API, a binding and the page write them first).</summary>
    public Task<List<string>> ClientIdsAsync(CancellationToken ct = default)
        => _db.AppPolicies.AsNoTracking().Select(p => p.ClientId).Distinct().ToListAsync(ct);

    // ---- roles, permissions and quotas of an app ---------------------------------------------------------------------------------------

    /// <summary>The roles of an app, the most powerful first; <see cref="DefaultRoles"/> when it has none.</summary>
    public async Task<IReadOnlyList<RoleInfo>> RolesAsync(string clientId, CancellationToken ct = default)
    {
        var roles = await _db.AppRoles.AsNoTracking().Where(r => r.ClientId == clientId).OrderBy(r => r.SortOrder)
            .Select(r => new RoleInfo(r.Key, r.Label)).ToListAsync(ct);
        return roles.Count > 0 ? roles : DefaultRoles;
    }

    /// <summary>The permissions of an app, in its order.</summary>
    public async Task<IReadOnlyList<PermissionInfo>> PermissionsAsync(string clientId, CancellationToken ct = default)
        => (await _db.AppPermissions.AsNoTracking().Where(p => p.ClientId == clientId).OrderBy(p => p.SortOrder).ToListAsync(ct)).Select(ToInfo).ToList();

    /// <summary>The quotas of an app, in its order.</summary>
    public async Task<IReadOnlyList<QuotaInfo>> QuotasAsync(string clientId, CancellationToken ct = default)
        => (await _db.AppQuotas.AsNoTracking().Where(q => q.ClientId == clientId).OrderBy(q => q.SortOrder).ToListAsync(ct)).Select(ToInfo).ToList();

    /// <summary>Sets the roles of an app (in this order). A grant whose role no longer exists falls back to the default role.</summary>
    public async Task<Dictionary<string, string>> SaveRolesAsync(string clientId, IReadOnlyList<RoleInfo> roles, CancellationToken ct = default)
    {
        var errors = ValidateRoles(roles);
        if (errors.Count > 0)
        {
            return errors;
        }

        await WatchAsync([clientId], null, async () =>
        {
            _db.AppRoles.RemoveRange(await _db.AppRoles.Where(r => r.ClientId == clientId).ToListAsync(ct));
            await _db.SaveChangesAsync(ct);
            for (var i = 0; i < roles.Count; i++)
            {
                _db.AppRoles.Add(new AppRole { ClientId = clientId, Key = roles[i].Key.Trim(), Label = roles[i].Label.Trim(), SortOrder = i });
            }

            var keys = roles.Select(r => r.Key.Trim()).ToHashSet(StringComparer.Ordinal);
            foreach (var grant in await _db.AppGrants.Where(g => g.ClientId == clientId && g.RoleKey != null).ToListAsync(ct))
            {
                if (!keys.Contains(grant.RoleKey!))
                {
                    grant.RoleKey = null;
                }
            }

            await _db.SaveChangesAsync(ct);
        }, ct);
        return errors;
    }

    /// <summary>A role key is what goes into a token: small letters, digits, - and _; at most 30 roles, no key twice.</summary>
    public static Dictionary<string, string> ValidateRoles(IReadOnlyList<RoleInfo> roles)
    {
        var errors = new Dictionary<string, string>();
        if (roles.Count is 0 or > 30)
        {
            errors["roles"] = "Give the app between 1 and 30 roles.";
        }
        else if (roles.FirstOrDefault(r => !AccessKeys.IsKey(r.Key.Trim())) is { } bad)
        {
            errors["roles"] = $"\"{bad.Key}\" is no role key: small letters, digits, - and _.";
        }
        else if (roles.GroupBy(r => r.Key.Trim()).FirstOrDefault(g => g.Count() > 1) is { } twice)
        {
            errors["roles"] = $"The role \"{twice.Key}\" is there twice.";
        }
        else if (roles.Any(r => string.IsNullOrWhiteSpace(r.Label) || r.Label.Trim().Length > 100))
        {
            errors["roles"] = "Every role needs a name of up to 100 characters.";
        }

        return errors;
    }

    /// <summary>
    /// Sets the permissions and the quotas of an app (each list as a whole, in this order; null leaves it as it is). A grant keeps only the permissions and quotas
    /// that still exist. The roles a permission names that the app does not have are left out.
    /// </summary>
    public async Task<Dictionary<string, string>> SaveCatalogAsync(string clientId, IReadOnlyList<PermissionInfo>? permissions, IReadOnlyList<QuotaInfo>? quotas, CancellationToken ct = default)
    {
        var errors = ValidateCatalog(permissions, quotas);
        if (errors.Count > 0 || (permissions is null && quotas is null))
        {
            return errors;
        }

        var roles = (await RolesAsync(clientId, ct)).Select(r => r.Key).ToHashSet(StringComparer.Ordinal);
        await WatchAsync([clientId], null, async () =>
        {
            if (permissions is not null)
            {
                _db.AppPermissions.RemoveRange(await _db.AppPermissions.Where(p => p.ClientId == clientId).ToListAsync(ct));
                await _db.SaveChangesAsync(ct);
                for (var i = 0; i < permissions.Count; i++)
                {
                    var p = permissions[i];
                    var given = (p.Roles ?? []).Select(r => r.Trim()).Where(roles.Contains).Distinct(StringComparer.Ordinal).ToList();
                    _db.AppPermissions.Add(new AppPermission
                    {
                        ClientId = clientId, Key = p.Key.Trim(), Label = p.Label.Trim(), Hint = Trim(p.Hint, 300),
                        Roles = given.Count == 0 ? null : string.Join(' ', given), SortOrder = i,
                    });
                }
            }

            if (quotas is not null)
            {
                _db.AppQuotas.RemoveRange(await _db.AppQuotas.Where(q => q.ClientId == clientId).ToListAsync(ct));
                await _db.SaveChangesAsync(ct);
                for (var i = 0; i < quotas.Count; i++)
                {
                    var q = quotas[i];
                    _db.AppQuotas.Add(new AppQuota
                    {
                        ClientId = clientId, Key = q.Key.Trim(), Label = q.Label.Trim(), Unit = q.Unit, Period = q.Period, Min = q.Min, Max = q.Max,
                        Hint = Trim(q.Hint, 300), SortOrder = i,
                    });
                }
            }

            // What the grants give is held to what the app has now.
            var permissionKeys = (permissions?.Select(p => p.Key.Trim()) ?? await _db.AppPermissions.Where(p => p.ClientId == clientId).Select(p => p.Key).ToListAsync(ct))
                .ToHashSet(StringComparer.Ordinal);
            var quotaKeys = (quotas?.Select(q => q.Key.Trim()) ?? await _db.AppQuotas.Where(q => q.ClientId == clientId).Select(q => q.Key).ToListAsync(ct))
                .ToHashSet(StringComparer.Ordinal);
            foreach (var grant in await _db.AppGrants.Where(g => g.ClientId == clientId && (g.Permissions != null || g.Quotas != null)).ToListAsync(ct))
            {
                var values = GrantValues.Of(grant);
                var kept = new GrantValues(
                    [.. values.Permissions.Where(permissionKeys.Contains)],
                    values.Quotas.Where(q => quotaKeys.Contains(q.Key)).ToDictionary(q => q.Key, q => q.Value, StringComparer.Ordinal));
                grant.Permissions = kept.PermissionsText;
                grant.Quotas = kept.QuotasJson;
            }

            await _db.SaveChangesAsync(ct);
        }, ct);
        return errors;
    }

    /// <summary>The checks of the permissions and quotas of an app (the page, the API and a binding share them).</summary>
    public static Dictionary<string, string> ValidateCatalog(IReadOnlyList<PermissionInfo>? permissions, IReadOnlyList<QuotaInfo>? quotas)
    {
        var errors = new Dictionary<string, string>();
        if (permissions is not null)
        {
            if (permissions.Count > MaxCatalog)
            {
                errors["permissions"] = $"An app has at most {MaxCatalog} permissions.";
            }
            else if (permissions.FirstOrDefault(p => !AccessKeys.IsKey(p.Key?.Trim())) is { } bad)
            {
                errors["permissions"] = $"\"{bad.Key}\" is no permission key: small letters, digits, - and _.";
            }
            else if (permissions.GroupBy(p => p.Key.Trim()).FirstOrDefault(g => g.Count() > 1) is { } twice)
            {
                errors["permissions"] = $"The permission \"{twice.Key}\" is there twice.";
            }
            else if (permissions.Any(p => string.IsNullOrWhiteSpace(p.Label) || p.Label.Trim().Length > 100))
            {
                errors["permissions"] = "Every permission needs a name of up to 100 characters.";
            }
        }

        if (quotas is not null)
        {
            if (quotas.Count > MaxCatalog)
            {
                errors["quotas"] = $"An app has at most {MaxCatalog} quotas.";
            }
            else if (quotas.FirstOrDefault(q => !AccessKeys.IsKey(q.Key?.Trim())) is { } bad)
            {
                errors["quotas"] = $"\"{bad.Key}\" is no quota key: small letters, digits, - and _.";
            }
            else if (quotas.GroupBy(q => q.Key.Trim()).FirstOrDefault(g => g.Count() > 1) is { } twice)
            {
                errors["quotas"] = $"The quota \"{twice.Key}\" is there twice.";
            }
            else if (quotas.Any(q => string.IsNullOrWhiteSpace(q.Label) || q.Label.Trim().Length > 100))
            {
                errors["quotas"] = "Every quota needs a name of up to 100 characters.";
            }
            else if (quotas.FirstOrDefault(q => !AccessKeys.Units.Contains(q.Unit ?? string.Empty)) is { } unit)
            {
                errors["quotas"] = $"The quota \"{unit.Key}\" has the unit \"{unit.Unit}\": {string.Join(", ", AccessKeys.Units)}.";
            }
            else if (quotas.FirstOrDefault(q => q.Period is not null && !AccessKeys.Periods.Contains(q.Period)) is { } period)
            {
                errors["quotas"] = $"The quota \"{period.Key}\" has the period \"{period.Period}\": day, month or none.";
            }
            else if (quotas.FirstOrDefault(q => q.Min is < 0 || q.Max is < 0 || (q.Min is { } min && q.Max is { } max && min > max)) is { } limits)
            {
                errors["quotas"] = $"The quota \"{limits.Key}\" has limits that do not fit (from 0, min not above max).";
            }
        }

        return errors;
    }

    /// <summary>The checks of what a grant gives (the quotas within the limits of the app); the page, the API and SCIM share them.</summary>
    public static Dictionary<string, string> ValidateGrant(GrantValues values, IReadOnlyList<PermissionInfo> permissions, IReadOnlyList<QuotaInfo> quotas)
    {
        var errors = new Dictionary<string, string>();
        var known = permissions.Select(p => p.Key).ToHashSet(StringComparer.Ordinal);
        if (values.Permissions.FirstOrDefault(p => !known.Contains(p)) is { } unknown)
        {
            errors["permissions"] = $"The app has no permission \"{unknown}\".";
        }

        foreach (var (key, value) in values.Quotas)
        {
            if (quotas.FirstOrDefault(q => q.Key == key) is not { } quota)
            {
                errors["quotas." + key] = $"The app has no quota \"{key}\".";
            }
            else if (value is { } number && (number < (quota.Min ?? 0) || (quota.Max is { } max && number > max)))
            {
                errors["quotas." + key] = $"{quota.Label}: from {quota.Min ?? 0}" + (quota.Max is { } most ? $" to {most}." : ".");
            }
        }

        return errors;
    }

    // ---- grants ----------------------------------------------------------------------------------------------------------------------

    /// <summary>The grants of an app with the names of the people and groups, groups first.</summary>
    public async Task<List<AppGrant>> GrantsAsync(string clientId, CancellationToken ct = default)
    {
        var grants = await _db.AppGrants.AsNoTracking().Include(g => g.User).Include(g => g.Group)
            .Where(g => g.ClientId == clientId).ToListAsync(ct);
        // A grant of a deleted person or group is not shown (the query filters do not reach through the relation).
        return grants.Where(g => (g.User is { UpdateState: not UpdateState.Deleted }) || (g.Group is { UpdateState: not UpdateState.Deleted }))
            .OrderBy(g => g.GroupId is null).ThenBy(g => g.Group?.Name ?? g.User?.DisplayName, StringComparer.OrdinalIgnoreCase).ToList();
    }

    /// <summary>The grants given to a person or to a group directly, in every app.</summary>
    public Task<List<AppGrant>> GrantsOfAsync(long? userId, long? groupId, CancellationToken ct = default)
        => _db.AppGrants.AsNoTracking().Where(g => (userId != null && g.UserId == userId) || (groupId != null && g.GroupId == groupId)).ToListAsync(ct);

    /// <summary>Gives the app to a person or a group (or changes the role when they have it already); their permissions and quotas stay.</summary>
    public Task GrantAsync(string clientId, long? userId, long? groupId, string? roleKey, CancellationToken ct = default)
        => SaveGrantAsync(clientId, userId, groupId, roleKey, null, ct);

    /// <summary>
    /// Gives the app to a person or a group with a role and, unless <paramref name="values"/> is null, exactly these permissions and quotas (check them first with
    /// <see cref="ValidateGrant"/>).
    /// </summary>
    public Task SaveGrantAsync(string clientId, long? userId, long? groupId, string? roleKey, GrantValues? values, CancellationToken ct = default)
    {
        if ((userId is null) == (groupId is null))
        {
            throw new ArgumentException("Give the app either to a person or to a group.");
        }

        return WatchAsync([clientId], userId is { } user ? [user] : null, async () =>
        {
            var grant = await _db.AppGrants.FirstOrDefaultAsync(g => g.ClientId == clientId && g.UserId == userId && g.GroupId == groupId, ct);
            if (grant is null)
            {
                grant = new AppGrant { ClientId = clientId, UserId = userId, GroupId = groupId };
                _db.AppGrants.Add(grant);
            }

            grant.RoleKey = string.IsNullOrWhiteSpace(roleKey) ? null : roleKey;
            if (values is not null)
            {
                grant.Permissions = values.PermissionsText;
                grant.Quotas = values.QuotasJson;
            }

            await _db.SaveChangesAsync(ct);
        }, ct, groupId);
    }

    /// <summary>
    /// Sets the grants given directly to a person or a group to exactly <paramref name="grants"/> (app, role, values): what is not in the list is taken away.
    /// Returns the errors per app (nothing is saved then).
    /// </summary>
    public async Task<Dictionary<string, string>> ReplaceGrantsAsync(long? userId, long? groupId, IReadOnlyList<(string ClientId, string? Role, GrantValues Values)> grants, CancellationToken ct = default)
    {
        if ((userId is null) == (groupId is null))
        {
            throw new ArgumentException("Either a person or a group.");
        }

        var errors = await CheckGrantsAsync(grants, ct);
        if (errors.Count > 0)
        {
            return errors;
        }

        await WatchAsync(null, userId is { } user ? [user] : null, async () =>
        {
            var existing = await _db.AppGrants.Where(g => g.UserId == userId && g.GroupId == groupId).ToListAsync(ct);
            _db.AppGrants.RemoveRange(existing.Where(e => grants.All(g => g.ClientId != e.ClientId)));
            foreach (var (clientId, role, values) in grants)
            {
                var grant = existing.FirstOrDefault(e => e.ClientId == clientId);
                if (grant is null)
                {
                    grant = new AppGrant { ClientId = clientId, UserId = userId, GroupId = groupId };
                    _db.AppGrants.Add(grant);
                }

                grant.RoleKey = role;
                grant.Permissions = values.PermissionsText;
                grant.Quotas = values.QuotasJson;
            }

            await _db.SaveChangesAsync(ct);
        }, ct, groupId);
        return errors;
    }

    /// <summary>The checks of a list of grants (app, role, values) against the apps: a known app, its roles, its permissions, its quotas and their limits, no app twice.</summary>
    public async Task<Dictionary<string, string>> CheckGrantsAsync(IReadOnlyList<(string ClientId, string? Role, GrantValues Values)> grants, CancellationToken ct = default)
    {
        var errors = new Dictionary<string, string>();
        var known = (await ClientIdsAsync(ct)).ToHashSet(StringComparer.Ordinal);
        foreach (var (clientId, role, values) in grants)
        {
            if (!known.Contains(clientId))
            {
                errors[clientId] = $"There is no app \"{clientId}\".";
                continue;
            }

            var roles = await RolesAsync(clientId, ct);
            if (role is not null && roles.All(r => r.Key != role))
            {
                errors[clientId] = $"The app has no role \"{role}\".";
                continue;
            }

            foreach (var (_, message) in ValidateGrant(values, await PermissionsAsync(clientId, ct), await QuotasAsync(clientId, ct)))
            {
                errors[clientId] = message;
            }
        }

        if (grants.GroupBy(g => g.ClientId).FirstOrDefault(g => g.Count() > 1) is { } twice)
        {
            errors[twice.Key] = "The app is there twice.";
        }

        return errors;
    }

    public async Task<bool> RevokeAsync(long grantId, CancellationToken ct = default)
    {
        var grant = await _db.AppGrants.AsNoTracking().FirstOrDefaultAsync(g => g.Id == grantId, ct);
        if (grant is null)
        {
            return false;
        }

        await WatchAsync([grant.ClientId], grant.UserId is { } user ? [user] : null, async () =>
        {
            _db.AppGrants.Remove(await _db.AppGrants.FirstAsync(g => g.Id == grantId, ct));
            await _db.SaveChangesAsync(ct);
        }, ct, grant.GroupId);
        return true;
    }

    public Task<AppGrant?> FindGrantAsync(long grantId, CancellationToken ct = default) => _db.AppGrants.FirstOrDefaultAsync(g => g.Id == grantId, ct);

    // ---- calls between apps ----------------------------------------------------------------------------------------------------------

    /// <summary>The apps (client ids) another app may call, when it does not call all.</summary>
    public Task<List<string>> CallTargetsAsync(string callerClientId, CancellationToken ct = default)
        => _db.AppCallGrants.Where(c => c.CallerClientId == callerClientId).Select(c => c.TargetClientId).ToListAsync(ct);

    /// <summary>Sets which apps an app may call (exactly these).</summary>
    public async Task SetCallTargetsAsync(string callerClientId, IEnumerable<string> targets, CancellationToken ct = default)
    {
        var wanted = targets.ToHashSet(StringComparer.Ordinal);
        var existing = await _db.AppCallGrants.Where(c => c.CallerClientId == callerClientId).ToListAsync(ct);
        _db.AppCallGrants.RemoveRange(existing.Where(c => !wanted.Contains(c.TargetClientId)));
        foreach (var target in wanted.Except(existing.Select(c => c.TargetClientId)))
        {
            _db.AppCallGrants.Add(new AppCallGrant { CallerClientId = callerClientId, TargetClientId = target });
        }

        await _db.SaveChangesAsync(ct);
    }

    // ---- removal ---------------------------------------------------------------------------------------------------------------------

    /// <summary>Removes everything of an app (its rules, roles, permissions, quotas, grants and the calls from and to it), when the app is removed.</summary>
    public async Task RemoveAppAsync(string clientId, CancellationToken ct = default)
    {
        _db.AppPolicies.RemoveRange(await _db.AppPolicies.Where(p => p.ClientId == clientId).ToListAsync(ct));
        _db.AppRoles.RemoveRange(await _db.AppRoles.Where(r => r.ClientId == clientId).ToListAsync(ct));
        _db.AppPermissions.RemoveRange(await _db.AppPermissions.Where(p => p.ClientId == clientId).ToListAsync(ct));
        _db.AppQuotas.RemoveRange(await _db.AppQuotas.Where(q => q.ClientId == clientId).ToListAsync(ct));
        _db.AppGrants.RemoveRange(await _db.AppGrants.Where(g => g.ClientId == clientId).ToListAsync(ct));
        _db.AppCallGrants.RemoveRange(await _db.AppCallGrants.Where(c => c.CallerClientId == clientId || c.TargetClientId == clientId).ToListAsync(ct));
        await _db.SaveChangesAsync(ct);
    }

    /// <summary>Removes the memberships and grants of a person (when the person is deleted).</summary>
    public async Task RemoveUserAsync(long userId, CancellationToken ct = default)
    {
        _db.GroupMembers.RemoveRange(await _db.GroupMembers.Where(m => m.UserId == userId).ToListAsync(ct));
        _db.AppGrants.RemoveRange(await _db.AppGrants.Where(g => g.UserId == userId).ToListAsync(ct));
        await _db.SaveChangesAsync(ct);
    }

    // ---- the decision ----------------------------------------------------------------------------------------------------------------

    /// <summary>May <paramref name="user"/> sign in to the app, with which role, permissions and quotas (see the rules in the remarks of the class).</summary>
    public async Task<AccessDecision> DecideAsync(User user, string clientId, CancellationToken ct = default)
    {
        var data = await LoadAsync([clientId], [user.Id], ct);
        return Decide(user, clientId, data);
    }

    /// <summary>The apps (client ids) <paramref name="user"/> may sign in to, for the start page.</summary>
    public async Task<HashSet<string>> AllowedAppsAsync(User user, IEnumerable<string> clientIds, CancellationToken ct = default)
    {
        var clients = clientIds.Distinct(StringComparer.Ordinal).ToList();
        var data = await LoadAsync(clients, [user.Id], ct);
        return clients.Where(c => Decide(user, c, data).Allowed).ToHashSet(StringComparer.Ordinal);
    }

    /// <summary>What <paramref name="user"/> ends up with in each of <paramref name="clientIds"/> (only the apps they may use), for SCIM and the pages.</summary>
    public async Task<IReadOnlyList<(string ClientId, AccessDecision Decision)>> AccessOfAsync(User user, IReadOnlyCollection<string> clientIds, CancellationToken ct = default)
    {
        var data = await LoadAsync(clientIds, [user.Id], ct);
        return [.. clientIds.Select(c => (c, Decide(user, c, data))).Where(x => x.Item2.Allowed).OrderBy(x => x.c, StringComparer.Ordinal)];
    }

    /// <summary>What every one of <paramref name="users"/> ends up with in the app <paramref name="clientId"/> (SCIM for an app: its own people).</summary>
    public async Task<Dictionary<long, AccessDecision>> AccessToAsync(string clientId, IReadOnlyList<User> users, CancellationToken ct = default)
    {
        var data = await LoadAsync([clientId], [.. users.Select(u => u.Id)], ct);
        return users.ToDictionary(u => u.Id, u => Decide(u, clientId, data));
    }

    /// <summary>
    /// Runs <paramref name="change"/> and then tells the apps about every person whose access, role, permissions or quotas in one of <paramref name="clientIds"/>
    /// (null: every app) changed, among <paramref name="userIds"/> (null: everyone; with <paramref name="groupId"/> the members of that group are added): a
    /// back-channel logout to the app (<see cref="IAccessChangeListener"/>) and their refresh tokens for it revoked.
    /// </summary>
    public async Task WatchAsync(IReadOnlyCollection<string>? clientIds, IReadOnlyCollection<long>? userIds, Func<Task> change, CancellationToken ct, long? groupId = null)
    {
        var clients = clientIds ?? await ClientIdsAsync(ct);
        var users = userIds is null && groupId is null ? null : (userIds ?? []).ToHashSet();
        if (groupId is { } group)
        {
            users!.UnionWith(await _db.GroupMembers.Where(m => m.GroupId == group).Select(m => m.UserId).ToListAsync(ct));
        }

        var before = await SnapshotAsync(clients, users, ct);
        await change();
        if (groupId is { } again)
        {
            // Members added by the change count too.
            users!.UnionWith(await _db.GroupMembers.Where(m => m.GroupId == again).Select(m => m.UserId).ToListAsync(ct));
        }

        var after = await SnapshotAsync(clients, users, ct);
        // A person who is not in one of the two snapshots (made or deleted by the change) counts as "no access" there.
        var changes = before.Keys.Union(after.Keys)
            .Where(k => before.GetValueOrDefault(k, "-") != after.GetValueOrDefault(k, "-"))
            .Select(k => new AccessChange(k.Subject, k.ClientId))
            .ToList();
        if (changes.Count == 0)
        {
            return;
        }

        if (_revoker is not null)
        {
            foreach (var changed in changes)
            {
                await _revoker.RevokeForSubjectAndClientAsync(changed.Subject, changed.ClientId, ct);
            }
        }

        await _listener.AccessChangedAsync(changes, ct);
    }

    /// <summary>What every person (or <paramref name="userIds"/>) ends up with in each app: the signature of the decision per person and app.</summary>
    private async Task<Dictionary<(string Subject, string ClientId), string>> SnapshotAsync(IReadOnlyCollection<string> clients, IReadOnlyCollection<long>? userIds, CancellationToken ct)
    {
        var users = await _db.Users.AsNoTracking().Where(u => userIds == null || userIds.Contains(u.Id)).ToListAsync(ct);
        var data = await LoadAsync(clients, userIds is null ? null : [.. users.Select(u => u.Id)], ct);
        var snapshot = new Dictionary<(string, string), string>();
        foreach (var user in users)
        {
            foreach (var client in clients)
            {
                snapshot[(user.Subject, client)] = Decide(user, client, data).Signature;
            }
        }

        return snapshot;
    }

    /// <summary>Everything the decision needs for these apps and people, read at once.</summary>
    private async Task<AccessData> LoadAsync(IReadOnlyCollection<string> clients, IReadOnlyCollection<long>? userIds, CancellationToken ct)
    {
        var policies = await _db.AppPolicies.AsNoTracking().Where(p => clients.Contains(p.ClientId)).ToListAsync(ct);
        var roles = await _db.AppRoles.AsNoTracking().Where(r => clients.Contains(r.ClientId)).OrderBy(r => r.SortOrder).ToListAsync(ct);
        var permissions = await _db.AppPermissions.AsNoTracking().Where(p => clients.Contains(p.ClientId)).OrderBy(p => p.SortOrder).ToListAsync(ct);
        var quotas = await _db.AppQuotas.AsNoTracking().Where(q => clients.Contains(q.ClientId)).OrderBy(q => q.SortOrder).ToListAsync(ct);
        var members = await _db.GroupMembers.AsNoTracking().Where(m => userIds == null || userIds.Contains(m.UserId)).ToListAsync(ct);
        var groupNames = await _db.Groups.AsNoTracking().ToDictionaryAsync(g => g.Id, g => g.Name, ct);
        var grants = await _db.AppGrants.AsNoTracking().Where(g => clients.Contains(g.ClientId)).ToListAsync(ct);

        return new AccessData(
            policies.GroupBy(p => p.ClientId).ToDictionary(g => g.Key, g => g.First(), StringComparer.Ordinal),
            roles.GroupBy(r => r.ClientId).ToDictionary(g => g.Key, g => (IReadOnlyList<RoleInfo>)[.. g.Select(r => new RoleInfo(r.Key, r.Label))], StringComparer.Ordinal),
            permissions.GroupBy(p => p.ClientId).ToDictionary(g => g.Key, g => (IReadOnlyList<PermissionInfo>)[.. g.Select(ToInfo)], StringComparer.Ordinal),
            quotas.GroupBy(q => q.ClientId).ToDictionary(g => g.Key, g => (IReadOnlyList<QuotaInfo>)[.. g.Select(ToInfo)], StringComparer.Ordinal),
            members.Where(m => groupNames.ContainsKey(m.GroupId)).GroupBy(m => m.UserId).ToDictionary(g => g.Key, g => g.Select(m => m.GroupId).ToHashSet()),
            groupNames,
            grants.Where(g => g.GroupId is null || groupNames.ContainsKey(g.GroupId.Value)).GroupBy(g => g.ClientId).ToDictionary(g => g.Key, g => g.ToList(), StringComparer.Ordinal));
    }

    private static AccessDecision Decide(User user, string clientId, AccessData data)
    {
        if (!user.IsActive)
        {
            return new AccessDecision(false, null, "The account is disabled.");
        }

        var policy = data.Policies.GetValueOrDefault(clientId) ?? new AppPolicy { ClientId = clientId };
        var roles = data.Roles.GetValueOrDefault(clientId) is { Count: > 0 } named ? named : DefaultRoles;
        var groupIds = data.Memberships.GetValueOrDefault(user.Id) ?? [];
        var grants = data.Grants.GetValueOrDefault(clientId) ?? [];
        var mine = grants.FirstOrDefault(g => g.UserId == user.Id);
        var fromGroups = grants.Where(g => g.GroupId is { } id && groupIds.Contains(id)).ToList();
        var isAdmin = user.Role == UserRole.Admin;
        if (!isAdmin && mine is null && fromGroups.Count == 0 && !policy.OpenToEveryone)
        {
            return new AccessDecision(false, null, "This app was not given to you.");
        }

        var via = new List<string>();
        if (mine is not null)
        {
            via.Add("person");
        }

        via.AddRange(fromGroups.Select(g => "group:" + data.GroupNames.GetValueOrDefault(g.GroupId!.Value, "?")).Distinct(StringComparer.Ordinal));
        if (policy.OpenToEveryone)
        {
            via.Add("everyone");
        }

        if (isAdmin)
        {
            via.Add("administrator");
        }

        if (policy.RoleMode == RoleMode.App)
        {
            return new AccessDecision(true, null, "The app decides the role.") { Via = via };
        }

        var rank = roles.Select((r, i) => (r.Key, i)).ToDictionary(x => x.Key, x => x.i, StringComparer.Ordinal);
        string role;
        if (mine?.RoleKey is { } ownRole && rank.ContainsKey(ownRole))
        {
            role = ownRole;
        }
        else if (fromGroups.Where(g => g.RoleKey is not null && rank.ContainsKey(g.RoleKey)).MinBy(g => rank[g.RoleKey!]) is { } best)
        {
            role = best.RoleKey!;
        }
        else
        {
            // An administrator without a role of their own gets the most powerful one, everyone else the default (the least powerful).
            role = isAdmin && mine is null && fromGroups.Count == 0 ? roles[0].Key : roles[^1].Key;
        }

        // Permissions only add up: the role's, the person's own, every group's; only those the app has, in its order.
        var catalog = data.Permissions.GetValueOrDefault(clientId) ?? [];
        var given = new HashSet<string>(StringComparer.Ordinal);
        foreach (var grant in fromGroups.Prepend(mine).OfType<AppGrant>())
        {
            given.UnionWith(GrantValues.Of(grant).Permissions);
        }

        var permissions = catalog.Where(p => given.Contains(p.Key) || (p.Roles ?? []).Contains(role, StringComparer.Ordinal)).Select(p => p.Key).ToList();

        // A quota: the person's own value, else the largest of the groups (no limit beats every number), else none (the app's own setting).
        var quotas = new Dictionary<string, long?>(StringComparer.Ordinal);
        var own = mine is null ? GrantValues.None : GrantValues.Of(mine);
        var groupValues = fromGroups.Select(GrantValues.Of).ToList();
        foreach (var quota in data.Quotas.GetValueOrDefault(clientId) ?? [])
        {
            if (own.Quotas.TryGetValue(quota.Key, out var value))
            {
                quotas[quota.Key] = value;
            }
            else if (groupValues.Where(v => v.Quotas.ContainsKey(quota.Key)).Select(v => v.Quotas[quota.Key]).ToList() is { Count: > 0 } values)
            {
                quotas[quota.Key] = values.Any(v => v is null) ? null : values.Max();
            }
        }

        return new AccessDecision(true, role, "Allowed.") { Permissions = permissions, Quotas = quotas, Via = via };
    }

    private static PermissionInfo ToInfo(AppPermission p)
        => new(p.Key, p.Label, p.Hint, (p.Roles ?? string.Empty).Split(' ', StringSplitOptions.RemoveEmptyEntries));

    private static QuotaInfo ToInfo(AppQuota q) => new(q.Key, q.Label, q.Unit, q.Period, q.Min, q.Max, q.Hint);

    private static string? Trim(string? value, int max)
        => string.IsNullOrWhiteSpace(value) ? null : value.Trim().Length > max ? value.Trim()[..max] : value.Trim();

    /// <summary>What the decision reads, for a set of apps and people.</summary>
    private sealed record AccessData(
        Dictionary<string, AppPolicy> Policies,
        Dictionary<string, IReadOnlyList<RoleInfo>> Roles,
        Dictionary<string, IReadOnlyList<PermissionInfo>> Permissions,
        Dictionary<string, IReadOnlyList<QuotaInfo>> Quotas,
        Dictionary<long, HashSet<long>> Memberships,
        Dictionary<long, string> GroupNames,
        Dictionary<string, List<AppGrant>> Grants);
}
