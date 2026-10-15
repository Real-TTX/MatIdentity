using MatIdentity.Core.Data;
using MatIdentity.Core.Entities;
using Microsoft.EntityFrameworkCore;

namespace MatIdentity.Core.Access;

/// <summary>What an app's rules say for one person.</summary>
/// <param name="Allowed">The person may sign in to the app.</param>
/// <param name="Role">The role of the app for the token (claim <c>role</c>); null when the app decides the roles itself.</param>
/// <param name="Reason">For a person: why (shown on the page that says no, and in the activity list).</param>
public sealed record AccessDecision(bool Allowed, string? Role, string Reason);

/// <summary>A role of an app as the pages and the API see it.</summary>
public sealed record RoleInfo(string Key, string Label);

/// <summary>Who may sign in where, with which role (docs/ARCHITECTURE.md, "Permissions").</summary>
/// <remarks>
/// The rules, in this order:
/// <list type="number">
/// <item>An administrator of MatIdentity may sign in to every app. Without a grant of their own they get the first (most powerful) role.</item>
/// <item>A person given to the app directly, or through one of their groups, may sign in. Their role: the one of their own grant, else the most powerful of their groups' grants, else the default role.</item>
/// <item>When the app is open to everyone, every active person may sign in, with the default role (the last, least powerful one).</item>
/// <item>Everyone else may not. A new app is open to nobody but the administrators.</item>
/// </list>
/// When the app decides the roles itself (<see cref="RoleMode.App"/>) the token carries no role.
/// </remarks>
public sealed class PermissionService
{
    /// <summary>The roles of an app that has not said which it has.</summary>
    public static readonly IReadOnlyList<RoleInfo> DefaultRoles = [new("admin", "Administrator"), new("user", "User")];

    private readonly MatIdentityDbContext _db;

    public PermissionService(MatIdentityDbContext db)
    {
        _db = db;
    }

    /// <summary>The rules of an app (the defaults when it has none yet; not saved).</summary>
    public async Task<AppPolicy> PolicyAsync(string clientId, CancellationToken ct = default)
        => await _db.AppPolicies.AsNoTracking().FirstOrDefaultAsync(p => p.ClientId == clientId, ct) ?? new AppPolicy { ClientId = clientId };

    public async Task SavePolicyAsync(string clientId, RoleMode roleMode, bool openToEveryone, bool callsAllApps, CancellationToken ct = default)
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
    }

    /// <summary>The roles of an app, the most powerful first; <see cref="DefaultRoles"/> when it has none.</summary>
    public async Task<IReadOnlyList<RoleInfo>> RolesAsync(string clientId, CancellationToken ct = default)
    {
        var roles = await _db.AppRoles.AsNoTracking().Where(r => r.ClientId == clientId).OrderBy(r => r.SortOrder)
            .Select(r => new RoleInfo(r.Key, r.Label)).ToListAsync(ct);
        return roles.Count > 0 ? roles : DefaultRoles;
    }

    /// <summary>Sets the roles of an app (in this order). A grant whose role no longer exists falls back to the default role.</summary>
    public async Task<Dictionary<string, string>> SaveRolesAsync(string clientId, IReadOnlyList<RoleInfo> roles, CancellationToken ct = default)
    {
        var errors = ValidateRoles(roles);
        if (errors.Count > 0)
        {
            return errors;
        }

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
        else if (roles.FirstOrDefault(r => !System.Text.RegularExpressions.Regex.IsMatch(r.Key.Trim(), "^[a-z0-9][a-z0-9_-]{0,63}$")) is { } bad)
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

    /// <summary>The grants of an app with the names of the people and groups, groups first.</summary>
    public async Task<List<AppGrant>> GrantsAsync(string clientId, CancellationToken ct = default)
    {
        var grants = await _db.AppGrants.AsNoTracking().Include(g => g.User).Include(g => g.Group)
            .Where(g => g.ClientId == clientId).ToListAsync(ct);
        // A grant of a deleted person or group is not shown (the query filters do not reach through the relation).
        return grants.Where(g => (g.User is { UpdateState: not UpdateState.Deleted }) || (g.Group is { UpdateState: not UpdateState.Deleted }))
            .OrderBy(g => g.GroupId is null).ThenBy(g => g.Group?.Name ?? g.User?.DisplayName, StringComparer.OrdinalIgnoreCase).ToList();
    }

    /// <summary>Gives the app to a person or a group (or changes the role when they have it already).</summary>
    public async Task GrantAsync(string clientId, long? userId, long? groupId, string? roleKey, CancellationToken ct = default)
    {
        if ((userId is null) == (groupId is null))
        {
            throw new ArgumentException("Give the app either to a person or to a group.");
        }

        var grant = await _db.AppGrants.FirstOrDefaultAsync(g => g.ClientId == clientId && g.UserId == userId && g.GroupId == groupId, ct);
        if (grant is null)
        {
            grant = new AppGrant { ClientId = clientId, UserId = userId, GroupId = groupId };
            _db.AppGrants.Add(grant);
        }

        grant.RoleKey = string.IsNullOrWhiteSpace(roleKey) ? null : roleKey;
        await _db.SaveChangesAsync(ct);
    }

    public async Task<bool> RevokeAsync(long grantId, CancellationToken ct = default)
    {
        var grant = await _db.AppGrants.FirstOrDefaultAsync(g => g.Id == grantId, ct);
        if (grant is null)
        {
            return false;
        }

        _db.AppGrants.Remove(grant);
        await _db.SaveChangesAsync(ct);
        return true;
    }

    public Task<AppGrant?> FindGrantAsync(long grantId, CancellationToken ct = default) => _db.AppGrants.FirstOrDefaultAsync(g => g.Id == grantId, ct);

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

    /// <summary>Removes everything of an app (its rules, roles, grants and the calls from and to it), when the app is removed.</summary>
    public async Task RemoveAppAsync(string clientId, CancellationToken ct = default)
    {
        _db.AppPolicies.RemoveRange(await _db.AppPolicies.Where(p => p.ClientId == clientId).ToListAsync(ct));
        _db.AppRoles.RemoveRange(await _db.AppRoles.Where(r => r.ClientId == clientId).ToListAsync(ct));
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

    /// <summary>May <paramref name="user"/> sign in to the app, and with which role (see the rules in the remarks of the class).</summary>
    public async Task<AccessDecision> DecideAsync(User user, string clientId, CancellationToken ct = default)
    {
        if (!user.IsActive)
        {
            return new AccessDecision(false, null, "The account is disabled.");
        }

        var policy = await PolicyAsync(clientId, ct);
        var roles = await RolesAsync(clientId, ct);
        var groupIds = await _db.GroupMembers.Where(m => m.UserId == user.Id).Select(m => m.GroupId).ToListAsync(ct);
        var grants = await _db.AppGrants.AsNoTracking()
            .Where(g => g.ClientId == clientId && (g.UserId == user.Id || (g.GroupId != null && groupIds.Contains(g.GroupId.Value))))
            .ToListAsync(ct);

        var own = grants.FirstOrDefault(g => g.UserId == user.Id);
        var fromGroups = grants.Where(g => g.GroupId is not null).ToList();
        var allowed = user.Role == UserRole.Admin || own is not null || fromGroups.Count > 0 || policy.OpenToEveryone;
        if (!allowed)
        {
            return new AccessDecision(false, null, "This app was not given to you.");
        }

        if (policy.RoleMode == RoleMode.App)
        {
            return new AccessDecision(true, null, "The app decides the role.");
        }

        var rank = roles.Select((r, i) => (r.Key, i)).ToDictionary(x => x.Key, x => x.i, StringComparer.Ordinal);
        string role;
        if (own?.RoleKey is { } ownRole && rank.ContainsKey(ownRole))
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
            role = user.Role == UserRole.Admin && own is null && fromGroups.Count == 0 ? roles[0].Key : roles[^1].Key;
        }

        return new AccessDecision(true, role, "Allowed.");
    }

    /// <summary>The apps (client ids) <paramref name="user"/> may sign in to, for the start page.</summary>
    public async Task<HashSet<string>> AllowedAppsAsync(User user, IEnumerable<string> clientIds, CancellationToken ct = default)
    {
        var result = new HashSet<string>(StringComparer.Ordinal);
        foreach (var clientId in clientIds)
        {
            if ((await DecideAsync(user, clientId, ct)).Allowed)
            {
                result.Add(clientId);
            }
        }

        return result;
    }
}
