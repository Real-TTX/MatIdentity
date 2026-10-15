using MatIdentity.Core.Access;
using MatIdentity.Core.Activity;
using MatIdentity.Core.Clients;
using MatIdentity.Core.Entities;
using MatIdentity.Core.Users;
using MatIdentity.Web.Controls;
using MatIdentity.Web.Platform;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace MatIdentity.Web.Pages.Apps;

/// <summary>
/// Who may sign in to an app and with which role: who decides the roles (MatIdentity or the app), whether everyone may come in, the roles of the app,
/// and the people and groups it is given to. Every change takes effect at the next sign-in and at the next renewal of a token.
/// </summary>
public class AccessModel : PageModel
{
    private readonly ClientService _clients;
    private readonly PermissionService _permissions;
    private readonly GroupService _groups;
    private readonly UserService _users;
    private readonly ActivityService _activity;
    private readonly AppRolesReader _rolesReader;

    public AccessModel(ClientService clients, PermissionService permissions, GroupService groups, UserService users, ActivityService activity, AppRolesReader rolesReader)
    {
        _clients = clients;
        _permissions = permissions;
        _groups = groups;
        _users = users;
        _activity = activity;
        _rolesReader = rolesReader;
    }

    [BindProperty(SupportsGet = true, Name = "id")]
    public string Id { get; set; } = string.Empty;

    public ClientInfo App { get; private set; } = default!;

    public AppPolicy Policy { get; private set; } = default!;

    public IReadOnlyList<RoleInfo> Roles { get; private set; } = [];

    /// <summary>The app has roles of its own (not the defaults).</summary>
    public bool HasOwnRoles { get; private set; }

    public IReadOnlyList<AppGrant> Grants { get; private set; } = [];

    /// <summary>What can still be given the app: groups first, then people (<c>g:3</c>, <c>u:12</c>).</summary>
    public IReadOnlyList<(string Value, string Label)> Candidates { get; private set; } = [];

    [BindProperty]
    public RoleMode RoleMode { get; set; }

    [BindProperty]
    public bool OpenToEveryone { get; set; }

    [BindProperty]
    public string? RolesText { get; set; }

    [TempData] public string? StatusMessage { get; set; }
    [TempData] public bool IsError { get; set; }

    public TabBarModel Tabs => AppTabs.For(Id, "access", App.AllowMachine);

    public async Task<IActionResult> OnGetAsync() => await LoadAsync() ? Page() : NotFound();

    public async Task<IActionResult> OnPostRulesAsync()
    {
        var ct = HttpContext.RequestAborted;
        if (!await LoadAsync(keepInput: true))
        {
            return NotFound();
        }

        await _permissions.SavePolicyAsync(Id, Enum.IsDefined(RoleMode) ? RoleMode : RoleMode.MatIdentity, OpenToEveryone, Policy.CallsAllApps, ct);
        await LogAsync($"Roles by {(RoleMode == RoleMode.App ? "the app" : "MatIdentity")}, {(OpenToEveryone ? "open to everyone" : "only those it is given to")}");
        return Done("Saved. It takes effect at the next sign-in and at the next renewal of a token.");
    }

    public async Task<IActionResult> OnPostRolesAsync()
    {
        if (!await LoadAsync(keepInput: true))
        {
            return NotFound();
        }

        var roles = ParseRoles(RolesText);
        var errors = await _permissions.SaveRolesAsync(Id, roles, HttpContext.RequestAborted);
        if (errors.Count > 0)
        {
            ModelState.AddModelError(nameof(RolesText), errors.Values.First());
            return Page();
        }

        await LogAsync("Roles: " + string.Join(", ", roles.Select(r => r.Key)));
        return Done("Roles saved.");
    }

    public async Task<IActionResult> OnPostReadRolesAsync()
    {
        if (!await LoadAsync())
        {
            return NotFound();
        }

        var (roles, error) = await _rolesReader.ReadAsync(App, HttpContext.RequestAborted);
        if (roles is null)
        {
            StatusMessage = error;
            IsError = true;
            return RedirectToPage(new { id = Id });
        }

        var errors = await _permissions.SaveRolesAsync(Id, roles, HttpContext.RequestAborted);
        if (errors.Count > 0)
        {
            StatusMessage = "The app named roles MatIdentity cannot use: " + errors.Values.First();
            IsError = true;
            return RedirectToPage(new { id = Id });
        }

        await LogAsync("Roles read from the app: " + string.Join(", ", roles.Select(r => r.Key)));
        return Done($"{roles.Count} roles read from the app.");
    }

    public async Task<IActionResult> OnPostGrantAsync(string? principal, string? role)
    {
        if (!await LoadAsync())
        {
            return NotFound();
        }

        var (userId, groupId) = ParsePrincipal(principal);
        if (userId is null && groupId is null)
        {
            StatusMessage = "Choose a person or a group.";
            IsError = true;
            return RedirectToPage(new { id = Id });
        }

        var name = groupId is { } g ? (await _groups.GetAsync(g, HttpContext.RequestAborted))?.Name : (await _users.GetAsync(userId!.Value, HttpContext.RequestAborted))?.DisplayName;
        if (name is null)
        {
            return NotFound();
        }

        await _permissions.GrantAsync(Id, userId, groupId, ValidRole(role), HttpContext.RequestAborted);
        await LogAsync($"Given to {name}" + (ValidRole(role) is { } r ? $" as {r}" : string.Empty));
        return Done($"{App.DisplayName} is given to {name}.");
    }

    public async Task<IActionResult> OnPostChangeRoleAsync(long grantId, string? role)
    {
        if (!await LoadAsync() || await _permissions.FindGrantAsync(grantId, HttpContext.RequestAborted) is not { } grant || grant.ClientId != Id)
        {
            return NotFound();
        }

        await _permissions.GrantAsync(Id, grant.UserId, grant.GroupId, ValidRole(role), HttpContext.RequestAborted);
        await LogAsync($"Role changed to {ValidRole(role) ?? "the default"}");
        return Done("Role changed.");
    }

    public async Task<IActionResult> OnPostRevokeAsync(long grantId)
    {
        if (!await LoadAsync() || await _permissions.FindGrantAsync(grantId, HttpContext.RequestAborted) is not { } grant || grant.ClientId != Id)
        {
            return NotFound();
        }

        await _permissions.RevokeAsync(grantId, HttpContext.RequestAborted);
        await LogAsync("Taken away from a " + (grant.GroupId is null ? "person" : "group"));
        return Done("Taken away. The app lets them in no more after the next renewal of their token.");
    }

    /// <summary>One role per line: the key, a space or a tab, the name ("admin Administrator"); a line with only a key uses it as the name too.</summary>
    public static IReadOnlyList<RoleInfo> ParseRoles(string? text)
        => (text ?? string.Empty).Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(line => line.Split([' ', '\t'], 2, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            .Select(parts => new RoleInfo(parts[0], parts.Length > 1 ? parts[1] : parts[0]))
            .ToList();

    private static (long? UserId, long? GroupId) ParsePrincipal(string? value)
        => value switch
        {
            ['u', ':', .. var rest] when long.TryParse(rest, out var id) => (id, null),
            ['g', ':', .. var rest] when long.TryParse(rest, out var id) => (null, id),
            _ => (null, null),
        };

    private string? ValidRole(string? role) => Roles.Any(r => r.Key == role) ? role : null;

    private async Task LogAsync(string detail)
        => await _activity.WriteAsync(ActivityKind.ClientChanged, username: User.GetUsername(), clientId: Id,
            ipAddress: HttpContext.Connection.RemoteIpAddress?.ToString(), detail: detail, ct: HttpContext.RequestAborted);

    private IActionResult Done(string message)
    {
        StatusMessage = message;
        IsError = false;
        return RedirectToPage(new { id = Id });
    }

    private async Task<bool> LoadAsync(bool keepInput = false)
    {
        var ct = HttpContext.RequestAborted;
        if (await _clients.GetAsync(Id, ct) is not { } app)
        {
            return false;
        }

        App = app;
        Policy = await _permissions.PolicyAsync(Id, ct);
        Roles = await _permissions.RolesAsync(Id, ct);
        HasOwnRoles = !ReferenceEquals(Roles, PermissionService.DefaultRoles);
        Grants = await _permissions.GrantsAsync(Id, ct);
        if (!keepInput)
        {
            RoleMode = Policy.RoleMode;
            OpenToEveryone = Policy.OpenToEveryone;
            RolesText = string.Join('\n', Roles.Select(r => $"{r.Key} {r.Label}"));
        }

        var givenGroups = Grants.Where(g => g.GroupId is not null).Select(g => g.GroupId!.Value).ToHashSet();
        var givenUsers = Grants.Where(g => g.UserId is not null).Select(g => g.UserId!.Value).ToHashSet();
        var groups = (await _groups.GetAllAsync(ct)).Where(g => !givenGroups.Contains(g.Group.Id)).Select(g => ($"g:{g.Group.Id}", $"Group: {g.Group.Name}"));
        var people = (await _users.GetAllAsync(ct)).Where(u => !givenUsers.Contains(u.Id)).Select(u => ($"u:{u.Id}", $"{u.DisplayName} ({u.Username})"));
        Candidates = groups.Concat(people).ToList();
        return true;
    }
}

/// <summary>The tabs of the pages of one app.</summary>
public static class AppTabs
{
    public static TabBarModel For(string clientId, string active, bool callsApps) => new()
    {
        Tabs =
        [
            new TabItem { Title = "General", Href = "/Apps/Edit?id=" + Uri.EscapeDataString(clientId), Icon = "settings", Active = active == "general" },
            new TabItem { Title = "Access", Href = "/Apps/Access?id=" + Uri.EscapeDataString(clientId), Icon = "users", Active = active == "access" },
        ],
    };
}
