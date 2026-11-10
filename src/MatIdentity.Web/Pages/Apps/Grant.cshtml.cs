using System.Globalization;
using MatIdentity.Core.Access;
using MatIdentity.Core.Activity;
using MatIdentity.Core.Clients;
using MatIdentity.Core.Entities;
using MatIdentity.Web.Controls;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace MatIdentity.Web.Pages.Apps;

/// <summary>
/// What one grant gives in an app (MatDesign docs/PLATFORM.md "People, permissions and quotas"): the role, the permissions on top of it and the quotas. A permission the
/// role brings is shown ticked; a quota left empty is the app's own setting. A change ends the sessions of the people it concerns in this app, so they get it at once.
/// </summary>
public class GrantModel : PageModel
{
    /// <summary>A quota in bytes is entered in GB.</summary>
    public const long Gigabyte = 1024L * 1024 * 1024;

    private readonly ClientService _clients;
    private readonly PermissionService _permissions;
    private readonly ActivityService _activity;

    public GrantModel(ClientService clients, PermissionService permissions, ActivityService activity)
    {
        _clients = clients;
        _permissions = permissions;
        _activity = activity;
    }

    [BindProperty(SupportsGet = true, Name = "id")]
    public string Id { get; set; } = string.Empty;

    [BindProperty(SupportsGet = true, Name = "grant")]
    public long GrantId { get; set; }

    public ClientInfo App { get; private set; } = default!;

    public AppGrant Grant { get; private set; } = default!;

    /// <summary>The person or the group of the grant.</summary>
    public string Who { get; private set; } = string.Empty;

    public IReadOnlyList<RoleInfo> Roles { get; private set; } = [];

    public IReadOnlyList<PermissionInfo> AppPermissions { get; private set; } = [];

    public IReadOnlyList<QuotaInfo> AppQuotas { get; private set; } = [];

    [BindProperty]
    public string? Role { get; set; }

    [BindProperty]
    public List<string> Permissions { get; set; } = [];

    /// <summary>The value per quota as typed (GB for a quota in bytes); empty: the app's own setting.</summary>
    [BindProperty]
    public Dictionary<string, string?> Quota { get; set; } = new(StringComparer.Ordinal);

    /// <summary>The quotas set to no limit.</summary>
    [BindProperty]
    public List<string> Unlimited { get; set; } = [];

    [TempData] public string? StatusMessage { get; set; }
    [TempData] public bool IsError { get; set; }

    public TabBarModel Tabs => AppTabs.For(Id, "access", App.AllowMachine);

    /// <summary>The role that counts for the permissions it brings: the one of the grant, else the default (the last).</summary>
    public string EffectiveRole => Role is { Length: > 0 } role ? role : Roles[^1].Key;

    public async Task<IActionResult> OnGetAsync()
    {
        if (!await LoadAsync())
        {
            return NotFound();
        }

        var values = GrantValues.Of(Grant);
        Role = Grant.RoleKey;
        Permissions = [.. values.Permissions];
        foreach (var quota in AppQuotas)
        {
            if (values.Quotas.TryGetValue(quota.Key, out var value))
            {
                if (value is null)
                {
                    Unlimited.Add(quota.Key);
                }
                else
                {
                    Quota[quota.Key] = Show(quota, value.Value);
                }
            }
        }

        return Page();
    }

    public async Task<IActionResult> OnPostAsync()
    {
        var ct = HttpContext.RequestAborted;
        if (!await LoadAsync())
        {
            return NotFound();
        }

        var role = Roles.Any(r => r.Key == Role) ? Role : null;
        var quotas = new Dictionary<string, long?>(StringComparer.Ordinal);
        foreach (var quota in AppQuotas)
        {
            if (Unlimited.Contains(quota.Key))
            {
                quotas[quota.Key] = null;
            }
            else if (Quota.GetValueOrDefault(quota.Key) is { Length: > 0 } text)
            {
                if (Parse(quota, text) is { } number)
                {
                    quotas[quota.Key] = number;
                }
                else
                {
                    ModelState.AddModelError($"Quota[{quota.Key}]", $"{quota.Label}: a number" + (quota.Unit == "bytes" ? " of GB." : "."));
                }
            }
        }

        // A permission the role brings is not kept on the grant: it comes with the role anyway.
        var fromRole = AppPermissions.Where(p => (p.Roles ?? []).Contains(role ?? Roles[^1].Key)).Select(p => p.Key).ToHashSet(StringComparer.Ordinal);
        var values = new GrantValues([.. Permissions.Distinct(StringComparer.Ordinal).Where(p => !fromRole.Contains(p))], quotas);
        foreach (var (key, message) in PermissionService.ValidateGrant(values, AppPermissions, AppQuotas))
        {
            ModelState.AddModelError(key.StartsWith("quotas.", StringComparison.Ordinal) ? $"Quota[{key[7..]}]" : string.Empty, message);
        }

        if (!ModelState.IsValid)
        {
            return Page();
        }

        await _permissions.SaveGrantAsync(Id, Grant.UserId, Grant.GroupId, role, values, ct);
        await _activity.WriteAsync(ActivityKind.ClientChanged, username: User.GetUsername(), clientId: Id, ipAddress: HttpContext.Connection.RemoteIpAddress?.ToString(),
            detail: $"{Who}: role {role ?? "default"}, permissions {string.Join(' ', values.Permissions)}, quotas {values.QuotasJson ?? "none"}", ct: ct);
        StatusMessage = $"Saved for {Who}. The people it concerns get it the next time they open the app.";
        IsError = false;
        return RedirectToPage("/Apps/Access", new { id = Id });
    }

    /// <summary>The value of a quota as the field shows it (GB for bytes).</summary>
    public static string Show(QuotaInfo quota, long value)
        => quota.Unit == "bytes" ? (value / (double)Gigabyte).ToString("0.###", CultureInfo.InvariantCulture) : value.ToString(CultureInfo.InvariantCulture);

    /// <summary>The unit of a quota for people (with its period).</summary>
    public static string UnitOf(QuotaInfo quota)
    {
        var unit = quota.Unit switch { "bytes" => "GB", "count" => "items", _ => quota.Unit };
        return quota.Period switch { "day" => unit + " per day", "month" => unit + " per month", _ => unit };
    }

    private static long? Parse(QuotaInfo quota, string text)
    {
        var normalized = text.Trim().Replace(',', '.');
        if (quota.Unit == "bytes")
        {
            return double.TryParse(normalized, NumberStyles.Float, CultureInfo.InvariantCulture, out var gb) && gb >= 0 && gb < 8_000_000_000
                ? (long)Math.Round(gb * Gigabyte)
                : null;
        }

        return long.TryParse(normalized, NumberStyles.Integer, CultureInfo.InvariantCulture, out var number) && number >= 0 ? number : null;
    }

    private async Task<bool> LoadAsync()
    {
        var ct = HttpContext.RequestAborted;
        if (await _clients.GetAsync(Id, ct) is not { } app || await _permissions.FindGrantAsync(GrantId, ct) is not { } grant || grant.ClientId != Id)
        {
            return false;
        }

        App = app;
        Grant = grant;
        var named = (await _permissions.GrantsAsync(Id, ct)).FirstOrDefault(g => g.Id == grant.Id);
        Who = named?.Group?.Name ?? named?.User?.DisplayName ?? "?";
        Roles = await _permissions.RolesAsync(Id, ct);
        AppPermissions = await _permissions.PermissionsAsync(Id, ct);
        AppQuotas = await _permissions.QuotasAsync(Id, ct);
        return true;
    }
}
