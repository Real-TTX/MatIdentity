using MatIdentity.Core.Activity;
using MatIdentity.Core.Clients;
using MatIdentity.Core.Entities;
using MatIdentity.Web.Platform;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace MatIdentity.Web.Pages;

/// <summary>
/// The start page: the apps a person can open with this one sign-in (those with an address), and for an administrator the figures of
/// <c>/api/state</c> and the last things that happened.
/// </summary>
public class IndexModel : PageModel
{
    private readonly ClientService _clients;
    private readonly ActivityService _activity;
    private readonly IMatPlatformApp _platform;

    public IndexModel(ClientService clients, ActivityService activity, IMatPlatformApp platform)
    {
        _clients = clients;
        _activity = activity;
        _platform = platform;
    }

    public IReadOnlyList<ClientInfo> Apps { get; private set; } = [];

    /// <summary>The tiles of the overview, as Mattiverse shows them: the definition and the values of the platform contract.</summary>
    public IReadOnlyList<(MatStateItem Item, MatStateValue Value)> Tiles { get; private set; } = [];

    public IReadOnlyList<ActivityEntry> Recent { get; private set; } = [];

    public bool HasAnyApp { get; private set; }

    public async Task OnGetAsync()
    {
        var ct = HttpContext.RequestAborted;
        var all = await _clients.GetAllAsync(ct);
        HasAnyApp = all.Count > 0;
        Apps = all.Where(c => c.AllowSignIn && !string.IsNullOrEmpty(c.HomeUrl)).ToList();

        if (User.IsAdmin())
        {
            var definition = _platform.Definition(HttpContext);
            var values = await _platform.StateAsync(ct);
            Tiles = definition.State.Where(s => s.Widget == "number" && values.ContainsKey(s.Key)).Select(s => (s, values[s.Key])).ToList();
            Recent = await _activity.GetRecentAsync(8, ct);
        }
    }
}
