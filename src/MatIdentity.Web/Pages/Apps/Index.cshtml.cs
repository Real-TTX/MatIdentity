using MatIdentity.Core.Activity;
using MatIdentity.Core.Clients;
using MatIdentity.Core.Entities;
using MatIdentity.Web.Controls;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace MatIdentity.Web.Pages.Apps;

/// <summary>The apps that sign in through MatIdentity (OpenID Connect clients): a list with its toolbar, create and edit on their own page.</summary>
public class IndexModel : PageModel
{
    private const int PageSize = 15;
    private static readonly StringComparison Ic = StringComparison.OrdinalIgnoreCase;

    private readonly ClientService _clients;
    private readonly ActivityService _activity;

    public IndexModel(ClientService clients, ActivityService activity)
    {
        _clients = clients;
        _activity = activity;
    }

    public ListView<ClientInfo> List { get; private set; } = default!;

    [TempData] public string? StatusMessage { get; set; }
    [TempData] public bool IsError { get; set; }

    public async Task OnGetAsync()
    {
        var all = await _clients.GetAllAsync(HttpContext.RequestAborted);
        var q = ListQuery.Text(Request, "q");
        var kind = ListQuery.Text(Request, "kind");
        var sort = ListQuery.Text(Request, "sort") is "id" ? "id" : "name";
        var descending = ListQuery.Descending(Request, defaultDescending: false);

        IEnumerable<ClientInfo> query = all;
        query = kind switch
        {
            "signin" => query.Where(c => c.AllowSignIn),
            "machine" => query.Where(c => c.AllowMachine),
            "mattiverse" => query.Where(c => c.ManagedBy == "mattiverse"),
            _ => query,
        };
        if (kind is not ("signin" or "machine" or "mattiverse"))
        {
            kind = null;
        }

        if (q is not null)
        {
            query = query.Where(c => c.DisplayName.Contains(q, Ic) || c.ClientId.Contains(q, Ic) || (c.HomeUrl?.Contains(q, Ic) ?? false));
        }

        query = sort == "id"
            ? (descending ? query.OrderByDescending(c => c.ClientId) : query.OrderBy(c => c.ClientId))
            : (descending ? query.OrderByDescending(c => c.DisplayName.ToLowerInvariant()) : query.OrderBy(c => c.DisplayName.ToLowerInvariant()));

        var list = query.ToList();
        var toolbar = new ToolbarModel
        {
            Id = "apps",
            Action = "/Apps",
            Label = "Apps",
            Search = q,
            SearchPlaceholder = "Search apps",
            SearchField = true,
            Filters = [new FilterField("kind", "Kind", [new("signin", "People sign in"), new("machine", "Calls other apps"), new("mattiverse", "Added by Mattiverse")], kind)],
            SortOptions = [new("name", "Name"), new("id", "Id")],
            Sort = sort,
            Descending = descending,
            DefaultSort = "name",
            Total = all.Count,
            Matching = list.Count,
            Noun = all.Count == 1 ? "app" : "apps",
        };

        var (items, pager) = ListQuery.Slice(list, Request, PageSize, toolbar.UrlWithPage);
        List = new ListView<ClientInfo> { Items = items, Toolbar = toolbar, Pager = pager };
    }

    public async Task<IActionResult> OnPostDeleteAsync(string clientId)
    {
        var deleted = await _clients.DeleteAsync(clientId, HttpContext.RequestAborted);
        if (deleted)
        {
            await _activity.WriteAsync(ActivityKind.ClientDeleted, username: User.GetUsername(), clientId: clientId, ipAddress: HttpContext.Connection.RemoteIpAddress?.ToString(), ct: HttpContext.RequestAborted);
        }

        StatusMessage = deleted ? "App removed. It can no longer sign anyone in." : "App not found.";
        IsError = !deleted;
        return RedirectToPage();
    }
}
