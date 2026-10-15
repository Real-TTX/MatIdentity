using MatIdentity.Core.Activity;
using MatIdentity.Core.Entities;
using MatIdentity.Web.Controls;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace MatIdentity.Web.Pages.Activity;

/// <summary>What happened: sign-ins (and the failed ones), app sign-ins, machine tokens, changes to apps. Kept for 90 days.</summary>
public class IndexModel : PageModel
{
    private const int PageSize = 25;
    private static readonly StringComparison Ic = StringComparison.OrdinalIgnoreCase;

    private readonly ActivityService _activity;

    public IndexModel(ActivityService activity)
    {
        _activity = activity;
    }

    public ListView<ActivityEntry> List { get; private set; } = default!;

    public async Task OnGetAsync()
    {
        var all = await _activity.GetAllAsync(HttpContext.RequestAborted);
        var q = ListQuery.Text(Request, "q");
        var kind = ListQuery.Text(Request, "kind");
        var descending = ListQuery.Descending(Request, defaultDescending: true);

        IEnumerable<ActivityEntry> query = all;
        if (Enum.TryParse<ActivityKind>(kind, out var kindValue) && Enum.IsDefined(kindValue))
        {
            query = query.Where(a => a.Kind == kindValue);
        }
        else
        {
            kind = null;
        }

        if (q is not null)
        {
            query = query.Where(a => (a.Username?.Contains(q, Ic) ?? false) || (a.ClientId?.Contains(q, Ic) ?? false) || (a.IpAddress?.Contains(q, Ic) ?? false) || (a.Detail?.Contains(q, Ic) ?? false));
        }

        query = descending ? query.OrderByDescending(a => a.Id) : query.OrderBy(a => a.Id);
        var list = query.ToList();
        var toolbar = new ToolbarModel
        {
            Id = "activity",
            Action = "/Activity",
            Label = "Activity",
            Search = q,
            SearchPlaceholder = "Search people, apps, addresses",
            SearchField = true,
            Filters = [new FilterField("kind", "What", Enum.GetValues<ActivityKind>().Select(k => new FilterOption(k.ToString(), ActivityService.Describe(k))).ToList(), kind)],
            SortOptions = [new("time", "Time")],
            Sort = "time",
            Descending = descending,
            DefaultSort = "time",
            DefaultDescending = true,
            Total = all.Count,
            Matching = list.Count,
            Noun = all.Count == 1 ? "entry" : "entries",
        };

        var (items, pager) = ListQuery.Slice(list, Request, PageSize, toolbar.UrlWithPage);
        List = new ListView<ActivityEntry> { Items = items, Toolbar = toolbar, Pager = pager };
    }
}
