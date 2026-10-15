using MatIdentity.Core.Access;
using MatIdentity.Core.Entities;
using MatIdentity.Web.Controls;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace MatIdentity.Web.Pages.Groups;

/// <summary>The groups of people: apps and roles given to a group count for all its members.</summary>
public class IndexModel : PageModel
{
    private const int PageSize = 15;

    private readonly GroupService _groups;

    public IndexModel(GroupService groups)
    {
        _groups = groups;
    }

    public ListView<(Group Group, int Members)> List { get; private set; } = default!;

    [TempData] public string? StatusMessage { get; set; }
    [TempData] public bool IsError { get; set; }

    public async Task OnGetAsync()
    {
        var all = await _groups.GetAllAsync(HttpContext.RequestAborted);
        var q = ListQuery.Text(Request, "q");
        var sort = ListQuery.Text(Request, "sort") is "members" ? "members" : "name";
        var descending = ListQuery.Descending(Request, defaultDescending: false);

        IEnumerable<(Group Group, int Members)> query = all;
        if (q is not null)
        {
            query = query.Where(g => g.Group.Name.Contains(q, StringComparison.OrdinalIgnoreCase) || (g.Group.Description?.Contains(q, StringComparison.OrdinalIgnoreCase) ?? false));
        }

        query = sort == "members"
            ? (descending ? query.OrderByDescending(g => g.Members) : query.OrderBy(g => g.Members))
            : (descending ? query.OrderByDescending(g => g.Group.Name.ToLowerInvariant()) : query.OrderBy(g => g.Group.Name.ToLowerInvariant()));

        var list = query.ToList();
        var toolbar = new ToolbarModel
        {
            Id = "groups",
            Action = "/Groups",
            Label = "Groups",
            Search = q,
            SearchPlaceholder = "Search groups",
            SearchField = true,
            SortOptions = [new("name", "Name"), new("members", "Members")],
            Sort = sort,
            Descending = descending,
            DefaultSort = "name",
            Total = all.Count,
            Matching = list.Count,
            Noun = all.Count == 1 ? "group" : "groups",
        };

        var (items, pager) = ListQuery.Slice(list, Request, PageSize, toolbar.UrlWithPage);
        List = new ListView<(Group Group, int Members)> { Items = items, Toolbar = toolbar, Pager = pager };
    }

    public async Task<IActionResult> OnPostDeleteAsync(long id)
    {
        var deleted = await _groups.DeleteAsync(id, HttpContext.RequestAborted);
        StatusMessage = deleted ? "Group deleted. Its people keep what was given to them directly." : "Group not found.";
        IsError = !deleted;
        return RedirectToPage();
    }
}
