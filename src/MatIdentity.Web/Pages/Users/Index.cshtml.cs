using MatIdentity.Core.Access;
using MatIdentity.Core.Auth;
using MatIdentity.Core.Clients;
using MatIdentity.Core.Entities;
using MatIdentity.Core.Users;
using MatIdentity.Web.Controls;
using MatIdentity.Web.Infrastructure;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace MatIdentity.Web.Pages.Users;

public class IndexModel : PageModel
{
    private const int PageSize = 15;
    private static readonly StringComparison Ic = StringComparison.OrdinalIgnoreCase;
    private static readonly string[] SortKeys = ["username", "name", "role", "login"];

    private readonly UserService _userService;
    private readonly SessionService _sessions;
    private readonly TokenRevoker _revoker;
    private readonly PermissionService _permissions;

    public IndexModel(UserService userService, SessionService sessions, TokenRevoker revoker, PermissionService permissions)
    {
        _permissions = permissions;
        _userService = userService;
        _sessions = sessions;
        _revoker = revoker;
    }

    public ListView<User> List { get; private set; } = default!;

    [TempData] public string? StatusMessage { get; set; }
    [TempData] public bool IsError { get; set; }

    public async Task OnGetAsync()
    {
        var all = await _userService.GetAllAsync(HttpContext.RequestAborted);
        var q = ListQuery.Text(Request, "q");
        var role = ListQuery.Text(Request, "role");
        var sort = ListQuery.Text(Request, "sort") is { } s && SortKeys.Contains(s) ? s : "username";
        var descending = ListQuery.Descending(Request, defaultDescending: sort == "login");

        IEnumerable<User> query = all;
        if (Enum.TryParse<UserRole>(role, out var roleValue) && roleValue is UserRole.Admin or UserRole.User)
        {
            query = query.Where(u => u.Role == roleValue);
        }
        else
        {
            role = null;
        }

        if (q is not null)
        {
            query = query.Where(u => u.Username.Contains(q, Ic) || u.DisplayName.Contains(q, Ic) || (u.Email != null && u.Email.Contains(q, Ic)));
        }

        query = sort switch
        {
            "name" => Order(query, u => u.DisplayName.ToLowerInvariant(), descending),
            "role" => Order(query, u => (int)u.Role, descending),
            "login" => Order(query, u => u.LastLoginAt ?? DateTime.MinValue, descending),
            _ => Order(query, u => u.Username.ToLowerInvariant(), descending),
        };

        var list = query.ToList();
        var toolbar = new ToolbarModel
        {
            Id = "users",
            Action = "/Users",
            Label = "People",
            Search = q,
            SearchPlaceholder = "Search people",
            SearchField = true,
            Filters = [new FilterField("role", "Role", [new(nameof(UserRole.Admin), "Admin"), new(nameof(UserRole.User), "User")], role)],
            SortOptions = [new("username", "Username"), new("name", "Display name"), new("role", "Role"), new("login", "Last login")],
            Sort = sort,
            Descending = descending,
            DefaultSort = "username",
            Total = all.Count,
            Matching = list.Count,
            Noun = all.Count == 1 ? "person" : "people",
        };

        var (items, pager) = ListQuery.Slice(list, Request, PageSize, toolbar.UrlWithPage);
        List = new ListView<User> { Items = items, Toolbar = toolbar, Pager = pager };
    }

    public async Task<IActionResult> OnPostDeleteAsync(long id)
    {
        if (User.GetUserId() == id)
        {
            StatusMessage = "You cannot delete your own account.";
            IsError = true;
            return RedirectToPage();
        }

        // Signed out everywhere first: their sessions here and what the apps hold for them.
        if (await _userService.GetAsync(id, HttpContext.RequestAborted) is { } user)
        {
            await _sessions.InvalidateAllAsync(user.Id, ct: HttpContext.RequestAborted);
            await _revoker.RevokeForSubjectAsync(user.Subject, HttpContext.RequestAborted);
            await _permissions.RemoveUserAsync(user.Id, HttpContext.RequestAborted);
        }

        var deleted = await _userService.DeleteAsync(id, HttpContext.RequestAborted);
        StatusMessage = deleted ? "Person deleted." : "Person not found.";
        IsError = !deleted;
        return RedirectToPage();
    }

    private static IEnumerable<User> Order<TKey>(IEnumerable<User> source, Func<User, TKey> key, bool descending)
        => descending ? source.OrderByDescending(key) : source.OrderBy(key);
}
