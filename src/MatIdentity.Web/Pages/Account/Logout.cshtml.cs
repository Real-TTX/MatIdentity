using MatIdentity.Core.Activity;
using MatIdentity.Core.Auth;
using MatIdentity.Core.Entities;
using MatIdentity.Core.Users;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace MatIdentity.Web.Pages.Account;

/// <summary>
/// Signs out of MatIdentity: the menu posts here. A GET asks first (a link on another site must not sign anyone out); <c>/connect/logout</c> sends an app's
/// sign-out here when it came without an ID token of the person, and the <see cref="ReturnUrl"/> takes the person back to it afterwards.
/// </summary>
[AllowAnonymous]
public class LogoutModel : PageModel
{
    private readonly SessionService _sessionService;
    private readonly UserService _users;
    private readonly ActivityService _activity;

    public LogoutModel(SessionService sessionService, UserService users, ActivityService activity)
    {
        _sessionService = sessionService;
        _users = users;
        _activity = activity;
    }

    [BindProperty(SupportsGet = true)]
    public string? ReturnUrl { get; set; }

    public IActionResult OnGet()
        => User.Identity?.IsAuthenticated == true ? Page() : LocalRedirect(Target(signedOut: false));

    public async Task<IActionResult> OnPostAsync()
    {
        if (User.GetSessionToken() is { } token)
        {
            await _sessionService.InvalidateAsync(token, HttpContext.RequestAborted);
        }

        if (User.GetUserId() is { } id)
        {
            await _activity.WriteAsync(ActivityKind.SignOut, await _users.GetAsync(id, HttpContext.RequestAborted),
                ipAddress: HttpContext.Connection.RemoteIpAddress?.ToString(), ct: HttpContext.RequestAborted);
        }

        await HttpContext.SignOutAsync(AuthConstants.CookieScheme);
        return LocalRedirect(Target(signedOut: true));
    }

    private string Target(bool signedOut)
        => Url.IsLocalUrl(ReturnUrl) ? ReturnUrl! : signedOut ? "/Account/Login?signedOut=true" : "/Account/Login";
}
