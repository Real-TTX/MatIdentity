using MatIdentity.Core.Activity;
using MatIdentity.Core.Auth;
using MatIdentity.Core.Entities;
using MatIdentity.Core.Users;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace MatIdentity.Web.Pages.Account;

/// <summary>Signs out of MatIdentity (the menu). An app signs out through <c>/connect/logout</c> instead, which also sends the person back to it.</summary>
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

    public IActionResult OnGet() => RedirectToPage("/Account/Login");

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
        return RedirectToPage("/Account/Login", new { signedOut = true });
    }
}
