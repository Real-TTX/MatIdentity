using MatIdentity.Core.Activity;
using MatIdentity.Core.Entities;
using MatIdentity.Core.Users;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace MatIdentity.Web.Pages.Account;

/// <summary>The link that confirms an e-mail address: from then on the apps get <c>email_verified: true</c>.</summary>
[AllowAnonymous]
public class VerifyModel : PageModel
{
    private readonly AccountMailService _accounts;
    private readonly ActivityService _activity;

    public VerifyModel(AccountMailService accounts, ActivityService activity)
    {
        _accounts = accounts;
        _activity = activity;
    }

    [BindProperty(SupportsGet = true)]
    public string? Token { get; set; }

    /// <summary>The confirmed address, or null when the link did not work.</summary>
    public string? Email { get; private set; }

    public async Task<IActionResult> OnGetAsync()
    {
        Response.Headers["Referrer-Policy"] = "no-referrer";
        if (await _accounts.VerifyEmailAsync(Token, HttpContext.RequestAborted) is { } user)
        {
            Email = user.Email;
            await _activity.WriteAsync(ActivityKind.EmailVerified, user, ipAddress: HttpContext.Connection.RemoteIpAddress?.ToString(), detail: user.Email, ct: HttpContext.RequestAborted);
        }

        return Page();
    }
}
