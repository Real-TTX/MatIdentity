using System.ComponentModel.DataAnnotations;
using MatIdentity.Core.Activity;
using MatIdentity.Core.Auth;
using MatIdentity.Core.Clients;
using MatIdentity.Core.Entities;
using MatIdentity.Core.Users;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.RateLimiting;

namespace MatIdentity.Web.Pages.Account;

/// <summary>
/// The link of a mail that sets a password: "Forgot your password?" (30 minutes) or an invitation (7 days). It works once; the new password ends every
/// other sign-in of the person (sessions here, the refresh tokens of the apps). The page sends no Referer, so the key does not leave with a link.
/// </summary>
[AllowAnonymous]
[EnableRateLimiting(RateLimits.SignIn)]
public class ResetModel : PageModel
{
    private readonly AccountMailService _accounts;
    private readonly SessionService _sessions;
    private readonly TokenRevoker _revoker;
    private readonly ActivityService _activity;

    public ResetModel(AccountMailService accounts, SessionService sessions, TokenRevoker revoker, ActivityService activity)
    {
        _accounts = accounts;
        _sessions = sessions;
        _revoker = revoker;
        _activity = activity;
    }

    [BindProperty(SupportsGet = true)]
    public string? Token { get; set; }

    [BindProperty]
    public InputModel Input { get; set; } = new();

    /// <summary>The link works: whose it is and what for.</summary>
    public AccountToken? Link { get; private set; }

    public bool IsInvitation => Link?.Purpose == AccountTokenPurpose.Invitation;

    public class InputModel
    {
        [Required(ErrorMessage = "Please enter a password.")]
        [MinLength(UserService.MinPasswordLength, ErrorMessage = "The password must be at least 8 characters.")]
        public string Password { get; set; } = string.Empty;

        [Compare(nameof(Password), ErrorMessage = "The passwords do not match.")]
        public string ConfirmPassword { get; set; } = string.Empty;
    }

    public async Task<IActionResult> OnGetAsync()
    {
        Response.Headers["Referrer-Policy"] = "no-referrer";
        Link = await _accounts.FindPasswordLinkAsync(Token, HttpContext.RequestAborted);
        return Page();
    }

    public async Task<IActionResult> OnPostAsync()
    {
        Response.Headers["Referrer-Policy"] = "no-referrer";
        Link = await _accounts.FindPasswordLinkAsync(Token, HttpContext.RequestAborted);
        if (Link is null || !ModelState.IsValid)
        {
            return Page();
        }

        var invitation = IsInvitation;
        if (await _accounts.SetPasswordAsync(Token, Input.Password, HttpContext.RequestAborted) is not { } user)
        {
            Link = null;
            return Page();
        }

        await _sessions.InvalidateAllAsync(user.Id, ct: HttpContext.RequestAborted);
        await _revoker.RevokeForSubjectAsync(user.Subject, HttpContext.RequestAborted);
        await _activity.WriteAsync(ActivityKind.PasswordSetByLink, user, ipAddress: HttpContext.Connection.RemoteIpAddress?.ToString(),
            detail: invitation ? "Invitation accepted" : "Password reset", ct: HttpContext.RequestAborted);
        return RedirectToPage("/Account/Login", new { passwordSet = true });
    }
}
