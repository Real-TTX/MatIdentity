using System.ComponentModel.DataAnnotations;
using MatIdentity.Core.Activity;
using MatIdentity.Core.Auth;
using MatIdentity.Core.Entities;
using MatIdentity.Core.Users;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.RateLimiting;

namespace MatIdentity.Web.Pages.Account;

/// <summary>
/// The second step after the password: the code of the authenticator app, a recovery code, or a passkey. Only reachable within five minutes of a right
/// password (<see cref="SignInFlow"/>); five wrong codes and the person starts with the password again.
/// </summary>
[AllowAnonymous]
[EnableRateLimiting(RateLimits.SignIn)]
public class TwoFactorModel : PageModel
{
    private readonly TwoFactorService _twoFactor;
    private readonly UserService _users;
    private readonly ActivityService _activity;
    private readonly PasskeyService _passkeys;

    public TwoFactorModel(TwoFactorService twoFactor, UserService users, ActivityService activity, PasskeyService passkeys)
    {
        _twoFactor = twoFactor;
        _users = users;
        _activity = activity;
        _passkeys = passkeys;
    }

    [BindProperty(SupportsGet = true)]
    public string? ReturnUrl { get; set; }

    [BindProperty]
    [Required(ErrorMessage = "Please enter the code.")]
    [Display(Name = "Code")]
    public string Code { get; set; } = string.Empty;

    public string? ErrorMessage { get; private set; }

    public bool HasAuthenticator { get; private set; }

    public bool HasPasskey { get; private set; }

    public async Task<IActionResult> OnGetAsync()
        => await LoadAsync() is null ? RedirectToPage("/Account/Login", new { returnUrl = ReturnUrl }) : Page();

    public async Task<IActionResult> OnPostAsync()
    {
        var pending = await SignInFlow.PendingAsync(HttpContext);
        var user = await LoadAsync();
        if (pending is null || user is null)
        {
            return RedirectToPage("/Account/Login", new { returnUrl = ReturnUrl });
        }

        if (!ModelState.IsValid)
        {
            return Page();
        }

        var (ok, recovery) = await _twoFactor.VerifyAsync(user.Id, Code, HttpContext.RequestAborted);
        if (!ok)
        {
            await _activity.WriteAsync(ActivityKind.SignInFailed, user, ipAddress: HttpContext.Connection.RemoteIpAddress?.ToString(), detail: "Wrong code", ct: HttpContext.RequestAborted);
            if (await SignInFlow.FailedAttemptAsync(HttpContext, user.Id))
            {
                return RedirectToPage("/Account/Login", new { returnUrl = ReturnUrl });
            }

            ErrorMessage = "This code is not right. Use the code your app shows now, or one of your recovery codes.";
            return Page();
        }

        await SignInFlow.CompleteAsync(HttpContext, user, pending.Value.Remember, recovery ? "with a recovery code" : "with the authenticator app");
        return LocalRedirect(!string.IsNullOrEmpty(ReturnUrl) && Url.IsLocalUrl(ReturnUrl) ? ReturnUrl : "/");
    }

    private async Task<User?> LoadAsync()
    {
        if (await SignInFlow.PendingAsync(HttpContext) is not { } pending || await _users.GetAsync(pending.UserId, HttpContext.RequestAborted) is not { IsActive: true } user)
        {
            return null;
        }

        HasAuthenticator = user.TotpEnabled;
        HasPasskey = await _passkeys.AnyAsync(user.Id, HttpContext.RequestAborted);
        return user;
    }
}
