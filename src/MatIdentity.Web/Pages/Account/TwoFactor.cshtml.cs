using System.ComponentModel.DataAnnotations;
using MatIdentity.Core.Activity;
using MatIdentity.Core.Auth;
using MatIdentity.Core.Entities;
using MatIdentity.Core.Users;
using Microsoft.AspNetCore.Authentication;
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
    private readonly AuthService _auth;

    public TwoFactorModel(TwoFactorService twoFactor, UserService users, ActivityService activity, PasskeyService passkeys, AuthService auth)
    {
        _auth = auth;
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

    /// <summary>Recovery codes are left (they come with the authenticator app); without them a passkey is the only second step.</summary>
    public bool HasRecoveryCodes { get; private set; }

    /// <summary>The field for a code: for the authenticator app or a recovery code.</summary>
    public bool AcceptsCode => HasAuthenticator || HasRecoveryCodes;

    /// <summary>Back to the password, for the same app.</summary>
    public string CancelUrl => "/Account/Login" + (string.IsNullOrEmpty(ReturnUrl) ? string.Empty : "?returnUrl=" + Uri.EscapeDataString(ReturnUrl));

    public async Task<IActionResult> OnGetAsync()
        => await LoadAsync() is null ? RedirectToPage("/Account/Login", new { returnUrl = ReturnUrl }) : Page();

    public async Task<IActionResult> OnPostAsync()
    {
        var pending = await SignInFlow.PendingAsync(HttpContext);
        var user = await LoadAsync();
        if (pending is null || user is null || user.LockedUntil > DateTime.UtcNow)
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
            // Wrong codes count like wrong passwords: ten in a row lock the account (the five-try limit alone could be restarted with the password).
            if (await _auth.RegisterFailureAsync(user, HttpContext.RequestAborted))
            {
                await _activity.WriteAsync(ActivityKind.AccountLocked, user, ipAddress: HttpContext.Connection.RemoteIpAddress?.ToString(),
                    detail: $"{AuthService.MaxFailedAttempts} wrong attempts in a row: locked for {(int)AuthService.LockoutDuration.TotalMinutes} minutes", ct: HttpContext.RequestAborted);
                await HttpContext.SignOutAsync(SignInFlow.TwoFactorScheme);
                return RedirectToPage("/Account/Login", new { returnUrl = ReturnUrl });
            }

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
        HasRecoveryCodes = TwoFactorService.RecoveryCodesLeft(user) > 0;
        return user;
    }
}
