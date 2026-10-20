using System.ComponentModel.DataAnnotations;
using MatIdentity.Core.Activity;
using MatIdentity.Core.Auth;
using MatIdentity.Core.Configuration;
using MatIdentity.Core.Entities;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.RateLimiting;

namespace MatIdentity.Web.Pages.Account;

/// <summary>
/// The one sign-in form of the family. An app sends the person to <c>/connect/authorize</c>, which sends them here with the request as <c>returnUrl</c>;
/// after the sign-in they go back there and on to the app. A person who is signed in already never sees the form (unless the app asked for it: <c>force</c>).
/// </summary>
[AllowAnonymous]
[EnableRateLimiting(RateLimits.SignIn)]
public class LoginModel : PageModel
{
    private readonly AuthService _authService;
    private readonly SessionService _sessionService;
    private readonly ActivityService _activity;
    private readonly SystemConfigService _config;
    private readonly TwoFactorService _twoFactor;
    private readonly MatIdentity.Core.Mail.MailService _mail;
    private readonly IConfiguration _configuration;

    public LoginModel(AuthService authService, SessionService sessionService, ActivityService activity, SystemConfigService config, TwoFactorService twoFactor, MatIdentity.Core.Mail.MailService mail, IConfiguration configuration)
    {
        _mail = mail;
        _configuration = configuration;
        _twoFactor = twoFactor;
        _authService = authService;
        _sessionService = sessionService;
        _activity = activity;
        _config = config;
    }

    [BindProperty]
    public InputModel Input { get; set; } = new();

    [BindProperty(SupportsGet = true)]
    public string? ReturnUrl { get; set; }

    /// <summary>The app asked for the form although the person is signed in (<c>prompt=login</c>).</summary>
    [BindProperty(SupportsGet = true)]
    public bool Force { get; set; }

    [BindProperty(SupportsGet = true)]
    public bool SignedOut { get; set; }

    /// <summary>Back from a link that set the password.</summary>
    [BindProperty(SupportsGet = true)]
    public bool PasswordSet { get; set; }

    /// <summary>"Forgot your password?" is offered (mail and a public address).</summary>
    public bool CanReset { get; private set; }

    public string? ErrorMessage { get; private set; }

    public string InstanceName { get; private set; } = Support.Ui.App.Name;

    /// <summary>The sign-in is for an app (the person came through <c>/connect/authorize</c>).</summary>
    public bool ForApp => ReturnUrl?.StartsWith("/connect/authorize", StringComparison.OrdinalIgnoreCase) == true;

    public class InputModel
    {
        [Required(ErrorMessage = "Please enter your username or e-mail.")]
        [Display(Name = "Username")]
        public string Username { get; set; } = string.Empty;

        [Required(ErrorMessage = "Please enter your password.")]
        [DataType(DataType.Password)]
        [Display(Name = "Password")]
        public string Password { get; set; } = string.Empty;

        [Display(Name = "Stay signed in")]
        public bool RememberMe { get; set; } = true;
    }

    public async Task<IActionResult> OnGetAsync()
    {
        if (User.Identity?.IsAuthenticated == true && !Force)
        {
            return LocalRedirect(SafeReturnUrl());
        }

        await LoadAsync();
        return Page();
    }

    public async Task<IActionResult> OnPostAsync()
    {
        await LoadAsync();
        if (!ModelState.IsValid)
        {
            return Page();
        }

        var ip = HttpContext.Connection.RemoteIpAddress?.ToString();
        var result = await _authService.AuthenticateAsync(Input.Username, Input.Password, HttpContext.RequestAborted);
        if (!result.Succeeded || result.User is null)
        {
            await _activity.WriteAsync(ActivityKind.SignInFailed, username: Input.Username, ipAddress: ip, detail: result.WasLocked ? "The account is locked" : result.Error, ct: HttpContext.RequestAborted);
            if (result.LockedNow)
            {
                await _activity.WriteAsync(ActivityKind.AccountLocked, username: Input.Username, ipAddress: ip,
                    detail: $"{AuthService.MaxFailedAttempts} wrong attempts in a row: locked for {(int)AuthService.LockoutDuration.TotalMinutes} minutes", ct: HttpContext.RequestAborted);
            }

            ErrorMessage = result.Error ?? "Sign-in failed.";
            return Page();
        }

        // An authenticator app or a passkey: the password alone is not enough, the second step comes first.
        if (await _twoFactor.NeedsSecondStepAsync(result.User, HttpContext.RequestAborted))
        {
            await SignInFlow.BeginSecondStepAsync(HttpContext, result.User, Input.RememberMe);
            return RedirectToPage("/Account/TwoFactor", new { returnUrl = SafeReturnUrl() });
        }

        await SignInFlow.CompleteAsync(HttpContext, result.User, Input.RememberMe, how: "with the password");

        // A forced password change lands on the account page via the guard middleware (and comes back here afterwards).
        return LocalRedirect(SafeReturnUrl());
    }

    private async Task LoadAsync()
    {
        InstanceName = (await _config.GetAsync(HttpContext.RequestAborted)).InstanceName;
        CanReset = await ForgotModel.LinkBaseAsync(HttpContext, _mail, _config, _configuration) is not null;
    }

    private string SafeReturnUrl()
        => !string.IsNullOrEmpty(ReturnUrl) && Url.IsLocalUrl(ReturnUrl) ? ReturnUrl : "/";
}
