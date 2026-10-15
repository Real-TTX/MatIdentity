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

    public LoginModel(AuthService authService, SessionService sessionService, ActivityService activity, SystemConfigService config)
    {
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

    public string? ErrorMessage { get; private set; }

    public string InstanceName { get; private set; } = Support.Ui.App.Name;

    /// <summary>The sign-in is for an app (the person came through <c>/connect/authorize</c>).</summary>
    public bool ForApp => ReturnUrl?.StartsWith("/connect/authorize", StringComparison.OrdinalIgnoreCase) == true;

    public class InputModel
    {
        [Required(ErrorMessage = "Please enter your username.")]
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
            await _activity.WriteAsync(ActivityKind.SignInFailed, username: Input.Username, ipAddress: ip, detail: result.Error, ct: HttpContext.RequestAborted);
            ErrorMessage = result.Error ?? "Sign-in failed.";
            return Page();
        }

        // A new sign-in replaces the session this browser had (another person may have used it).
        if (User.GetSessionToken() is { } previous)
        {
            await _sessionService.InvalidateAsync(previous, HttpContext.RequestAborted);
        }

        var session = await _sessionService.CreateAsync(result.User.Id, Request.Headers.UserAgent.ToString(), ip, HttpContext.RequestAborted);
        await HttpContext.SignInAsync(
            AuthConstants.CookieScheme,
            PrincipalFactory.Build(result.User, session.Token),
            new AuthenticationProperties { IsPersistent = Input.RememberMe });
        await _activity.WriteAsync(ActivityKind.SignIn, result.User, ipAddress: ip, ct: HttpContext.RequestAborted);

        // A forced password change lands on the account page via the guard middleware (and comes back here afterwards).
        return LocalRedirect(SafeReturnUrl());
    }

    private async Task LoadAsync() => InstanceName = (await _config.GetAsync(HttpContext.RequestAborted)).InstanceName;

    private string SafeReturnUrl()
        => !string.IsNullOrEmpty(ReturnUrl) && Url.IsLocalUrl(ReturnUrl) ? ReturnUrl : "/";
}
