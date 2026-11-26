using System.ComponentModel.DataAnnotations;
using MatIdentity.Core.Auth;
using MatIdentity.Core.Clients;
using MatIdentity.Core.Configuration;
using MatIdentity.Core.Security;
using MatIdentity.Core.Users;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace MatIdentity.Web.Pages.Account;

/// <summary>
/// The password a person must change before they go on (<c>MustChangePassword</c>, <see cref="Infrastructure.PasswordChangeGuardMiddleware"/>), as a step of
/// the sign-in: in the look of the app whose sign-in it is (SignInBranding), without MatIdentity's menu. A sign-in without a brand keeps the password tab of
/// the account (<c>/Account/Profile?tab=password</c>), so this page sends it there.
/// </summary>
public class ChangePasswordModel : PageModel
{
    private readonly UserService _users;
    private readonly SessionService _sessions;
    private readonly TokenRevoker _revoker;
    private readonly IPasswordHasher _passwordHasher;
    private readonly SystemConfigService _config;

    public ChangePasswordModel(UserService users, SessionService sessions, TokenRevoker revoker, IPasswordHasher passwordHasher, SystemConfigService config)
    {
        _users = users;
        _sessions = sessions;
        _revoker = revoker;
        _passwordHasher = passwordHasher;
        _config = config;
    }

    [BindProperty]
    public InputModel Input { get; set; } = new();

    /// <summary>The request the sign-in goes on with afterwards (an app waiting for it).</summary>
    [BindProperty(SupportsGet = true)]
    public string? ReturnUrl { get; set; }

    public int MinPasswordLength { get; private set; } = PasswordPolicy.Floor;

    public class InputModel
    {
        [Required(ErrorMessage = "Please enter your current password.")]
        public string CurrentPassword { get; set; } = string.Empty;

        [Required(ErrorMessage = "Please enter a new password.")]
        [MinLength(UserService.MinPasswordLength, ErrorMessage = "The password must be at least 8 characters.")]
        public string NewPassword { get; set; } = string.Empty;

        [Compare(nameof(NewPassword), ErrorMessage = "The passwords do not match.")]
        public string ConfirmPassword { get; set; } = string.Empty;
    }

    public async Task<IActionResult> OnGetAsync()
    {
        if (await SignInBranding.ResolveAsync(HttpContext) is null)
        {
            return LocalRedirect("/Account/Profile?tab=password" + (SafeReturnUrl() is { } back ? "&returnUrl=" + Uri.EscapeDataString(back) : string.Empty));
        }

        if (await CurrentAsync() is not { } user)
        {
            return Forbid();
        }

        if (!user.MustChangePassword)
        {
            return Redirect(SignInBranding.ContinueTo(HttpContext, SafeReturnUrl()));
        }

        MinPasswordLength = (await _config.GetAsync(HttpContext.RequestAborted)).PasswordMinLength;
        return Page();
    }

    public async Task<IActionResult> OnPostAsync()
    {
        if (await CurrentAsync() is not { } user)
        {
            return Forbid();
        }

        MinPasswordLength = (await _config.GetAsync(HttpContext.RequestAborted)).PasswordMinLength;
        if (!ModelState.IsValid)
        {
            return Page();
        }

        if (!_passwordHasher.Verify(Input.CurrentPassword, user.PasswordHash))
        {
            ModelState.AddModelError("Input.CurrentPassword", "The current password is incorrect.");
            return Page();
        }

        if (PasswordPolicy.Check(Input.NewPassword, MinPasswordLength, user.Username, user.Email) is { } weak)
        {
            ModelState.AddModelError("Input.NewPassword", weak);
            return Page();
        }

        await _users.ChangePasswordAsync(user.Id, Input.NewPassword, HttpContext.RequestAborted);
        // As on the account page: a new password ends the sign-in everywhere else.
        await _sessions.InvalidateAllAsync(user.Id, exceptToken: User.GetSessionToken(), HttpContext.RequestAborted);
        await _revoker.RevokeForSubjectAsync(user.Subject, HttpContext.RequestAborted);
        user.MustChangePassword = false;
        await SignInFlow.RenewCookieAsync(HttpContext, user);

        await SignInBranding.ResolveAsync(HttpContext);
        return Redirect(SignInBranding.ContinueTo(HttpContext, SafeReturnUrl()));
    }

    private async Task<MatIdentity.Core.Entities.User?> CurrentAsync()
        => User.GetUserId() is { } id ? await _users.GetAsync(id, HttpContext.RequestAborted) : null;

    private string? SafeReturnUrl() => !string.IsNullOrEmpty(ReturnUrl) && Url.IsLocalUrl(ReturnUrl) ? ReturnUrl : null;
}
