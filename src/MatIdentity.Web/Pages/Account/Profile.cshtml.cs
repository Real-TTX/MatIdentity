using System.ComponentModel.DataAnnotations;
using MatIdentity.Core.Auth;
using MatIdentity.Core.Clients;
using MatIdentity.Core.Configuration;
using MatIdentity.Core.Entities;
using MatIdentity.Core.Security;
using MatIdentity.Core.Users;
using MatIdentity.Web.Controls;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace MatIdentity.Web.Pages.Account;

/// <summary>The account of the signed-in person: who they are, the password, and the devices they are signed in on.</summary>
public class ProfileModel : PageModel
{
    private readonly UserService _userService;
    private readonly SessionService _sessions;
    private readonly TokenRevoker _revoker;
    private readonly IPasswordHasher _passwordHasher;
    private readonly AccountMailService _accounts;
    private readonly MatIdentity.Core.Mail.MailService _mail;
    private readonly SystemConfigService _config;
    private readonly IConfiguration _configuration;

    public ProfileModel(UserService userService, SessionService sessions, TokenRevoker revoker, IPasswordHasher passwordHasher, AccountMailService accounts, MatIdentity.Core.Mail.MailService mail, SystemConfigService config, IConfiguration configuration)
    {
        _accounts = accounts;
        _mail = mail;
        _config = config;
        _configuration = configuration;
        _userService = userService;
        _sessions = sessions;
        _revoker = revoker;
        _passwordHasher = passwordHasher;
    }

    [BindProperty]
    public InputModel Input { get; set; } = new();

    [BindProperty(SupportsGet = true)]
    public string? Tab { get; set; }

    /// <summary>Where to go after a forced password change (an app was waiting for the sign-in).</summary>
    [BindProperty(SupportsGet = true)]
    public string? ReturnUrl { get; set; }

    public string Username { get; private set; } = string.Empty;
    public string DisplayName { get; private set; } = string.Empty;
    public string? Email { get; private set; }

    public bool EmailVerified { get; private set; }

    /// <summary>A confirmation mail can be sent (an address that is not confirmed, and mail).</summary>
    public bool CanVerify { get; private set; }
    public UserRole Role { get; private set; }
    public bool MustChange { get; private set; }

    public int MinPasswordLength { get; private set; } = MatIdentity.Core.Users.PasswordPolicy.Floor;
    public IReadOnlyList<UserSession> Sessions { get; private set; } = [];
    public string? CurrentToken => User.GetSessionToken();

    [TempData] public string? StatusMessage { get; set; }

    /// <summary>general, password or sessions; the password tab when a change is required or the last submit failed.</summary>
    public string ActiveTab => MustChange || Tab == "password" || !ModelState.IsValid ? "password" : Tab == "sessions" ? "sessions" : "general";

    public TabBarModel Tabs => TabsFor(ActiveTab);

    /// <summary>The tabs of the account (this page and the security page).</summary>
    public static TabBarModel TabsFor(string active) => new()
    {
        Tabs =
        [
            new TabItem { Title = "General", Href = "/Account/Profile", Icon = "user", Active = active == "general" },
            new TabItem { Title = "Password", Href = "/Account/Profile?tab=password", Icon = "key", Active = active == "password" },
            new TabItem { Title = "Security", Href = "/Account/Security", Icon = "shield", Active = active == "security" },
            new TabItem { Title = "Devices", Href = "/Account/Profile?tab=sessions", Icon = "monitor", Active = active == "sessions" },
        ],
    };

    public class InputModel
    {
        [Required(ErrorMessage = "Please enter your current password.")]
        [DataType(DataType.Password)]
        public string CurrentPassword { get; set; } = string.Empty;

        [Required(ErrorMessage = "Please enter a new password.")]
        [MinLength(UserService.MinPasswordLength, ErrorMessage = "The password must be at least 8 characters.")]
        [DataType(DataType.Password)]
        public string NewPassword { get; set; } = string.Empty;

        [DataType(DataType.Password)]
        [Compare(nameof(NewPassword), ErrorMessage = "The passwords do not match.")]
        public string ConfirmPassword { get; set; } = string.Empty;
    }

    public async Task<IActionResult> OnGetAsync()
        => await LoadAsync() ? Page() : Forbid();

    public async Task<IActionResult> OnPostAsync()
    {
        if (!await LoadAsync())
        {
            return Forbid();
        }

        if (!ModelState.IsValid)
        {
            return Page();
        }

        var userId = User.GetUserId()!.Value;
        var user = await _userService.GetAsync(userId, HttpContext.RequestAborted);
        if (user is null)
        {
            return Forbid();
        }

        if (!_passwordHasher.Verify(Input.CurrentPassword, user.PasswordHash))
        {
            ModelState.AddModelError("Input.CurrentPassword", "The current password is incorrect.");
            return Page();
        }

        if (MatIdentity.Core.Users.PasswordPolicy.Check(Input.NewPassword, MinPasswordLength, user.Username, user.Email) is { } weak)
        {
            ModelState.AddModelError("Input.NewPassword", weak);
            return Page();
        }

        await _userService.ChangePasswordAsync(userId, Input.NewPassword, HttpContext.RequestAborted);
        // A new password ends the sign-in everywhere else (a stolen session or device is out).
        await _sessions.InvalidateAllAsync(userId, exceptToken: CurrentToken, HttpContext.RequestAborted);
        await _revoker.RevokeForSubjectAsync(user.Subject, HttpContext.RequestAborted);

        // Re-issue the cookie so the "must change password" flag is cleared immediately.
        user.MustChangePassword = false;
        await SignInFlow.RenewCookieAsync(HttpContext, user);

        StatusMessage = "Password changed. You are signed out on your other devices.";
        return !string.IsNullOrEmpty(ReturnUrl) && Url.IsLocalUrl(ReturnUrl) ? LocalRedirect(ReturnUrl) : RedirectToPage();
    }

    public async Task<IActionResult> OnPostSignOutOthersAsync()
    {
        if (User.GetUserId() is not { } userId || await _userService.GetAsync(userId, HttpContext.RequestAborted) is not { } user)
        {
            return Forbid();
        }

        var count = await _sessions.InvalidateAllAsync(userId, exceptToken: CurrentToken, HttpContext.RequestAborted);
        await _revoker.RevokeForSubjectAsync(user.Subject, HttpContext.RequestAborted);
        StatusMessage = count == 1 ? "Signed out on 1 other device." : $"Signed out on {count} other devices.";
        return RedirectToPage(new { tab = "sessions" });
    }

    /// <summary>A link to the address of the account; following it confirms the address.</summary>
    public async Task<IActionResult> OnPostSendVerificationAsync()
    {
        if (User.GetUserId() is not { } userId || await _userService.GetAsync(userId, HttpContext.RequestAborted) is not { } user)
        {
            return Forbid();
        }

        var linkBase = await Support.Authority.GetAsync(HttpContext, _config, _configuration);
        StatusMessage = await _accounts.SendVerificationAsync(user, linkBase, HttpContext.RequestAborted)
            ? $"A link is on its way to {user.Email}. It works for 48 hours."
            : "No mail could be sent.";
        return RedirectToPage();
    }

    private async Task<bool> LoadAsync()
    {
        var userId = User.GetUserId();
        if (userId is null)
        {
            return false;
        }

        var user = await _userService.GetAsync(userId.Value, HttpContext.RequestAborted);
        if (user is null)
        {
            return false;
        }

        Username = user.Username;
        DisplayName = user.DisplayName;
        Email = user.Email;
        EmailVerified = user.EmailVerified;
        CanVerify = !string.IsNullOrEmpty(user.Email) && !user.EmailVerified && await _mail.IsAvailableAsync(HttpContext.RequestAborted);
        Role = user.Role;
        MustChange = user.MustChangePassword;
        MinPasswordLength = (await _config.GetAsync(HttpContext.RequestAborted)).PasswordMinLength;
        Sessions = await _sessions.ListActiveAsync(user.Id, HttpContext.RequestAborted);
        return true;
    }
}
