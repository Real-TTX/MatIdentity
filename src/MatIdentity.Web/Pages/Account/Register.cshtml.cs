using System.ComponentModel.DataAnnotations;
using MatIdentity.Core.Activity;
using MatIdentity.Core.Configuration;
using MatIdentity.Core.Entities;
using MatIdentity.Core.Mail;
using MatIdentity.Core.Users;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.RateLimiting;

namespace MatIdentity.Web.Pages.Account;

/// <summary>
/// A person makes their own account, when an administrator allows it (Settings, off by default) and mail and the public address are set. The account works
/// once the address is confirmed; it gets the apps that are open to everyone and nothing else until it is given more.
/// </summary>
[AllowAnonymous]
[EnableRateLimiting(RateLimits.SignIn)]
public class RegisterModel : PageModel
{
    /// <summary>Accounts whose address is not confirmed within this many days are removed at the next start.</summary>
    public const int ConfirmDays = 7;

    private readonly AccountMailService _accounts;
    private readonly UserService _users;
    private readonly MailService _mail;
    private readonly SystemConfigService _config;
    private readonly IConfiguration _configuration;
    private readonly ActivityService _activity;

    public RegisterModel(AccountMailService accounts, UserService users, MailService mail, SystemConfigService config, IConfiguration configuration, ActivityService activity)
    {
        _accounts = accounts;
        _users = users;
        _mail = mail;
        _config = config;
        _configuration = configuration;
        _activity = activity;
    }

    [BindProperty]
    public InputModel Input { get; set; } = new();

    public bool Done { get; private set; }

    public int MinPasswordLength { get; private set; } = PasswordPolicy.Floor;

    public class InputModel
    {
        [Required(ErrorMessage = "Please choose a username.")]
        [StringLength(128)]
        [RegularExpression(@"^[A-Za-z0-9._@-]+$", ErrorMessage = "Only letters, digits and . _ @ - are allowed.")]
        public string Username { get; set; } = string.Empty;

        [StringLength(256)]
        public string? DisplayName { get; set; }

        [Required(ErrorMessage = "Please enter your e-mail address.")]
        [StringLength(256)]
        [EmailAddress(ErrorMessage = "Please enter a valid e-mail address.")]
        public string Email { get; set; } = string.Empty;

        [Required(ErrorMessage = "Please choose a password.")]
        public string Password { get; set; } = string.Empty;

        [Compare(nameof(Password), ErrorMessage = "The passwords do not match.")]
        public string ConfirmPassword { get; set; } = string.Empty;
    }

    public async Task<IActionResult> OnGetAsync()
        => await LinkBaseAsync() is null ? RedirectToPage("/Account/Login") : Page();

    public async Task<IActionResult> OnPostAsync()
    {
        var ct = HttpContext.RequestAborted;
        if (await LinkBaseAsync() is not { } linkBase)
        {
            return RedirectToPage("/Account/Login");
        }

        if (PasswordPolicy.Check(Input.Password, MinPasswordLength, Input.Username, Input.Email) is { } weak)
        {
            ModelState.AddModelError("Input.Password", weak);
        }

        if (!string.IsNullOrWhiteSpace(Input.Username) && await _users.UsernameExistsAsync(Input.Username.Trim(), null, ct))
        {
            ModelState.AddModelError("Input.Username", "This username is taken. Choose another one.");
        }

        if (!ModelState.IsValid)
        {
            return Page();
        }

        var displayName = string.IsNullOrWhiteSpace(Input.DisplayName) ? Input.Username.Trim() : Input.DisplayName.Trim();
        if (await _accounts.RegisterAsync(Input.Username.Trim(), displayName, Input.Email.Trim(), Input.Password, linkBase, ct) is { } user)
        {
            await _activity.WriteAsync(ActivityKind.PersonCreated, user, ipAddress: HttpContext.Connection.RemoteIpAddress?.ToString(), detail: user.Username + " (registered, not confirmed)", ct: ct);
        }

        // The same answer when the address is known already: nobody learns which addresses have an account.
        Done = true;
        return Page();
    }

    /// <summary>The address for the confirmation link, or null when registration is not offered.</summary>
    private async Task<string?> LinkBaseAsync()
    {
        var config = await _config.GetAsync(HttpContext.RequestAborted);
        MinPasswordLength = config.PasswordMinLength;
        return config.AllowRegistration ? await ForgotModel.LinkBaseAsync(HttpContext, _mail, _config, _configuration) : null;
    }

    /// <summary>Registration is offered (for the link on the sign-in page).</summary>
    public static async Task<bool> OfferedAsync(HttpContext http, MailService mail, SystemConfigService config, IConfiguration configuration)
        => (await config.GetAsync(http.RequestAborted)).AllowRegistration && await ForgotModel.LinkBaseAsync(http, mail, config, configuration) is not null;
}
