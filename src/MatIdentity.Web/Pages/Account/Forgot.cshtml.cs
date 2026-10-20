using System.ComponentModel.DataAnnotations;
using MatIdentity.Core.Activity;
using MatIdentity.Core.Configuration;
using MatIdentity.Core.Entities;
using MatIdentity.Core.Mail;
using MatIdentity.Core.Users;
using MatIdentity.Web.Support;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.RateLimiting;

namespace MatIdentity.Web.Pages.Account;

/// <summary>
/// "Forgot your password?": a link by mail. The answer is the same whether an account exists or not, and the mail goes out after it (no difference in time).
/// Offered only with mail and a public address (the link must not point to the host a request names).
/// </summary>
[AllowAnonymous]
[EnableRateLimiting(RateLimits.SignIn)]
public class ForgotModel : PageModel
{
    private readonly AccountMailService _accounts;
    private readonly MailService _mail;
    private readonly SystemConfigService _config;
    private readonly IConfiguration _configuration;
    private readonly ActivityService _activity;

    public ForgotModel(AccountMailService accounts, MailService mail, SystemConfigService config, IConfiguration configuration, ActivityService activity)
    {
        _accounts = accounts;
        _mail = mail;
        _config = config;
        _configuration = configuration;
        _activity = activity;
    }

    [BindProperty]
    [Required(ErrorMessage = "Please enter your username or e-mail.")]
    public string Login { get; set; } = string.Empty;

    [BindProperty(SupportsGet = true)]
    public string? ReturnUrl { get; set; }

    public bool Sent { get; private set; }

    public async Task<IActionResult> OnGetAsync()
        => await LinkBaseAsync(HttpContext, _mail, _config, _configuration) is null ? RedirectToPage("/Account/Login") : Page();

    public async Task<IActionResult> OnPostAsync()
    {
        if (await LinkBaseAsync(HttpContext, _mail, _config, _configuration) is not { } linkBase)
        {
            return RedirectToPage("/Account/Login");
        }

        if (!ModelState.IsValid)
        {
            return Page();
        }

        if (await _accounts.RequestPasswordResetAsync(Login, linkBase, HttpContext.RequestAborted) is { } user)
        {
            await _activity.WriteAsync(ActivityKind.PasswordResetSent, user, ipAddress: HttpContext.Connection.RemoteIpAddress?.ToString(), ct: HttpContext.RequestAborted);
        }

        Sent = true;
        return Page();
    }

    /// <summary>The address for the links of "Forgot your password?", or null when it is not offered (no mail, or no public address).</summary>
    public static async Task<string?> LinkBaseAsync(HttpContext http, MailService mail, SystemConfigService config, IConfiguration configuration)
        => await mail.IsAvailableAsync(http.RequestAborted) ? await Authority.PublicAsync(http, config, configuration) : null;
}
