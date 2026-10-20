using System.ComponentModel.DataAnnotations;
using MatIdentity.Core.Activity;
using MatIdentity.Core.Auth;
using MatIdentity.Core.Clients;
using MatIdentity.Core.Configuration;
using MatIdentity.Core.Entities;
using MatIdentity.Core.Mail;
using MatIdentity.Core.Users;
using MatIdentity.Web.Platform;
using MatIdentity.Web.Support;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace MatIdentity.Web.Pages.Settings;

/// <summary>
/// The settings of MatIdentity: the same few values Mattiverse sets through <c>/api/configure</c>, checked by the same service, plus what an
/// administrator needs to connect apps (the addresses) and the emergency button "Sign everyone out".
/// </summary>
public class IndexModel : PageModel
{
    private readonly SystemConfigService _config;
    private readonly SessionService _sessions;
    private readonly TokenRevoker _revoker;
    private readonly ActivityService _activity;
    private readonly ApiAccess _access;
    private readonly IConfiguration _configuration;
    private readonly MailService _mail;
    private readonly UserService _users;

    public IndexModel(SystemConfigService config, SessionService sessions, TokenRevoker revoker, ActivityService activity, ApiAccess access, IConfiguration configuration, MailService mail, UserService users)
    {
        _mail = mail;
        _users = users;
        _config = config;
        _sessions = sessions;
        _revoker = revoker;
        _activity = activity;
        _access = access;
        _configuration = configuration;
    }

    [BindProperty]
    public InputModel Input { get; set; } = new();

    public string AuthorityUrl { get; private set; } = string.Empty;

    public bool ApiKeyEnabled => _access.KeyEnabled;

    /// <summary>The issuer or the token lifetime changed: OpenIddict reads them at start.</summary>
    public bool NeedsRestart { get; private set; }

    /// <summary>MatSMTP is set (Mattiverse): the mail settings are shown, not edited.</summary>
    public MailRelay Relay => _mail.Relay;

    /// <summary>A password of the own SMTP server is stored (it is never shown).</summary>
    public bool HasSmtpPassword { get; private set; }

    /// <summary>Mail can be sent now (MatSMTP or a saved server): the test button.</summary>
    public bool MailAvailable { get; private set; }

    [TempData] public string? StatusMessage { get; set; }
    [TempData] public bool IsError { get; set; }

    public class InputModel
    {
        [Required(ErrorMessage = "Please enter a name.")]
        [StringLength(80)]
        public string InstanceName { get; set; } = string.Empty;

        public string? Issuer { get; set; }

        [Range(SystemConfigService.MinSessionDays, SystemConfigService.MaxSessionDays, ErrorMessage = "Choose between 1 and 365 days.")]
        public int SessionLifetimeDays { get; set; }

        [Range(SystemConfigService.MinTokenMinutes, SystemConfigService.MaxTokenMinutes, ErrorMessage = "Choose between 5 and 1440 minutes.")]
        public int AccessTokenMinutes { get; set; }

        public string? SmtpHost { get; set; }

        [Range(1, 65535, ErrorMessage = "Choose a port between 1 and 65535.")]
        public int SmtpPort { get; set; } = 587;

        public string? SmtpUsername { get; set; }

        /// <summary>Empty keeps the stored one.</summary>
        public string? SmtpPassword { get; set; }

        public string? SmtpFrom { get; set; }

        public string SmtpTls { get; set; } = "starttls";
    }

    public async Task OnGetAsync()
    {
        var config = await _config.GetAsync(HttpContext.RequestAborted);
        Input = new InputModel
        {
            InstanceName = config.InstanceName,
            Issuer = config.Issuer,
            SessionLifetimeDays = config.SessionLifetimeDays,
            AccessTokenMinutes = config.AccessTokenMinutes,
            SmtpHost = config.SmtpHost,
            SmtpPort = config.SmtpPort,
            SmtpUsername = config.SmtpUsername,
            SmtpFrom = config.SmtpFrom,
            SmtpTls = config.SmtpTls,
        };
        HasSmtpPassword = !string.IsNullOrEmpty(config.SmtpPasswordProtected);
        MailAvailable = await _mail.IsAvailableAsync(HttpContext.RequestAborted);
        AuthorityUrl = await Authority.GetAsync(HttpContext, _config, _configuration);
    }

    public async Task<IActionResult> OnPostAsync()
    {
        AuthorityUrl = await Authority.GetAsync(HttpContext, _config, _configuration);
        HasSmtpPassword = !string.IsNullOrEmpty((await _config.GetAsync(HttpContext.RequestAborted)).SmtpPasswordProtected);
        MailAvailable = await _mail.IsAvailableAsync(HttpContext.RequestAborted);
        if (!ModelState.IsValid)
        {
            return Page();
        }

        var before = await _config.GetAsync(HttpContext.RequestAborted);
        var config = await _config.GetAsync(HttpContext.RequestAborted);
        var restart = !string.Equals(config.Issuer ?? string.Empty, Input.Issuer?.Trim().TrimEnd('/') ?? string.Empty, StringComparison.Ordinal)
                      || config.AccessTokenMinutes != Input.AccessTokenMinutes;
        config.InstanceName = Input.InstanceName;
        config.Issuer = Input.Issuer;
        config.SessionLifetimeDays = Input.SessionLifetimeDays;
        config.AccessTokenMinutes = Input.AccessTokenMinutes;
        if (!Relay.IsConfigured)
        {
            // MatSMTP fixes the mail; else the own server (an empty password keeps the stored one, an empty server switches mail off).
            config.SmtpHost = Input.SmtpHost;
            config.SmtpPort = Input.SmtpPort;
            config.SmtpUsername = Input.SmtpUsername;
            config.SmtpFrom = Input.SmtpFrom;
            config.SmtpTls = Input.SmtpTls;
            if (!string.IsNullOrEmpty(Input.SmtpPassword))
            {
                config.SmtpPasswordProtected = _mail.ProtectPassword(Input.SmtpPassword);
            }
            else if (string.IsNullOrWhiteSpace(Input.SmtpUsername))
            {
                config.SmtpPasswordProtected = null;
            }
        }

        var errors = await _config.SaveAsync(config, HttpContext.RequestAborted);
        if (errors.Count > 0)
        {
            foreach (var (field, message) in errors)
            {
                ModelState.AddModelError("Input." + char.ToUpperInvariant(field[0]) + field[1..], message);
            }

            return Page();
        }

        if (SystemConfigService.Changes(before, config) is { Count: > 0 } changed)
        {
            await _activity.WriteAsync(ActivityKind.SettingsChanged, username: User.GetUsername(), ipAddress: HttpContext.Connection.RemoteIpAddress?.ToString(),
                detail: string.Join(", ", changed), ct: HttpContext.RequestAborted);
        }

        StatusMessage = restart ? "Settings saved. Restart MatIdentity for the address and the token lifetime to take effect." : "Settings saved.";
        return RedirectToPage();
    }

    /// <summary>A test mail to the address of the signed-in administrator, through the server that is set now (saved settings).</summary>
    public async Task<IActionResult> OnPostTestMailAsync()
    {
        var me = User.GetUserId() is { } id ? await _users.GetAsync(id, HttpContext.RequestAborted) : null;
        if (string.IsNullOrEmpty(me?.Email))
        {
            StatusMessage = "Your account has no e-mail address to send the test to.";
            IsError = true;
            return RedirectToPage();
        }

        var name = (await _config.GetAsync(HttpContext.RequestAborted)).InstanceName;
        var error = await _mail.SendAsync(MailTemplates.Test(me.Email, me.DisplayName, name), HttpContext.RequestAborted);
        StatusMessage = error ?? $"A test mail is on its way to {me.Email}.";
        IsError = error is not null;
        return RedirectToPage();
    }

    public async Task<IActionResult> OnPostSignOutEveryoneAsync()
    {
        var (sessions, tokens) = await IdentityPlatform.SignOutEveryoneAsync(_sessions, _revoker, HttpContext.RequestAborted);
        await _activity.WriteAsync(ActivityKind.EveryoneSignedOut, username: User.GetUsername(), ipAddress: HttpContext.Connection.RemoteIpAddress?.ToString(),
            detail: $"({sessions} sessions, {tokens} app sign-ins)", ct: HttpContext.RequestAborted);
        // That includes this browser: the next page asks for the sign-in.
        return RedirectToPage("/Account/Login", new { signedOut = true });
    }
}
