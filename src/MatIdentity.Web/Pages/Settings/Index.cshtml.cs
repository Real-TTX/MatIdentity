using System.ComponentModel.DataAnnotations;
using MatIdentity.Core.Activity;
using MatIdentity.Core.Auth;
using MatIdentity.Core.Clients;
using MatIdentity.Core.Configuration;
using MatIdentity.Core.Entities;
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

    public IndexModel(SystemConfigService config, SessionService sessions, TokenRevoker revoker, ActivityService activity, ApiAccess access, IConfiguration configuration)
    {
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
        };
        AuthorityUrl = await Authority.GetAsync(HttpContext, _config, _configuration);
    }

    public async Task<IActionResult> OnPostAsync()
    {
        AuthorityUrl = await Authority.GetAsync(HttpContext, _config, _configuration);
        if (!ModelState.IsValid)
        {
            return Page();
        }

        var config = await _config.GetAsync(HttpContext.RequestAborted);
        var restart = !string.Equals(config.Issuer ?? string.Empty, Input.Issuer?.Trim().TrimEnd('/') ?? string.Empty, StringComparison.Ordinal)
                      || config.AccessTokenMinutes != Input.AccessTokenMinutes;
        config.InstanceName = Input.InstanceName;
        config.Issuer = Input.Issuer;
        config.SessionLifetimeDays = Input.SessionLifetimeDays;
        config.AccessTokenMinutes = Input.AccessTokenMinutes;

        var errors = await _config.SaveAsync(config, HttpContext.RequestAborted);
        if (errors.Count > 0)
        {
            foreach (var (field, message) in errors)
            {
                ModelState.AddModelError("Input." + char.ToUpperInvariant(field[0]) + field[1..], message);
            }

            return Page();
        }

        StatusMessage = restart ? "Settings saved. Restart MatIdentity for the address and the token lifetime to take effect." : "Settings saved.";
        return RedirectToPage();
    }

    public async Task<IActionResult> OnPostSignOutEveryoneAsync()
    {
        var (sessions, tokens) = await IdentityPlatform.SignOutEveryoneAsync(_sessions, _revoker, HttpContext.RequestAborted);
        await _activity.WriteAsync(ActivityKind.SignOut, username: User.GetUsername(), ipAddress: HttpContext.Connection.RemoteIpAddress?.ToString(),
            detail: $"Everyone signed out ({sessions} sessions, {tokens} app sign-ins)", ct: HttpContext.RequestAborted);
        // That includes this browser: the next page asks for the sign-in.
        return RedirectToPage("/Account/Login", new { signedOut = true });
    }
}
