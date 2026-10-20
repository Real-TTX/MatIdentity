using System.ComponentModel.DataAnnotations;
using MatIdentity.Core.Access;
using MatIdentity.Core.Auth;
using MatIdentity.Core.Clients;
using MatIdentity.Core.Entities;
using MatIdentity.Core.Users;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace MatIdentity.Web.Pages.Users;

/// <summary>
/// Creates or changes a person. The guards: the last active administrator stays an active administrator, nobody demotes or disables themselves,
/// and a disabled account or a password set here signs the person out everywhere (sessions here, refresh tokens of the apps).
/// </summary>
public class EditModel : PageModel
{
    private readonly UserService _userService;
    private readonly SessionService _sessions;
    private readonly TokenRevoker _revoker;
    private readonly GroupService _groups;
    private readonly TwoFactorService _twoFactor;
    private readonly PasskeyService _passkeys;
    private readonly MatIdentity.Core.Activity.ActivityService _activity;
    private readonly AccountMailService _accounts;
    private readonly MatIdentity.Core.Mail.MailService _mail;
    private readonly MatIdentity.Core.Configuration.SystemConfigService _config;
    private readonly IConfiguration _configuration;

    public EditModel(UserService userService, SessionService sessions, TokenRevoker revoker, GroupService groups, TwoFactorService twoFactor, PasskeyService passkeys, MatIdentity.Core.Activity.ActivityService activity,
        AccountMailService accounts, MatIdentity.Core.Mail.MailService mail, MatIdentity.Core.Configuration.SystemConfigService config, IConfiguration configuration)
    {
        _accounts = accounts;
        _mail = mail;
        _config = config;
        _configuration = configuration;
        _twoFactor = twoFactor;
        _passkeys = passkeys;
        _activity = activity;
        _groups = groups;
        _userService = userService;
        _sessions = sessions;
        _revoker = revoker;
    }

    [BindProperty]
    public InputModel Input { get; set; } = new();

    public bool IsEdit => Input.Id is > 0;

    /// <summary>Every group, for the checkboxes.</summary>
    public IReadOnlyList<Group> AllGroups { get; private set; } = [];

    /// <summary>What the person uses as the second step (for the card that resets it).</summary>
    public bool UsesAuthenticator { get; private set; }

    public int PasskeyCount { get; private set; }

    /// <summary>Mail can be sent: invitations and password links.</summary>
    public bool MailAvailable { get; private set; }

    /// <summary>The person was invited and has not chosen a password yet.</summary>
    public bool InvitationOpen { get; private set; }

    public bool EmailVerified { get; private set; }

    /// <summary>Too many wrong attempts: until then the password does not sign the person in.</summary>
    public DateTime? LockedUntil { get; private set; }

    public int MinPasswordLength { get; private set; } = PasswordPolicy.Floor;

    /// <summary>Where the person is signed in now.</summary>
    public IReadOnlyList<UserSession> Sessions { get; private set; } = [];

    [TempData] public string? StatusMessage { get; set; }
    [TempData] public bool IsError { get; set; }

    public class InputModel
    {
        public long? Id { get; set; }

        [Required(ErrorMessage = "Please enter a username.")]
        [StringLength(128)]
        [RegularExpression(@"^[A-Za-z0-9._@-]+$", ErrorMessage = "Only letters, digits and . _ @ - are allowed.")]
        [Display(Name = "Username")]
        public string Username { get; set; } = string.Empty;

        [StringLength(256)]
        [Display(Name = "Display name")]
        public string? DisplayName { get; set; }

        [StringLength(256)]
        [EmailAddress(ErrorMessage = "Please enter a valid e-mail address.")]
        [Display(Name = "E-mail")]
        public string? Email { get; set; }

        [Display(Name = "Role")]
        public UserRole Role { get; set; } = UserRole.User;

        [Display(Name = "Active")]
        public bool IsActive { get; set; } = true;

        [MinLength(UserService.MinPasswordLength, ErrorMessage = "The password must be at least 8 characters.")]
        [DataType(DataType.Password)]
        [Display(Name = "Password")]
        public string? Password { get; set; }

        [DataType(DataType.Password)]
        [Compare(nameof(Password), ErrorMessage = "The passwords do not match.")]
        [Display(Name = "Confirm password")]
        public string? ConfirmPassword { get; set; }

        public List<long> GroupIds { get; set; } = [];

        /// <summary>A new person gets a mail and chooses the password (instead of one set here).</summary>
        public bool Invite { get; set; } = true;
    }

    public async Task<IActionResult> OnGetAsync(long? id)
    {
        AllGroups = (await _groups.GetAllAsync(HttpContext.RequestAborted)).Select(g => g.Group).ToList();
        if (id is > 0)
        {
            var user = await _userService.GetAsync(id.Value, HttpContext.RequestAborted);
            if (user is null)
            {
                return NotFound();
            }

            Input = new InputModel
            {
                Id = user.Id,
                Username = user.Username,
                DisplayName = user.DisplayName,
                Email = user.Email,
                Role = user.Role,
                IsActive = user.IsActive,
                GroupIds = await _groups.GroupIdsOfAsync(user.Id, HttpContext.RequestAborted),
            };
            UsesAuthenticator = user.TotpEnabled;
            PasskeyCount = (await _passkeys.ListAsync(user.Id, HttpContext.RequestAborted)).Count;
            EmailVerified = user.EmailVerified;
            LockedUntil = user.LockedUntil > DateTime.UtcNow ? user.LockedUntil : null;
            Sessions = await _sessions.ListActiveAsync(user.Id, HttpContext.RequestAborted);
            InvitationOpen = (await _accounts.OpenInvitationsAsync(HttpContext.RequestAborted)).Contains(user.Id);
        }

        MailAvailable = await _mail.IsAvailableAsync(HttpContext.RequestAborted);
        Input.Invite = MailAvailable;
        MinPasswordLength = (await _config.GetAsync(HttpContext.RequestAborted)).PasswordMinLength;
        return Page();
    }

    /// <summary>Ends every sign-in of the person: the sessions here and the refresh tokens of the apps (the apps with a sign-out address hear it at once).</summary>
    public async Task<IActionResult> OnPostSignOutAsync(long id)
    {
        if (await _userService.GetAsync(id, HttpContext.RequestAborted) is not { } user)
        {
            return NotFound();
        }

        var sessions = await _sessions.InvalidateAllAsync(user.Id, ct: HttpContext.RequestAborted);
        var tokens = await _revoker.RevokeForSubjectAsync(user.Subject, HttpContext.RequestAborted);
        await _activity.WriteAsync(ActivityKind.PersonChanged, username: User.GetUsername(), ipAddress: HttpContext.Connection.RemoteIpAddress?.ToString(),
            detail: $"{user.Username}: signed out everywhere ({sessions} sessions, {tokens} app sign-ins)", ct: HttpContext.RequestAborted);
        StatusMessage = $"{user.DisplayName} is signed out everywhere.";
        IsError = false;
        return user.Id == User.GetUserId() ? RedirectToPage("/Account/Login", new { signedOut = true }) : RedirectToPage(new { id });
    }

    /// <summary>Ends a lock after too many wrong attempts (the person called and it was them).</summary>
    public async Task<IActionResult> OnPostUnlockAsync(long id, [FromServices] AuthService auth)
    {
        if (await _userService.GetAsync(id, HttpContext.RequestAborted) is not { } user)
        {
            return NotFound();
        }

        await auth.ClearFailuresAsync(user.Id, HttpContext.RequestAborted);
        await _activity.WriteAsync(ActivityKind.PersonChanged, username: User.GetUsername(), ipAddress: HttpContext.Connection.RemoteIpAddress?.ToString(),
            detail: user.Username + ": unlocked", ct: HttpContext.RequestAborted);
        StatusMessage = $"{user.DisplayName} can sign in again.";
        IsError = false;
        return RedirectToPage(new { id });
    }

    /// <summary>The invitation again (a new link; the old one stops working).</summary>
    public async Task<IActionResult> OnPostInviteAsync(long id)
    {
        if (await _userService.GetAsync(id, HttpContext.RequestAborted) is not { } user)
        {
            return NotFound();
        }

        await InviteAsync(user);
        return RedirectToPage(new { id });
    }

    /// <summary>A link for a new password to the address of the person (they forgot it and asked an administrator).</summary>
    public async Task<IActionResult> OnPostSendResetAsync(long id)
    {
        if (await _userService.GetAsync(id, HttpContext.RequestAborted) is not { Email: { Length: > 0 } } user)
        {
            return NotFound();
        }

        var linkBase = await Support.Authority.GetAsync(HttpContext, _config, _configuration);
        var sent = await _accounts.RequestPasswordResetAsync(user.Username, linkBase, HttpContext.RequestAborted) is not null;
        if (sent)
        {
            await _activity.WriteAsync(ActivityKind.PasswordResetSent, username: User.GetUsername(), ipAddress: HttpContext.Connection.RemoteIpAddress?.ToString(),
                detail: user.Username, ct: HttpContext.RequestAborted);
        }

        StatusMessage = sent
            ? $"A link for a new password is on its way to {user.Email}. It works for 30 minutes."
            : $"No link was sent: the account is disabled, or it got {AccountMailService.MaxResetsPerHour} links in the last hour.";
        IsError = !sent;
        return RedirectToPage(new { id });
    }

    private async Task<bool> InviteAsync(User user)
    {
        var linkBase = await Support.Authority.GetAsync(HttpContext, _config, _configuration);
        var error = await _accounts.InviteAsync(user, linkBase, User.GetDisplayName(), HttpContext.RequestAborted);
        if (error is null)
        {
            await _activity.WriteAsync(ActivityKind.InvitationSent, username: User.GetUsername(), ipAddress: HttpContext.Connection.RemoteIpAddress?.ToString(),
                detail: user.Username, ct: HttpContext.RequestAborted);
        }

        StatusMessage = error is null ? $"The invitation is on its way to {user.Email}." : "The invitation was not sent. " + error;
        IsError = error is not null;
        return error is null;
    }

    /// <summary>The phone is lost: turns the authenticator app off and removes the passkeys, so the password alone signs the person in again.</summary>
    public async Task<IActionResult> OnPostResetSecondStepAsync(long id)
    {
        var ct = HttpContext.RequestAborted;
        if (await _userService.GetAsync(id, ct) is not { } user)
        {
            return NotFound();
        }

        await _twoFactor.DisableAsync(user.Id, ct);
        var removed = await _passkeys.DeleteAllAsync(user.Id, ct);
        await _activity.WriteAsync(ActivityKind.SecondStepReset, username: User.GetUsername(), ipAddress: HttpContext.Connection.RemoteIpAddress?.ToString(),
            detail: $"{user.Username} (authenticator app off, {removed} passkeys removed)", ct: ct);
        StatusMessage = $"The second step of {user.DisplayName} is reset: the password alone signs them in until they set up a new one.";
        IsError = false;
        return RedirectToPage(new { id });
    }

    public async Task<IActionResult> OnPostAsync()
    {
        var ct = HttpContext.RequestAborted;
        AllGroups = (await _groups.GetAllAsync(ct)).Select(g => g.Group).ToList();
        MailAvailable = await _mail.IsAvailableAsync(ct);
        MinPasswordLength = (await _config.GetAsync(ct)).PasswordMinLength;
        var invite = !IsEdit && MailAvailable && Input.Invite;
        if (invite && string.IsNullOrWhiteSpace(Input.Email))
        {
            ModelState.AddModelError("Input.Email", "The invitation goes to this address: please enter it.");
        }

        if (!IsEdit && !invite && string.IsNullOrEmpty(Input.Password))
        {
            ModelState.AddModelError("Input.Password", "Please set a password.");
        }

        if (!Enum.IsDefined(Input.Role))
        {
            ModelState.AddModelError("Input.Role", "Choose User or Admin.");
        }

        if (!string.IsNullOrWhiteSpace(Input.Email) && await _userService.EmailExistsAsync(Input.Email, Input.Id, ct))
        {
            ModelState.AddModelError("Input.Email", "Another person has this e-mail address.");
        }

        if (!string.IsNullOrEmpty(Input.Password)
            && PasswordPolicy.Check(Input.Password, (await _config.GetAsync(ct)).PasswordMinLength, Input.Username, Input.Email) is { } weak)
        {
            ModelState.AddModelError("Input.Password", weak);
        }

        var existing = IsEdit ? await _userService.GetAsync(Input.Id!.Value, ct) : null;
        if (IsEdit && existing is null)
        {
            return NotFound();
        }

        if (existing is not null)
        {
            var losesAdmin = existing.Role == UserRole.Admin && existing.IsActive && (Input.Role != UserRole.Admin || !Input.IsActive);
            if (losesAdmin && existing.Id == User.GetUserId())
            {
                ModelState.AddModelError("Input.Role", "You cannot take away your own administrator rights or disable yourself.");
            }
            else if (losesAdmin && await _userService.CountActiveAdminsAsync(ct) <= 1)
            {
                ModelState.AddModelError("Input.Role", "This is the last active administrator.");
            }
        }

        if (!ModelState.IsValid)
        {
            return Page();
        }

        var displayName = Input.DisplayName ?? string.Empty;
        if (existing is not null)
        {
            var changes = new List<string>();
            if (existing.Role != Input.Role)
            {
                changes.Add("role " + Input.Role);
            }

            if (existing.IsActive != Input.IsActive)
            {
                changes.Add(Input.IsActive ? "enabled" : "disabled");
            }

            if (!string.Equals(existing.Email ?? string.Empty, Input.Email?.Trim() ?? string.Empty, StringComparison.OrdinalIgnoreCase))
            {
                changes.Add("e-mail");
            }

            if (!string.IsNullOrEmpty(Input.Password))
            {
                changes.Add("new password");
            }

            await _userService.UpdateAsync(existing.Id, displayName, Input.Email, Input.Role, Input.IsActive, Input.Password, ct);
            await _groups.SetGroupsOfAsync(existing.Id, Input.GroupIds, ct);
            await _activity.WriteAsync(ActivityKind.PersonChanged, username: User.GetUsername(), ipAddress: HttpContext.Connection.RemoteIpAddress?.ToString(),
                detail: existing.Username + (changes.Count > 0 ? ": " + string.Join(", ", changes) : string.Empty), ct: ct);

            // A disabled account or a password set by an administrator: out everywhere.
            if (!Input.IsActive || !string.IsNullOrEmpty(Input.Password))
            {
                await _sessions.InvalidateAllAsync(existing.Id, ct: ct);
                await _revoker.RevokeForSubjectAsync(existing.Subject, ct);
            }

            StatusMessage = "Person saved.";
        }
        else
        {
            if (await _userService.UsernameExistsAsync(Input.Username.Trim(), null, ct))
            {
                ModelState.AddModelError("Input.Username", "This username is already taken.");
                return Page();
            }

            // Invited: a password nobody knows until the person chooses one with the link.
            var password = invite ? AccountMailService.UnusablePassword() : Input.Password!;
            var created = await _userService.CreateAsync(Input.Username, displayName, Input.Email, password, Input.Role, mustChangePassword: false, ct);
            await _groups.SetGroupsOfAsync(created.Id, Input.GroupIds, ct);
            await _activity.WriteAsync(ActivityKind.PersonCreated, username: User.GetUsername(), ipAddress: HttpContext.Connection.RemoteIpAddress?.ToString(),
                detail: created.Username + (created.Role == UserRole.Admin ? " (administrator)" : string.Empty), ct: ct);
            if (invite && !await InviteAsync(created))
            {
                // Created, but the mail failed: the person's page says so and offers to send it again.
                return RedirectToPage(new { id = created.Id });
            }

            StatusMessage = invite ? $"Person created. The invitation is on its way to {created.Email}." : "Person created.";
        }

        IsError = false;
        return RedirectToPage("/Users/Index");
    }
}
