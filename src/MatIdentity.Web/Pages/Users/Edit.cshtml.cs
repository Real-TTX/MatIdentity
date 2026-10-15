using System.ComponentModel.DataAnnotations;
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

    public EditModel(UserService userService, SessionService sessions, TokenRevoker revoker)
    {
        _userService = userService;
        _sessions = sessions;
        _revoker = revoker;
    }

    [BindProperty]
    public InputModel Input { get; set; } = new();

    public bool IsEdit => Input.Id is > 0;

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
    }

    public async Task<IActionResult> OnGetAsync(long? id)
    {
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
                IsActive = user.IsActive
            };
        }

        return Page();
    }

    public async Task<IActionResult> OnPostAsync()
    {
        var ct = HttpContext.RequestAborted;
        if (!IsEdit && string.IsNullOrEmpty(Input.Password))
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
            await _userService.UpdateAsync(existing.Id, displayName, Input.Email, Input.Role, Input.IsActive, Input.Password, ct);

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

            await _userService.CreateAsync(Input.Username, displayName, Input.Email, Input.Password!, Input.Role, mustChangePassword: false, ct);
            StatusMessage = "Person created.";
        }

        IsError = false;
        return RedirectToPage("/Users/Index");
    }
}
