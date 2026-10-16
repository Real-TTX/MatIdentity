using MatIdentity.Core.Auth;
using MatIdentity.Core.Configuration;
using MatIdentity.Core.Entities;
using MatIdentity.Core.Security;
using MatIdentity.Core.Users;
using MatIdentity.Web.Controls;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using QRCoder;

namespace MatIdentity.Web.Pages.Account;

/// <summary>
/// The second step of a person's own sign-in: the authenticator app (set up with a QR code, confirmed with a first code), the recovery codes (shown once,
/// on the page of the POST itself, never stored in plain text) and the passkeys. Turning something off asks for the password.
/// </summary>
public class SecurityModel : PageModel
{
    private readonly TwoFactorService _twoFactor;
    private readonly UserService _users;
    private readonly IPasswordHasher _hasher;
    private readonly SystemConfigService _config;
    private readonly PasskeyService _passkeys;

    public SecurityModel(TwoFactorService twoFactor, UserService users, IPasswordHasher hasher, SystemConfigService config, PasskeyService passkeys)
    {
        _twoFactor = twoFactor;
        _users = users;
        _hasher = hasher;
        _config = config;
        _passkeys = passkeys;
    }

    public User Me { get; private set; } = default!;

    /// <summary>The secret being set up (the QR code and the text for typing it in), or null.</summary>
    public string? SetupSecret { get; private set; }

    /// <summary>The picture of the QR code as a data address (SVG), or null.</summary>
    public string? SetupQr { get; private set; }

    /// <summary>The recovery codes made by this request, shown once.</summary>
    public IReadOnlyList<string>? NewRecoveryCodes { get; private set; }

    public int RecoveryCodesLeft { get; private set; }

    public IReadOnlyList<Passkey> Passkeys { get; private set; } = [];

    public string? ErrorMessage { get; private set; }

    [TempData] public string? StatusMessage { get; set; }

    public TabBarModel Tabs => ProfileModel.TabsFor("security");

    public async Task<IActionResult> OnGetAsync(bool setup = false)
    {
        if (!await LoadAsync())
        {
            return Forbid();
        }

        if (setup && !Me.TotpEnabled)
        {
            await ShowSetupAsync(_twoFactor.PendingSecret(Me));
        }

        return Page();
    }

    public async Task<IActionResult> OnPostBeginAsync()
    {
        if (!await LoadAsync() || Me.TotpEnabled)
        {
            return RedirectToPage();
        }

        await _twoFactor.BeginSetupAsync(Me.Id, HttpContext.RequestAborted);
        return RedirectToPage(new { setup = true });
    }

    public async Task<IActionResult> OnPostConfirmAsync(string? code)
    {
        if (!await LoadAsync())
        {
            return Forbid();
        }

        var codes = await _twoFactor.ConfirmSetupAsync(Me.Id, code ?? string.Empty, HttpContext.RequestAborted);
        if (codes is null)
        {
            ErrorMessage = "This code is not right. Scan the QR code again and enter the code the app shows now.";
            await ShowSetupAsync(_twoFactor.PendingSecret(Me));
            return Page();
        }

        await LoadAsync();
        NewRecoveryCodes = codes;
        return Page();
    }

    public async Task<IActionResult> OnPostDisableAsync(string? password)
    {
        if (!await LoadAsync())
        {
            return Forbid();
        }

        if (!_hasher.Verify(password ?? string.Empty, Me.PasswordHash))
        {
            ErrorMessage = "The password is not right; the authenticator app stays on.";
            return Page();
        }

        await _twoFactor.DisableAsync(Me.Id, HttpContext.RequestAborted);
        StatusMessage = "The authenticator app is off.";
        return RedirectToPage();
    }

    public async Task<IActionResult> OnPostRenewCodesAsync(string? password)
    {
        if (!await LoadAsync())
        {
            return Forbid();
        }

        if (!_hasher.Verify(password ?? string.Empty, Me.PasswordHash))
        {
            ErrorMessage = "The password is not right; the recovery codes stay as they are.";
            return Page();
        }

        NewRecoveryCodes = await _twoFactor.RenewRecoveryCodesAsync(Me.Id, HttpContext.RequestAborted);
        await LoadAsync();
        return Page();
    }

    public async Task<IActionResult> OnPostDeletePasskeyAsync(long id)
    {
        if (!await LoadAsync())
        {
            return Forbid();
        }

        if (await _passkeys.DeleteAsync(Me.Id, id, HttpContext.RequestAborted) is { } name)
        {
            StatusMessage = $"The passkey \"{name}\" is removed.";
        }

        return RedirectToPage();
    }

    private async Task ShowSetupAsync(string? secret)
    {
        if (secret is null)
        {
            return;
        }

        SetupSecret = secret;
        var issuer = (await _config.GetAsync(HttpContext.RequestAborted)).InstanceName;
        using var generator = new QRCodeGenerator();
        using var data = generator.CreateQrCode(Totp.KeyUri(issuer, Me.Username, secret), QRCodeGenerator.ECCLevel.M);
        var svg = new SvgQRCode(data).GetGraphic(6);
        SetupQr = "data:image/svg+xml;base64," + Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(svg));
    }

    /// <summary>The secret in groups of four, easier to type into an app by hand.</summary>
    public static string Grouped(string secret) => string.Join(' ', secret.Chunk(4).Select(c => new string(c)));

    private async Task<bool> LoadAsync()
    {
        if (User.GetUserId() is not { } id || await _users.GetAsync(id, HttpContext.RequestAborted) is not { } user)
        {
            return false;
        }

        Me = user;
        RecoveryCodesLeft = TwoFactorService.RecoveryCodesLeft(user);
        Passkeys = await _passkeys.ListAsync(user.Id, HttpContext.RequestAborted);
        return true;
    }
}
