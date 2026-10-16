using System.Security.Cryptography;
using System.Text;
using MatIdentity.Core.Data;
using MatIdentity.Core.Entities;
using MatIdentity.Core.Security;
using Microsoft.EntityFrameworkCore;

namespace MatIdentity.Core.Auth;

/// <summary>
/// The second step of a sign-in: the authenticator app (TOTP) and the recovery codes. Optional for everyone; who has an authenticator app or a passkey
/// is asked for it after the password (<see cref="NeedsSecondStepAsync"/>).
/// </summary>
public sealed class TwoFactorService
{
    public const int RecoveryCodeCount = 10;

    private readonly MatIdentityDbContext _db;
    private readonly ISecretProtector _protector;
    private readonly TimeProvider _time;

    public TwoFactorService(MatIdentityDbContext db, ISecretProtector protector, TimeProvider time)
    {
        _db = db;
        _protector = protector;
        _time = time;
    }

    /// <summary>A password alone is not enough for this person: they have an authenticator app or a passkey.</summary>
    public async Task<bool> NeedsSecondStepAsync(User user, CancellationToken ct = default)
        => user.TotpEnabled || await _db.Passkeys.AnyAsync(p => p.UserId == user.Id, ct);

    /// <summary>Starts setting up the authenticator app: a new secret (not yet on) for the QR code. A secret already on stays until the new one is confirmed.</summary>
    public async Task<string> BeginSetupAsync(long userId, CancellationToken ct = default)
    {
        var user = await _db.Users.FirstAsync(u => u.Id == userId, ct);
        if (user.TotpEnabled)
        {
            throw new InvalidOperationException("The authenticator app is on already; turn it off first.");
        }

        var secret = Totp.NewSecret();
        user.TotpSecret = _protector.Protect(secret);
        await _db.SaveChangesAsync(ct);
        return secret;
    }

    /// <summary>The secret being set up (for showing the QR code again after a wrong code), or null.</summary>
    public string? PendingSecret(User user)
        => !user.TotpEnabled && user.TotpSecret is { } protectedSecret ? _protector.Unprotect(protectedSecret) : null;

    /// <summary>Turns the authenticator app on when <paramref name="code"/> is right; returns the new recovery codes (shown once), or null for a wrong code.</summary>
    public async Task<IReadOnlyList<string>?> ConfirmSetupAsync(long userId, string code, CancellationToken ct = default)
    {
        var user = await _db.Users.FirstAsync(u => u.Id == userId, ct);
        if (user.TotpEnabled || user.TotpSecret is null)
        {
            return null;
        }

        var step = Totp.Verify(_protector.Unprotect(user.TotpSecret), code, _time.GetUtcNow(), lastUsedStep: 0);
        if (step is null)
        {
            return null;
        }

        user.TotpEnabled = true;
        user.TotpLastStep = step.Value;
        var codes = NewRecoveryCodes(user);
        await _db.SaveChangesAsync(ct);
        return codes;
    }

    /// <summary>Checks the code of the authenticator app or a recovery code (used up by this). True when it was right.</summary>
    public async Task<(bool Ok, bool WasRecoveryCode)> VerifyAsync(long userId, string? code, CancellationToken ct = default)
    {
        var user = await _db.Users.FirstAsync(u => u.Id == userId, ct);
        var input = (code ?? string.Empty).Trim();
        if (user.TotpEnabled && user.TotpSecret is not null)
        {
            var step = Totp.Verify(_protector.Unprotect(user.TotpSecret), input, _time.GetUtcNow(), user.TotpLastStep);
            if (step is not null)
            {
                user.TotpLastStep = step.Value;
                await _db.SaveChangesAsync(ct);
                return (true, false);
            }
        }

        var hashes = (user.RecoveryCodeHashes ?? string.Empty).Split(' ', StringSplitOptions.RemoveEmptyEntries).ToList();
        var hash = HashRecoveryCode(input);
        var match = hashes.FirstOrDefault(h => CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(h), Encoding.ASCII.GetBytes(hash)));
        if (match is not null)
        {
            hashes.Remove(match);
            user.RecoveryCodeHashes = string.Join(' ', hashes);
            await _db.SaveChangesAsync(ct);
            return (true, true);
        }

        return (false, false);
    }

    /// <summary>Turns the authenticator app off and drops the recovery codes (the person, with their password; or an administrator for a lost phone).</summary>
    public async Task DisableAsync(long userId, CancellationToken ct = default)
    {
        var user = await _db.Users.FirstAsync(u => u.Id == userId, ct);
        user.TotpEnabled = false;
        user.TotpSecret = null;
        user.TotpLastStep = 0;
        user.RecoveryCodeHashes = null;
        await _db.SaveChangesAsync(ct);
    }

    /// <summary>New recovery codes; the old ones stop working.</summary>
    public async Task<IReadOnlyList<string>> RenewRecoveryCodesAsync(long userId, CancellationToken ct = default)
    {
        var user = await _db.Users.FirstAsync(u => u.Id == userId, ct);
        var codes = NewRecoveryCodes(user);
        await _db.SaveChangesAsync(ct);
        return codes;
    }

    /// <summary>How many recovery codes are left.</summary>
    public static int RecoveryCodesLeft(User user) => (user.RecoveryCodeHashes ?? string.Empty).Split(' ', StringSplitOptions.RemoveEmptyEntries).Length;

    private static List<string> NewRecoveryCodes(User user)
    {
        // 10 characters of Base32 (50 bits each), shown as xxxxx-xxxxx; only the hash is kept.
        var codes = Enumerable.Range(0, RecoveryCodeCount).Select(_ =>
        {
            var raw = Totp.ToBase32(RandomNumberGenerator.GetBytes(7))[..10].ToLowerInvariant();
            return raw[..5] + "-" + raw[5..];
        }).ToList();
        user.RecoveryCodeHashes = string.Join(' ', codes.Select(HashRecoveryCode));
        return codes;
    }

    /// <summary>A recovery code is compared without the dash, spaces and case.</summary>
    private static string HashRecoveryCode(string code)
        => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(code.Replace("-", string.Empty).Replace(" ", string.Empty).ToLowerInvariant())));
}
