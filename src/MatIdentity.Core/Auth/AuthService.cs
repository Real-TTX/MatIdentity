using MatIdentity.Core.Entities;
using MatIdentity.Core.Data;
using MatIdentity.Core.Security;
using Microsoft.EntityFrameworkCore;

namespace MatIdentity.Core.Auth;

/// <summary>Validates local username/password credentials.</summary>
public sealed class AuthService
{
    // Valid-format hash of "nothing useful": lets us always run one PBKDF2 verification even when the
    // user does not exist, so response timing does not reveal whether a username is valid.
    private const string DummyHash =
        "pbkdf2$sha256$210000$AAAAAAAAAAAAAAAAAAAAAA==$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    private readonly MatIdentityDbContext _db;
    /// <summary>Wrong passwords or codes in a row before the password sign-in of an account is locked.</summary>
    public const int MaxFailedAttempts = 10;

    public static readonly TimeSpan LockoutDuration = TimeSpan.FromMinutes(15);

    private readonly IPasswordHasher _passwordHasher;
    private readonly TimeProvider _time;

    public AuthService(MatIdentityDbContext db, IPasswordHasher passwordHasher, TimeProvider time)
    {
        _db = db;
        _passwordHasher = passwordHasher;
        _time = time;
    }

    public async Task<AuthenticationResult> AuthenticateAsync(string username, string password, CancellationToken ct = default)
    {
        // Generic message on purpose: never reveal whether the username exists.
        const string invalidCredentials = "Incorrect username or password.";

        var user = await FindAsync(username, ct);

        // Always verify (against a dummy hash when the user is unknown) to equalize timing.
        var passwordValid = _passwordHasher.Verify(password, user?.PasswordHash ?? DummyHash);

        // Locked after too many wrong attempts: the same answer as a wrong password (a right one must not show through), for a quarter of an hour.
        if (user?.LockedUntil > _time.GetUtcNow().UtcDateTime)
        {
            return AuthenticationResult.Failure(invalidCredentials, wasLocked: true);
        }

        if (user is null || !passwordValid)
        {
            return AuthenticationResult.Failure(invalidCredentials, lockedNow: user is not null && await RegisterFailureAsync(user, ct));
        }

        // The "deactivated" hint is only shown once the password is correct, so it cannot be used to
        // enumerate usernames.
        if (!user.IsActive)
        {
            return AuthenticationResult.Failure(user.PendingRegistration ? "Confirm your e-mail address first: the link is in your mail." : "This account is disabled.");
        }

        user.LastLoginAt = DateTime.UtcNow;
        await _db.SaveChangesAsync(ct);

        return AuthenticationResult.Success(user);
    }

    /// <summary>
    /// Counts a wrong password or a wrong code of the second step; the <see cref="MaxFailedAttempts"/>th in a row locks the password sign-in of the account for
    /// <see cref="LockoutDuration"/> (a passkey alone still works: it is two factors itself). True when this attempt locked it.
    /// </summary>
    public async Task<bool> RegisterFailureAsync(User user, CancellationToken ct = default)
    {
        user.FailedSignIns++;
        var locked = user.FailedSignIns >= MaxFailedAttempts;
        if (locked)
        {
            user.LockedUntil = _time.GetUtcNow().UtcDateTime.Add(LockoutDuration);
            user.FailedSignIns = 0;
        }

        await _db.SaveChangesAsync(ct);
        return locked;
    }

    /// <summary>A sign-in succeeded, an administrator unlocked the account or a password was set by link: the count starts again.</summary>
    public async Task ClearFailuresAsync(long userId, CancellationToken ct = default)
    {
        if (await _db.Users.FirstOrDefaultAsync(u => u.Id == userId, ct) is { } user && (user.FailedSignIns != 0 || user.LockedUntil is not null))
        {
            user.FailedSignIns = 0;
            user.LockedUntil = null;
            await _db.SaveChangesAsync(ct);
        }
    }

    /// <summary>
    /// The person behind what was typed into the field "Username": the user name as it is written, else the one user name or e-mail address that matches it
    /// without regard to case (both are unique that way in practice; when two match, neither is guessed).
    /// </summary>
    public async Task<User?> FindAsync(string login, CancellationToken ct = default)
    {
        var typed = (login ?? string.Empty).Trim();
        if (typed.Length == 0)
        {
            return null;
        }

        if (await _db.Users.FirstOrDefaultAsync(u => u.Username == typed, ct) is { } exact)
        {
            return exact;
        }

        var lower = typed.ToLowerInvariant();
        var matches = await _db.Users.Where(u => u.Username.ToLower() == lower || (u.Email != null && u.Email.ToLower() == lower)).Take(2).ToListAsync(ct);
        return matches.Count == 1 ? matches[0] : null;
    }
}
