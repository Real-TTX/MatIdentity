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
    private readonly IPasswordHasher _passwordHasher;

    public AuthService(MatIdentityDbContext db, IPasswordHasher passwordHasher)
    {
        _db = db;
        _passwordHasher = passwordHasher;
    }

    public async Task<AuthenticationResult> AuthenticateAsync(string username, string password, CancellationToken ct = default)
    {
        // Generic message on purpose: never reveal whether the username exists.
        const string invalidCredentials = "Incorrect username or password.";

        var user = await FindAsync(username, ct);

        // Always verify (against a dummy hash when the user is unknown) to equalize timing.
        var passwordValid = _passwordHasher.Verify(password, user?.PasswordHash ?? DummyHash);

        if (user is null || !passwordValid)
        {
            return AuthenticationResult.Failure(invalidCredentials);
        }

        // The "deactivated" hint is only shown once the password is correct, so it cannot be used to
        // enumerate usernames.
        if (!user.IsActive)
        {
            return AuthenticationResult.Failure("This account is disabled.");
        }

        user.LastLoginAt = DateTime.UtcNow;
        await _db.SaveChangesAsync(ct);

        return AuthenticationResult.Success(user);
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
