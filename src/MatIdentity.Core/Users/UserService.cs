using MatIdentity.Core.Data;
using MatIdentity.Core.Entities;
using MatIdentity.Core.Security;
using Microsoft.EntityFrameworkCore;

namespace MatIdentity.Core.Users;

/// <summary>CRUD and password management for the people of MatIdentity.</summary>
public sealed class UserService
{
    public const int MinPasswordLength = 8;

    private readonly MatIdentityDbContext _db;
    private readonly IPasswordHasher _passwordHasher;

    public UserService(MatIdentityDbContext db, IPasswordHasher passwordHasher)
    {
        _db = db;
        _passwordHasher = passwordHasher;
    }

    public Task<List<User>> GetAllAsync(CancellationToken ct = default)
        => _db.Users.AsNoTracking().OrderBy(u => u.Username).ToListAsync(ct);

    public Task<User?> GetAsync(long id, CancellationToken ct = default)
        => _db.Users.FirstOrDefaultAsync(u => u.Id == id, ct);

    /// <summary>The person behind the claim <c>sub</c> of a token.</summary>
    public Task<User?> GetBySubjectAsync(string subject, CancellationToken ct = default)
        => _db.Users.FirstOrDefaultAsync(u => u.Subject == subject, ct);

    public Task<User?> GetByUsernameAsync(string username, CancellationToken ct = default)
        => _db.Users.FirstOrDefaultAsync(u => u.Username == username, ct);

    public Task<bool> UsernameExistsAsync(string username, long? excludeId = null, CancellationToken ct = default)
        => _db.Users.AnyAsync(u => u.Username == username && (excludeId == null || u.Id != excludeId), ct);

    /// <summary>True when another person has this e-mail address (an app links accounts by it, so it must be unique; case does not matter).</summary>
    public async Task<bool> EmailExistsAsync(string email, long? excludeId = null, CancellationToken ct = default)
    {
        var normalized = email.Trim().ToLowerInvariant();
        return await _db.Users.AnyAsync(u => u.Email != null && u.Email.ToLower() == normalized && (excludeId == null || u.Id != excludeId), ct);
    }

    public async Task<User> CreateAsync(string username, string displayName, string? email, string password, UserRole role, bool mustChangePassword = false, CancellationToken ct = default)
    {
        var user = new User
        {
            Subject = Guid.NewGuid().ToString(),
            Username = username.Trim(),
            DisplayName = string.IsNullOrWhiteSpace(displayName) ? username.Trim() : displayName.Trim(),
            Email = NormalizeEmail(email),
            PasswordHash = _passwordHasher.Hash(password),
            Role = role,
            IsActive = true,
            MustChangePassword = mustChangePassword
        };

        _db.Users.Add(user);
        await _db.SaveChangesAsync(ct);
        return user;
    }

    public async Task<bool> UpdateAsync(long id, string displayName, string? email, UserRole role, bool isActive, string? newPassword, CancellationToken ct = default)
    {
        var user = await _db.Users.FirstOrDefaultAsync(u => u.Id == id, ct);
        if (user is null)
        {
            return false;
        }

        user.DisplayName = string.IsNullOrWhiteSpace(displayName) ? user.Username : displayName.Trim();
        var newEmail = NormalizeEmail(email);
        if (!string.Equals(user.Email, newEmail, StringComparison.OrdinalIgnoreCase))
        {
            // A new address is unconfirmed until its owner follows a link to it.
            user.EmailVerified = false;
        }

        user.Email = newEmail;
        user.Role = role;
        user.IsActive = isActive;
        if (isActive)
        {
            // An administrator who enables a registration confirms it.
            user.PendingRegistration = false;
        }

        if (!string.IsNullOrEmpty(newPassword))
        {
            user.PasswordHash = _passwordHasher.Hash(newPassword);
            user.MustChangePassword = false;
            user.FailedSignIns = 0;
            user.LockedUntil = null;
        }

        await _db.SaveChangesAsync(ct);
        return true;
    }

    public async Task<bool> DeleteAsync(long id, CancellationToken ct = default)
    {
        var user = await _db.Users.FirstOrDefaultAsync(u => u.Id == id, ct);
        if (user is null)
        {
            return false;
        }

        _db.Users.Remove(user); // soft delete
        await _db.SaveChangesAsync(ct);
        return true;
    }

    /// <summary>Sets a new password and clears the "must change" flag.</summary>
    public async Task<bool> ChangePasswordAsync(long id, string newPassword, CancellationToken ct = default)
    {
        var user = await _db.Users.FirstOrDefaultAsync(u => u.Id == id, ct);
        if (user is null)
        {
            return false;
        }

        user.PasswordHash = _passwordHasher.Hash(newPassword);
        user.MustChangePassword = false;
        user.FailedSignIns = 0;
        user.LockedUntil = null;
        await _db.SaveChangesAsync(ct);
        return true;
    }

    /// <summary>An account a person made themselves: disabled until the address is confirmed (<see cref="ActivateRegistrationAsync"/>).</summary>
    public async Task<User> RegisterAsync(string username, string displayName, string email, string password, CancellationToken ct = default)
    {
        var user = await CreateAsync(username, displayName, email, password, UserRole.User, mustChangePassword: false, ct);
        user.IsActive = false;
        user.PendingRegistration = true;
        await _db.SaveChangesAsync(ct);
        return user;
    }

    /// <summary>The address of a registration is confirmed: the account works.</summary>
    public async Task ActivateRegistrationAsync(long id, CancellationToken ct = default)
    {
        if (await _db.Users.FirstOrDefaultAsync(u => u.Id == id && u.PendingRegistration, ct) is { } user)
        {
            user.PendingRegistration = false;
            user.IsActive = true;
            await _db.SaveChangesAsync(ct);
        }
    }

    /// <summary>Removes registrations whose address was not confirmed within <paramref name="days"/> days. Returns how many.</summary>
    public async Task<int> PruneUnconfirmedAsync(int days, CancellationToken ct = default)
    {
        var limit = DateTime.UtcNow.AddDays(-days);
        var stale = await _db.Users.Where(u => u.PendingRegistration && u.CreateDate < limit).ToListAsync(ct);
        _db.Users.RemoveRange(stale);
        await _db.SaveChangesAsync(ct);
        return stale.Count;
    }

    /// <summary>The person proved the address (a link in a mail to it).</summary>
    public async Task SetEmailVerifiedAsync(long id, CancellationToken ct = default)
    {
        if (await _db.Users.FirstOrDefaultAsync(u => u.Id == id, ct) is { } user)
        {
            user.EmailVerified = true;
            await _db.SaveChangesAsync(ct);
        }
    }

    /// <summary>Stores the preferred theme (<c>system</c>, <c>light</c> or <c>dark</c>) of a user. Returns the user, or <c>null</c> if it does not exist.</summary>
    public async Task<User?> SetThemeAsync(long id, string theme, CancellationToken ct = default)
    {
        if (theme is not ("system" or "light" or "dark"))
        {
            throw new ArgumentException("Unknown theme: " + theme, nameof(theme));
        }

        var user = await _db.Users.FirstOrDefaultAsync(u => u.Id == id, ct);
        if (user is null)
        {
            return null;
        }

        user.Theme = theme;
        await _db.SaveChangesAsync(ct);
        return user;
    }

    public Task<int> CountAsync(CancellationToken ct = default)
        => _db.Users.CountAsync(ct);

    /// <summary>The number of active administrators: the last one cannot be demoted, disabled or deleted.</summary>
    public Task<int> CountActiveAdminsAsync(CancellationToken ct = default)
        => _db.Users.CountAsync(u => u.Role == UserRole.Admin && u.IsActive, ct);

    private static string? NormalizeEmail(string? email)
        => string.IsNullOrWhiteSpace(email) ? null : email.Trim();
}
