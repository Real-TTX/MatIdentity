namespace MatIdentity.Core.Entities;

/// <summary>A person who can sign in to MatIdentity and, through it, to every app of the family.</summary>
public class User : AuditableEntity
{
    /// <summary>
    /// The claim <c>sub</c> the apps see (a UUID): stable for the life of the account, never the numeric <see cref="AuditableEntity.Id"/>
    /// and never the user name, which can be changed.
    /// </summary>
    public string Subject { get; set; } = string.Empty;

    public string Username { get; set; } = string.Empty;

    public string DisplayName { get; set; } = string.Empty;

    /// <summary>Optional; the apps use it to link an existing local account on the first sign-in.</summary>
    public string? Email { get; set; }

    /// <summary>PBKDF2 hash produced by <c>IPasswordHasher</c> (never the plain password).</summary>
    public string PasswordHash { get; set; } = string.Empty;

    public UserRole Role { get; set; } = UserRole.User;

    /// <summary>The person proved the address (a link in a mail to it): the claim <c>email_verified</c>. A new address is unconfirmed again.</summary>
    public bool EmailVerified { get; set; }

    public bool IsActive { get; set; } = true;

    /// <summary>Forces a password change on next login (e.g. for a seeded admin).</summary>
    public bool MustChangePassword { get; set; }

    /// <summary>Wrong passwords or codes in a row (the count starts again after a sign-in).</summary>
    public int FailedSignIns { get; set; }

    /// <summary>Until then the password does not sign the account in (too many wrong attempts in a row).</summary>
    public DateTime? LockedUntil { get; set; }

    public DateTime? LastLoginAt { get; set; }

    /// <summary>Preferred theme: system, light or dark (stored in the browser as well, so it applies before login).</summary>
    public string Theme { get; set; } = "system";

    /// <summary>The secret of the authenticator app (Base32), encrypted with Data Protection; set while setting it up and while it is on.</summary>
    public string? TotpSecret { get; set; }

    /// <summary>The authenticator app is confirmed: a sign-in with the password asks for a code.</summary>
    public bool TotpEnabled { get; set; }

    /// <summary>The last 30-second step a code was used for, so no code works twice.</summary>
    public long TotpLastStep { get; set; }

    /// <summary>The hashes (SHA-256, hex) of the unused recovery codes, separated by spaces; each one works once.</summary>
    public string? RecoveryCodeHashes { get; set; }

    public ICollection<UserSession> Sessions { get; set; } = new List<UserSession>();

    public ICollection<Passkey> Passkeys { get; set; } = new List<Passkey>();
}
