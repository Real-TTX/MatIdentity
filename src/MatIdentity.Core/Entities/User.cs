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

    public bool IsActive { get; set; } = true;

    /// <summary>Forces a password change on next login (e.g. for a seeded admin).</summary>
    public bool MustChangePassword { get; set; }

    public DateTime? LastLoginAt { get; set; }

    /// <summary>Preferred theme: system, light or dark (stored in the browser as well, so it applies before login).</summary>
    public string Theme { get; set; } = "system";

    public ICollection<UserSession> Sessions { get; set; } = new List<UserSession>();
}
