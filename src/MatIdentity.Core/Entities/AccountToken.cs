namespace MatIdentity.Core.Entities;

/// <summary>What a link in a mail is for.</summary>
public enum AccountTokenPurpose
{
    /// <summary>"Forgot your password?": a new password (30 minutes).</summary>
    PasswordReset = 1,

    /// <summary>An administrator made the account: the person chooses the password (7 days).</summary>
    Invitation = 2,

    /// <summary>The person confirms the e-mail address (<c>email_verified</c>, 48 hours).</summary>
    EmailVerification = 3,
}

/// <summary>
/// The key behind a link in a mail. Only the SHA-256 hash of the key is stored (who reads the database cannot use a link); it works once and only until
/// <see cref="ExpiresAt"/>; a new one of the same purpose replaces the old.
/// </summary>
public class AccountToken : AuditableEntity
{
    public long UserId { get; set; }

    public User? User { get; set; }

    public AccountTokenPurpose Purpose { get; set; }

    /// <summary>SHA-256 of the key, hex.</summary>
    public string TokenHash { get; set; } = string.Empty;

    /// <summary>The address the mail went to: a link confirms only that address (it no longer counts after the address changed).</summary>
    public string? Email { get; set; }

    public DateTime ExpiresAt { get; set; }

    public DateTime? UsedAt { get; set; }
}
