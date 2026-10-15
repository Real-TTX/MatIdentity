namespace MatIdentity.Core.Entities;

/// <summary>
/// A server-side sign-in session at MatIdentity (the single sign-on session: while it lives, an app that sends a person here gets them back
/// signed in without a form). Persisted in SQLite on the mounted data volume so that sessions survive a container restart. The <see cref="Token"/>
/// is the security key handed to the client cookie; the numeric <see cref="AuditableEntity.Id"/> is never exposed.
/// </summary>
public class UserSession : AuditableEntity
{
    /// <summary>Opaque, unguessable session token (UUID). Stored in the auth cookie.</summary>
    public string Token { get; set; } = string.Empty;

    public long UserId { get; set; }

    public User? User { get; set; }

    public DateTime ExpiresAt { get; set; }

    public DateTime LastSeenAt { get; set; }

    public string? UserAgent { get; set; }

    public string? IpAddress { get; set; }
}
