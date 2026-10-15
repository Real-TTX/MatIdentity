namespace MatIdentity.Core.Entities;

/// <summary>
/// One line of the activity list: who signed in where, which machine got a token, what changed on a client. Written once, never changed.
/// It holds names, never a password, a secret or a token.
/// </summary>
public class ActivityEntry : AuditableEntity
{
    public ActivityKind Kind { get; set; }

    /// <summary>The person, when there is one (the name as it was then, so the line stays readable after a rename or a delete).</summary>
    public long? UserId { get; set; }

    public string? Username { get; set; }

    /// <summary>The client (app) involved, by its client id.</summary>
    public string? ClientId { get; set; }

    public string? IpAddress { get; set; }

    /// <summary>A short text for a person ("Wrong password", "Redirect address added").</summary>
    public string? Detail { get; set; }
}
