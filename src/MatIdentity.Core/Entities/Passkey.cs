namespace MatIdentity.Core.Entities;

/// <summary>
/// A passkey of a person (a WebAuthn credential: Windows Hello, Touch ID, a phone, a security key). It signs a person in without a password, or is the
/// second step after the password. MatIdentity keeps the public key only; the private key never leaves the device.
/// </summary>
public class Passkey : AuditableEntity
{
    public long UserId { get; set; }

    public User? User { get; set; }

    /// <summary>The id of the credential (Base64url), as the browser names it at the sign-in.</summary>
    public string CredentialId { get; set; } = string.Empty;

    /// <summary>The public key (COSE).</summary>
    public byte[] PublicKey { get; set; } = [];

    /// <summary>The counter of the authenticator; one that goes back means a copied key (many passkeys always send 0).</summary>
    public long SignCount { get; set; }

    /// <summary>The name a person gave it ("Laptop", "Phone").</summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>The model of the authenticator (AAGUID), when it says.</summary>
    public Guid AaGuid { get; set; }

    public DateTime? LastUsedAt { get; set; }
}
