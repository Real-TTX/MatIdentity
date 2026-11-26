namespace MatIdentity.Core.Entities;

/// <summary>
/// The look of the sign-in of one app (by its client id): when a sign-in belongs to this app, the pages of the sign-in show its name, logo, accent and background
/// instead of MatIdentity's, and with <see cref="HideIdentity"/> nothing of MatIdentity at all (MatOS: a person signs in "to MatOS", docs/ARCHITECTURE.md "Branded sign-in").
/// Set by an administrator's key or the broker that manages the app (<c>PUT /api/v1/clients/{id}</c> with <c>branding</c>); the pictures are kept here and served by
/// MatIdentity itself (<c>/branding/{clientId}/…</c>).
/// </summary>
public class ClientBranding : AuditableEntity
{
    public string ClientId { get; set; } = string.Empty;

    /// <summary>The name the pages show ("Sign in to MatOS"), the title of the tab and, with <see cref="HideIdentity"/>, the name in the mails.</summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>The accent, <c>#rrggbb</c> (lower case); null: the toolkit's default.</summary>
    public string? Accent { get; set; }

    /// <summary>No word, logo, footer, version or link of MatIdentity on the pages of the sign-in, and the app's name in the mails.</summary>
    public bool HideIdentity { get; set; }

    /// <summary><c>image/svg+xml</c> or <c>image/png</c>; null: no logo (the pages show the first letters of the name in the accent).</summary>
    public string? LogoContentType { get; set; }

    public byte[]? Logo { get; set; }

    /// <summary>The first 16 hex digits of the SHA-256 of <see cref="Logo"/>: its ETag and the version in its address.</summary>
    public string? LogoHash { get; set; }

    /// <summary><c>image/jpeg</c>, <c>image/png</c> or <c>image/webp</c>; null: a calm gradient from the accent.</summary>
    public string? BackgroundContentType { get; set; }

    public byte[]? Background { get; set; }

    public string? BackgroundHash { get; set; }
}
