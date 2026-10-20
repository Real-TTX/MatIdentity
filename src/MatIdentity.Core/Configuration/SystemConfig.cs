namespace MatIdentity.Core.Configuration;

/// <summary>
/// What an administrator sets at runtime (<c>config/system.json</c>): the few settings that are also offered to Mattiverse through
/// <c>/api/configure</c> (docs/PLATFORM.md).
/// </summary>
public sealed class SystemConfig
{
    public const string FileName = "system";

    /// <summary>The name in the menu, the title of the pages and of the sign-in card.</summary>
    public string InstanceName { get; set; } = "MatIdentity";

    /// <summary>The public address (the <c>iss</c> of the tokens). Empty: <see cref="MatIdentityOptions.Issuer"/>, else the address of the request.</summary>
    public string? Issuer { get; set; }

    /// <summary>How long a sign-in at MatIdentity lasts without activity, in days (the single sign-on session).</summary>
    public int SessionLifetimeDays { get; set; } = 14;

    /// <summary>How long an access token is valid, in minutes. Short, because an app renews it with the refresh token.</summary>
    public int AccessTokenMinutes { get; set; } = 30;

    /// <summary>The own SMTP server (used when MatSMTP is not set); empty: no mail, unless MatSMTP is there.</summary>
    public string? SmtpHost { get; set; }

    public int SmtpPort { get; set; } = 587;

    public string? SmtpUsername { get; set; }

    /// <summary>The password of the SMTP user, encrypted with Data Protection (never in plain text).</summary>
    public string? SmtpPasswordProtected { get; set; }

    /// <summary>The sender of every mail (<c>id@example.com</c>).</summary>
    public string? SmtpFrom { get; set; }

    /// <summary><c>none</c>, <c>starttls</c> or <c>tls</c>.</summary>
    public string SmtpTls { get; set; } = "starttls";
}
