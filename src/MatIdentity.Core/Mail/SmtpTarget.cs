namespace MatIdentity.Core.Mail;

/// <summary>How the connection to the SMTP server is secured.</summary>
public enum MailTls
{
    /// <summary>Plain (inside the Docker network, MatSMTP's relay users may authenticate so).</summary>
    None,

    /// <summary>Plain connection, then <c>STARTTLS</c> (port 587).</summary>
    StartTls,

    /// <summary>TLS from the first byte (port 465).</summary>
    Tls,
}

/// <summary>Where the mail goes: MatSMTP (set by Mattiverse, <see cref="Fixed"/>) or the SMTP server of the settings.</summary>
public sealed record SmtpTarget(string Host, int Port, string? Username, string? Password, string From, MailTls Tls, bool Fixed)
{
    /// <summary>The words of the setting and of <c>MATSMTP_TLS</c>.</summary>
    public static string Name(MailTls tls) => tls switch
    {
        MailTls.StartTls => "starttls",
        MailTls.Tls => "tls",
        _ => "none",
    };

    /// <summary><c>none</c>, <c>starttls</c>, <c>tls</c> in any case; anything else is null.</summary>
    public static MailTls? Parse(string? value) => value?.Trim().ToLowerInvariant() switch
    {
        "none" => MailTls.None,
        "starttls" => MailTls.StartTls,
        "tls" => MailTls.Tls,
        _ => null,
    };
}

/// <summary>
/// MatSMTP, when the environment names it (<c>MATSMTP_*</c>, MatDesign docs/PLATFORM.md "Mail through MatSMTP"): then all mail goes there and the own SMTP
/// settings are fixed. The web project fills it from MatPlatform's <c>MatSmtpSettings</c>.
/// </summary>
public sealed class MailRelay
{
    public SmtpTarget? Target { get; init; }

    /// <summary>One sentence for the settings: where the mail goes, never the password.</summary>
    public string? Description { get; init; }

    public bool IsConfigured => Target is not null;
}

/// <summary>A mail to one person (plain text).</summary>
public sealed record OutgoingMail(string ToAddress, string? ToName, string Subject, string Text);
