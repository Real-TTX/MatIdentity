using MailKit.Net.Smtp;
using MailKit.Security;
using MimeKit;

namespace MatIdentity.Core.Mail;

/// <summary>Hands one mail to an SMTP server (the tests replace it).</summary>
public interface IMailTransport
{
    Task SendAsync(SmtpTarget target, OutgoingMail mail, CancellationToken ct);
}

/// <summary>MailKit: plain, STARTTLS or TLS from the start, with the user and password of the target when it has them.</summary>
public sealed class SmtpMailTransport : IMailTransport
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(20);

    public async Task SendAsync(SmtpTarget target, OutgoingMail mail, CancellationToken ct)
    {
        var message = new MimeMessage();
        message.From.Add(MailboxAddress.Parse(target.From));
        message.To.Add(new MailboxAddress(mail.ToName ?? string.Empty, mail.ToAddress));
        message.Subject = mail.Subject;
        message.Body = new TextPart("plain") { Text = mail.Text };

        using var client = new SmtpClient { Timeout = (int)Timeout.TotalMilliseconds };
        var security = target.Tls switch
        {
            MailTls.StartTls => SecureSocketOptions.StartTls,
            MailTls.Tls => SecureSocketOptions.SslOnConnect,
            _ => SecureSocketOptions.None,
        };
        await client.ConnectAsync(target.Host, target.Port, security, ct);
        if (!string.IsNullOrEmpty(target.Username))
        {
            await client.AuthenticateAsync(target.Username, target.Password ?? string.Empty, ct);
        }

        await client.SendAsync(message, ct);
        await client.DisconnectAsync(quit: true, ct);
    }
}
