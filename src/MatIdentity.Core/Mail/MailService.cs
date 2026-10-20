using System.Threading.Channels;
using MatIdentity.Core.Configuration;
using MatIdentity.Core.Security;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace MatIdentity.Core.Mail;

/// <summary>
/// The mail of MatIdentity (password reset, invitations, e-mail verification): through MatSMTP when the environment names it, else through the SMTP server
/// of the settings, else none, and the features that need mail are hidden. The password of the own server is kept encrypted (Data Protection).
/// </summary>
public sealed class MailService
{
    private readonly MailRelay _relay;
    private readonly SystemConfigService _config;
    private readonly ISecretProtector _protector;
    private readonly IMailTransport _transport;
    private readonly ILogger<MailService> _logger;

    public MailService(MailRelay relay, SystemConfigService config, ISecretProtector protector, IMailTransport transport, ILogger<MailService> logger)
    {
        _relay = relay;
        _config = config;
        _protector = protector;
        _transport = transport;
        _logger = logger;
    }

    /// <summary>MatSMTP is set: the own settings are fixed.</summary>
    public MailRelay Relay => _relay;

    /// <summary>Where mail goes now, or null (no MatSMTP, no own server).</summary>
    public async Task<SmtpTarget?> TargetAsync(CancellationToken ct = default)
    {
        if (_relay.Target is { } relay)
        {
            return relay;
        }

        var config = await _config.GetAsync(ct);
        if (string.IsNullOrWhiteSpace(config.SmtpHost) || string.IsNullOrWhiteSpace(config.SmtpFrom))
        {
            return null;
        }

        string? password = null;
        if (!string.IsNullOrEmpty(config.SmtpPasswordProtected))
        {
            try
            {
                password = _protector.Unprotect(config.SmtpPasswordProtected);
            }
            catch (System.Security.Cryptography.CryptographicException)
            {
                _logger.LogWarning("The password of the SMTP server cannot be read (the keys changed); enter it again in the settings.");
            }
        }

        return new SmtpTarget(config.SmtpHost.Trim(), config.SmtpPort, string.IsNullOrWhiteSpace(config.SmtpUsername) ? null : config.SmtpUsername.Trim(),
            password, config.SmtpFrom.Trim(), SmtpTarget.Parse(config.SmtpTls) ?? MailTls.StartTls, Fixed: false);
    }

    /// <summary>Mail can be sent: the pages offer what needs it.</summary>
    public async Task<bool> IsAvailableAsync(CancellationToken ct = default) => await TargetAsync(ct) is not null;

    /// <summary>Sends now; null when it went out, else the reason in words (never a password).</summary>
    public async Task<string?> SendAsync(OutgoingMail mail, CancellationToken ct = default)
    {
        if (await TargetAsync(ct) is not { } target)
        {
            return "No mail server is set.";
        }

        try
        {
            await _transport.SendAsync(target, mail, ct);
            return null;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning(ex, "A mail to {Address} could not be sent through {Host}:{Port}", mail.ToAddress, target.Host, target.Port);
            return $"The mail could not be sent through {target.Host}:{target.Port}: {ex.Message}";
        }
    }

    /// <summary>The password of the own server as it is stored (encrypted), or null.</summary>
    public string? ProtectPassword(string? plain) => string.IsNullOrEmpty(plain) ? null : _protector.Protect(plain);
}

/// <summary>
/// Mail that goes out after the answer (a password reset must not take longer for an existing account than for an unknown one): a queue in memory,
/// sent by <see cref="MailQueueWorker"/>. A mail that fails is written to the log; the person asks again.
/// </summary>
public sealed class MailQueue
{
    private readonly Channel<OutgoingMail> _channel = Channel.CreateBounded<OutgoingMail>(new BoundedChannelOptions(500) { FullMode = BoundedChannelFullMode.DropWrite });

    public void Enqueue(OutgoingMail mail) => _channel.Writer.TryWrite(mail);

    internal ChannelReader<OutgoingMail> Reader => _channel.Reader;
}

/// <summary>Sends the mail of <see cref="MailQueue"/>, one after another.</summary>
public sealed class MailQueueWorker : BackgroundService
{
    private readonly MailQueue _queue;
    private readonly MailService _mail;

    public MailQueueWorker(MailQueue queue, MailService mail)
    {
        _queue = queue;
        _mail = mail;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            await foreach (var mail in _queue.Reader.ReadAllAsync(stoppingToken))
            {
                await _mail.SendAsync(mail, stoppingToken);
            }
        }
        catch (OperationCanceledException)
        {
            // Stopping.
        }
    }
}
