using System.Collections.Concurrent;
using MatIdentity.Core.Mail;

namespace MatIdentity.Tests;

/// <summary>The mail of the site in memory: kept here instead of being sent (the tests read the links in it).</summary>
public sealed class RecordingMailTransport : IMailTransport
{
    private readonly ConcurrentQueue<(SmtpTarget Target, OutgoingMail Mail)> _sent = new();

    public IReadOnlyCollection<(SmtpTarget Target, OutgoingMail Mail)> Sent => _sent;

    public Task SendAsync(SmtpTarget target, OutgoingMail mail, CancellationToken ct)
    {
        _sent.Enqueue((target, mail));
        return Task.CompletedTask;
    }

    /// <summary>The newest mail to <paramref name="address"/> whose subject contains <paramref name="subject"/> (it may come a moment later: the queue sends it).</summary>
    public async Task<OutgoingMail> WaitForAsync(string address, string subject, int skip = 0)
    {
        for (var i = 0; i < 100; i++)
        {
            var found = _sent.Where(s => s.Mail.ToAddress == address && s.Mail.Subject.Contains(subject, StringComparison.Ordinal)).Skip(skip).Select(s => s.Mail).LastOrDefault();
            if (found is not null)
            {
                return found;
            }

            await Task.Delay(50);
        }

        throw new TimeoutException($"No mail \"{subject}\" to {address}.");
    }

    public int CountTo(string address) => _sent.Count(s => s.Mail.ToAddress == address);
}
