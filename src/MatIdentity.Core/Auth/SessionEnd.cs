using System.Security.Cryptography;
using System.Text;

namespace MatIdentity.Core.Auth;

/// <summary>A session that ended: whose (<c>sub</c>), its public id (<c>sid</c>) and the apps it signed in to.</summary>
public sealed record EndedSession(string Subject, string Sid, IReadOnlyList<string> ClientIds);

/// <summary>
/// Hears when sessions end, so the apps can end theirs (the web project sends OpenID Connect back-channel logout tokens). <paramref name="everywhere"/>: the
/// person is out everywhere (disabled, deleted, a new password), so every app hears it, also one whose session here has expired already.
/// </summary>
public interface ISessionEndListener
{
    Task SessionsEndedAsync(IReadOnlyList<EndedSession> sessions, bool everywhere, CancellationToken ct);
}

/// <summary>Nobody listens (Core alone, the tests of Core).</summary>
public sealed class NoSessionEndListener : ISessionEndListener
{
    public Task SessionsEndedAsync(IReadOnlyList<EndedSession> sessions, bool everywhere, CancellationToken ct) => Task.CompletedTask;
}

/// <summary>The public id of a session (the claim <c>sid</c>): derived from its token, never the token itself.</summary>
public static class SessionIds
{
    public static string Of(string sessionToken)
        => Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes("sid:" + sessionToken)))[..22].Replace('+', '-').Replace('/', '_');
}
