using MatIdentity.Core.Configuration;
using MatIdentity.Core.Data;
using MatIdentity.Core.Entities;
using Microsoft.EntityFrameworkCore;

namespace MatIdentity.Core.Auth;

/// <summary>
/// Manages server-side sign-in sessions in SQLite. Because the sessions live on the mounted data volume, they remain valid after a container
/// restart (the client cookie only carries the token). The lifetime is the setting <see cref="SystemConfig.SessionLifetimeDays"/>: a session ends
/// after that many days without activity.
/// </summary>
public sealed class SessionService
{
    private static readonly TimeSpan TouchInterval = TimeSpan.FromMinutes(5);

    private readonly MatIdentityDbContext _db;
    private readonly SystemConfigService _config;
    private readonly ISessionEndListener _listener;

    public SessionService(MatIdentityDbContext db, SystemConfigService config, ISessionEndListener listener)
    {
        _db = db;
        _config = config;
        _listener = listener;
    }

    public async Task<UserSession> CreateAsync(long userId, string? userAgent, string? ipAddress, CancellationToken ct = default)
    {
        var days = (await _config.GetAsync(ct)).SessionLifetimeDays;
        var session = new UserSession
        {
            Token = Guid.NewGuid().ToString("N"),
            UserId = userId,
            ExpiresAt = DateTime.UtcNow.AddDays(Math.Max(1, days)),
            LastSeenAt = DateTime.UtcNow,
            UserAgent = Truncate(userAgent, 512),
            IpAddress = Truncate(ipAddress, 64)
        };

        _db.UserSessions.Add(session);
        await _db.SaveChangesAsync(ct);
        return session;
    }

    /// <summary>Returns the session (with its user) if the token is valid, otherwise <c>null</c>.</summary>
    public async Task<UserSession?> ValidateAsync(string token, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(token))
        {
            return null;
        }

        var session = await _db.UserSessions
            .Include(s => s.User)
            .FirstOrDefaultAsync(s => s.Token == token, ct);

        if (session is null || session.ExpiresAt <= DateTime.UtcNow || session.User is null || !session.User.IsActive)
        {
            return null;
        }

        if (DateTime.UtcNow - session.LastSeenAt > TouchInterval)
        {
            // Slide the server-side expiry with activity.
            var days = (await _config.GetAsync(ct)).SessionLifetimeDays;
            session.LastSeenAt = DateTime.UtcNow;
            session.ExpiresAt = DateTime.UtcNow.AddDays(Math.Max(1, days));
            await _db.SaveChangesAsync(ct);
        }

        return session;
    }

    public async Task InvalidateAsync(string token, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(token))
        {
            return;
        }

        var session = await _db.UserSessions.Include(s => s.User).FirstOrDefaultAsync(s => s.Token == token, ct);
        if (session is not null)
        {
            _db.UserSessions.Remove(session); // soft delete
            await _db.SaveChangesAsync(ct);
            await _listener.SessionsEndedAsync(Ended([session]), everywhere: false, ct);
        }
    }

    /// <summary>Ends every session of a person (a password was changed by an administrator, the account was disabled). Returns how many.</summary>
    public async Task<int> InvalidateAllAsync(long userId, string? exceptToken = null, CancellationToken ct = default)
    {
        var sessions = await _db.UserSessions.Include(s => s.User).Where(s => s.UserId == userId && s.Token != exceptToken).ToListAsync(ct);
        _db.UserSessions.RemoveRange(sessions);
        await _db.SaveChangesAsync(ct);

        // Without an exception the person is out everywhere (disabled, a new password set by an administrator); with one, only the other devices are.
        var ended = Ended(sessions);
        if (exceptToken is null && ended.Count == 0 && await _db.Users.IgnoreQueryFilters().FirstOrDefaultAsync(u => u.Id == userId, ct) is { } user)
        {
            ended = [new EndedSession(user.Subject, string.Empty, [])];
        }

        await _listener.SessionsEndedAsync(ended, everywhere: exceptToken is null, ct);
        return sessions.Count;
    }

    /// <summary>Ends every session of every person: everyone has to sign in again (the action "Sign everyone out"). Returns how many.</summary>
    public async Task<int> InvalidateEveryoneAsync(CancellationToken ct = default)
    {
        var sessions = await _db.UserSessions.Include(s => s.User).ToListAsync(ct);
        _db.UserSessions.RemoveRange(sessions);
        await _db.SaveChangesAsync(ct);
        await _listener.SessionsEndedAsync(Ended(sessions), everywhere: false, ct);
        return sessions.Count;
    }

    /// <summary>The sessions that are still valid, newest first (for the account page and the state).</summary>
    public Task<List<UserSession>> ListActiveAsync(long? userId = null, CancellationToken ct = default)
    {
        var now = DateTime.UtcNow;
        return _db.UserSessions.AsNoTracking()
            .Where(s => s.ExpiresAt > now && (userId == null || s.UserId == userId))
            .OrderByDescending(s => s.LastSeenAt)
            .ToListAsync(ct);
    }

    public Task<int> CountActiveAsync(CancellationToken ct = default)
    {
        var now = DateTime.UtcNow;
        return _db.UserSessions.CountAsync(s => s.ExpiresAt > now, ct);
    }

    /// <summary>The person signed in to an app from this session: the app hears of the end of it.</summary>
    public async Task AddClientAsync(string token, string clientId, CancellationToken ct = default)
    {
        var session = await _db.UserSessions.FirstOrDefaultAsync(s => s.Token == token, ct);
        var ids = (session?.ClientIds ?? string.Empty).Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (session is null || ids.Contains(clientId, StringComparer.Ordinal))
        {
            return;
        }

        var joined = string.Join(' ', ids.Append(clientId));
        if (joined.Length <= 2000)
        {
            session.ClientIds = joined;
            await _db.SaveChangesAsync(ct);
        }
    }

    private static List<EndedSession> Ended(IEnumerable<UserSession> sessions)
        => sessions.Where(s => s.User is not null)
            .Select(s => new EndedSession(s.User!.Subject, SessionIds.Of(s.Token), (s.ClientIds ?? string.Empty).Split(' ', StringSplitOptions.RemoveEmptyEntries)))
            .ToList();

    private static string? Truncate(string? value, int maxLength)
        => value is { Length: > 0 } && value.Length > maxLength ? value[..maxLength] : value;
}
