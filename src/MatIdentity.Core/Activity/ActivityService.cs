using MatIdentity.Core.Data;
using MatIdentity.Core.Entities;
using Microsoft.EntityFrameworkCore;

namespace MatIdentity.Core.Activity;

/// <summary>Writes and reads the activity list (<see cref="ActivityEntry"/>): sign-ins, tokens, changes to clients.</summary>
public sealed class ActivityService
{
    private readonly MatIdentityDbContext _db;

    public ActivityService(MatIdentityDbContext db)
    {
        _db = db;
    }

    public async Task WriteAsync(ActivityKind kind, User? user = null, string? username = null, string? clientId = null, string? ipAddress = null, string? detail = null, CancellationToken ct = default)
    {
        _db.Activity.Add(new ActivityEntry
        {
            Kind = kind,
            UserId = user?.Id,
            Username = Truncate(user?.Username ?? username, 128),
            ClientId = Truncate(clientId, 100),
            IpAddress = Truncate(ipAddress, 64),
            Detail = Truncate(detail, 500),
        });
        await _db.SaveChangesAsync(ct);
    }

    public Task<List<ActivityEntry>> GetAllAsync(CancellationToken ct = default)
        => _db.Activity.AsNoTracking().OrderByDescending(a => a.Id).ToListAsync(ct);

    public Task<List<ActivityEntry>> GetRecentAsync(int count, CancellationToken ct = default)
        => _db.Activity.AsNoTracking().OrderByDescending(a => a.Id).Take(count).ToListAsync(ct);

    /// <summary>How many entries of these kinds there were since <paramref name="sinceUtc"/>.</summary>
    public Task<int> CountSinceAsync(DateTime sinceUtc, IReadOnlyCollection<ActivityKind> kinds, CancellationToken ct = default)
        => _db.Activity.CountAsync(a => a.CreateDate >= sinceUtc && kinds.Contains(a.Kind), ct);

    /// <summary>The time of the last entry of a kind, or null.</summary>
    public async Task<DateTime?> LastAsync(ActivityKind kind, CancellationToken ct = default)
        => await _db.Activity.Where(a => a.Kind == kind).OrderByDescending(a => a.Id).Select(a => (DateTime?)a.CreateDate).FirstOrDefaultAsync(ct);

    /// <summary>Removes entries older than <paramref name="days"/> days (kept small, it is no archive). Returns how many.</summary>
    public Task<int> PruneAsync(int days, CancellationToken ct = default)
    {
        var limit = DateTime.UtcNow.AddDays(-days);
        return _db.Activity.IgnoreQueryFilters().Where(a => a.CreateDate < limit).ExecuteDeleteAsync(ct);
    }

    /// <summary>The words for a kind, as the activity list shows them.</summary>
    public static string Describe(ActivityKind kind) => kind switch
    {
        ActivityKind.SignIn => "Signed in",
        ActivityKind.SignInFailed => "Sign-in failed",
        ActivityKind.SignOut => "Signed out",
        ActivityKind.AppSignIn => "Signed in to an app",
        ActivityKind.MachineToken => "Machine token",
        ActivityKind.ClientCreated => "App added",
        ActivityKind.ClientChanged => "App changed",
        ActivityKind.ClientDeleted => "App removed",
        ActivityKind.ClientSecretRenewed => "App secret renewed",
        _ => kind.ToString(),
    };

    private static string? Truncate(string? value, int max) => value is { Length: > 0 } && value.Length > max ? value[..max] : value;
}
