using Microsoft.EntityFrameworkCore;

namespace MatIdentity.Core.Data;

/// <summary>What the host asks of the database itself: bring it up to date at start, and whether it answers (the health check).</summary>
public sealed class DatabaseService
{
    private readonly MatIdentityDbContext _db;

    public DatabaseService(MatIdentityDbContext db)
    {
        _db = db;
    }

    public Task MigrateAsync(CancellationToken ct = default) => _db.Database.MigrateAsync(ct);

    /// <summary>True when the database can be read.</summary>
    public async Task<bool> CanReadAsync(CancellationToken ct = default)
    {
        try
        {
            await _db.Database.ExecuteSqlRawAsync("SELECT 1", ct);
            return true;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return false;
        }
    }
}
