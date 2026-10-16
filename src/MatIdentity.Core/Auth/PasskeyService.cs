using MatIdentity.Core.Data;
using MatIdentity.Core.Entities;
using Microsoft.EntityFrameworkCore;

namespace MatIdentity.Core.Auth;

/// <summary>The passkeys of the people (the stored half of WebAuthn: id, public key, counter). The ceremonies themselves are in the web layer.</summary>
public sealed class PasskeyService
{
    private readonly MatIdentityDbContext _db;

    public PasskeyService(MatIdentityDbContext db)
    {
        _db = db;
    }

    public Task<List<Passkey>> ListAsync(long userId, CancellationToken ct = default)
        => _db.Passkeys.AsNoTracking().Where(p => p.UserId == userId).OrderBy(p => p.CreateDate).ToListAsync(ct);

    public Task<List<string>> CredentialIdsAsync(long userId, CancellationToken ct = default)
        => _db.Passkeys.Where(p => p.UserId == userId).Select(p => p.CredentialId).ToListAsync(ct);

    public Task<bool> AnyAsync(long userId, CancellationToken ct = default) => _db.Passkeys.AnyAsync(p => p.UserId == userId, ct);

    public Task<bool> ExistsAsync(string credentialId, CancellationToken ct = default) => _db.Passkeys.AnyAsync(p => p.CredentialId == credentialId, ct);

    /// <summary>The passkey with this credential id and its person (null when unknown or the person is gone).</summary>
    public async Task<Passkey?> FindAsync(string credentialId, CancellationToken ct = default)
    {
        var passkey = await _db.Passkeys.Include(p => p.User).FirstOrDefaultAsync(p => p.CredentialId == credentialId, ct);
        return passkey?.User is { UpdateState: not UpdateState.Deleted } ? passkey : null;
    }

    /// <summary>How many passkeys each person has (for the list of people).</summary>
    public Task<Dictionary<long, int>> CountsAsync(CancellationToken ct = default)
        => _db.Passkeys.GroupBy(p => p.UserId).Select(g => new { g.Key, Count = g.Count() }).ToDictionaryAsync(x => x.Key, x => x.Count, ct);

    public async Task AddAsync(long userId, string credentialId, byte[] publicKey, long signCount, Guid aaGuid, string name, CancellationToken ct = default)
    {
        _db.Passkeys.Add(new Passkey
        {
            UserId = userId,
            CredentialId = credentialId,
            PublicKey = publicKey,
            SignCount = signCount,
            AaGuid = aaGuid,
            Name = name.Length > 100 ? name[..100] : name,
        });
        await _db.SaveChangesAsync(ct);
    }

    /// <summary>After a sign-in: the new counter and the time.</summary>
    public async Task UsedAsync(long passkeyId, long signCount, CancellationToken ct = default)
    {
        var passkey = await _db.Passkeys.FirstAsync(p => p.Id == passkeyId, ct);
        passkey.SignCount = signCount;
        passkey.LastUsedAt = DateTime.UtcNow;
        await _db.SaveChangesAsync(ct);
    }

    /// <summary>Removes one passkey of a person; the name of the removed one, or null.</summary>
    public async Task<string?> DeleteAsync(long userId, long passkeyId, CancellationToken ct = default)
    {
        var passkey = await _db.Passkeys.FirstOrDefaultAsync(p => p.Id == passkeyId && p.UserId == userId, ct);
        if (passkey is null)
        {
            return null;
        }

        _db.Passkeys.Remove(passkey);
        await _db.SaveChangesAsync(ct);
        return passkey.Name;
    }

    /// <summary>Removes all passkeys of a person (an administrator, for lost devices). Returns how many.</summary>
    public async Task<int> DeleteAllAsync(long userId, CancellationToken ct = default)
    {
        var passkeys = await _db.Passkeys.Where(p => p.UserId == userId).ToListAsync(ct);
        _db.Passkeys.RemoveRange(passkeys);
        await _db.SaveChangesAsync(ct);
        return passkeys.Count;
    }
}
