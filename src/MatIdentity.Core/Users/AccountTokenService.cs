using System.Security.Cryptography;
using System.Text;
using MatIdentity.Core.Data;
using MatIdentity.Core.Entities;
using Microsoft.EntityFrameworkCore;

namespace MatIdentity.Core.Users;

/// <summary>The keys behind the links in mails (<see cref="AccountToken"/>): made, found by their hash, used once.</summary>
public sealed class AccountTokenService
{
    public static readonly TimeSpan ResetLifetime = TimeSpan.FromMinutes(30);
    public static readonly TimeSpan InvitationLifetime = TimeSpan.FromDays(7);
    public static readonly TimeSpan VerificationLifetime = TimeSpan.FromHours(48);

    private readonly MatIdentityDbContext _db;
    private readonly TimeProvider _time;

    public AccountTokenService(MatIdentityDbContext db, TimeProvider time)
    {
        _db = db;
        _time = time;
    }

    public static TimeSpan LifetimeOf(AccountTokenPurpose purpose) => purpose switch
    {
        AccountTokenPurpose.PasswordReset => ResetLifetime,
        AccountTokenPurpose.Invitation => InvitationLifetime,
        _ => VerificationLifetime,
    };

    /// <summary>A new key (256 bits, URL-safe) for <paramref name="purpose"/>; the unused ones of the same purpose stop working. Only its hash is stored.</summary>
    public async Task<string> IssueAsync(long userId, AccountTokenPurpose purpose, string? email, CancellationToken ct = default)
    {
        await RevokeAsync(userId, purpose, ct);
        var key = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        _db.AccountTokens.Add(new AccountToken
        {
            UserId = userId,
            Purpose = purpose,
            TokenHash = Hash(key),
            Email = email,
            ExpiresAt = Now().Add(LifetimeOf(purpose)),
        });
        await _db.SaveChangesAsync(ct);
        return key;
    }

    /// <summary>The token of a link (with its person) while it is unused, not expired and one of <paramref name="purposes"/>; else null.</summary>
    public async Task<AccountToken?> FindAsync(string? key, IReadOnlyCollection<AccountTokenPurpose> purposes, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(key) || key.Length > 100)
        {
            return null;
        }

        var hash = Hash(key.Trim());
        var now = Now();
        var token = await _db.AccountTokens.Include(t => t.User).FirstOrDefaultAsync(t => t.TokenHash == hash, ct);
        return token is { UsedAt: null, User: not null } && token.ExpiresAt > now && purposes.Contains(token.Purpose) ? token : null;
    }

    /// <summary>Marks the token used: the link works no more.</summary>
    public async Task UseAsync(AccountToken token, CancellationToken ct = default)
    {
        token.UsedAt = Now();
        await _db.SaveChangesAsync(ct);
    }

    /// <summary>Ends the unused tokens of a person for <paramref name="purpose"/> (a new password ends the open reset links).</summary>
    public async Task RevokeAsync(long userId, AccountTokenPurpose purpose, CancellationToken ct = default)
    {
        var open = await _db.AccountTokens.Where(t => t.UserId == userId && t.Purpose == purpose && t.UsedAt == null).ToListAsync(ct);
        _db.AccountTokens.RemoveRange(open);
        await _db.SaveChangesAsync(ct);
    }

    /// <summary>How many tokens of this purpose a person got since <paramref name="since"/> (also used and replaced ones): the limit of reset mails.</summary>
    public Task<int> CountSinceAsync(long userId, AccountTokenPurpose purpose, DateTime since, CancellationToken ct = default)
        => _db.AccountTokens.IgnoreQueryFilters().CountAsync(t => t.UserId == userId && t.Purpose == purpose && t.CreateDate >= since, ct);

    /// <summary>The people with an invitation that is still open (they have not chosen their password yet).</summary>
    public async Task<HashSet<long>> OpenInvitationsAsync(CancellationToken ct = default)
    {
        var now = Now();
        return (await _db.AccountTokens.Where(t => t.Purpose == AccountTokenPurpose.Invitation && t.UsedAt == null && t.ExpiresAt > now).Select(t => t.UserId).ToListAsync(ct)).ToHashSet();
    }

    public static string Hash(string key) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(key)));

    private DateTime Now() => _time.GetUtcNow().UtcDateTime;
}
