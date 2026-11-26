using MatIdentity.Core.Data;
using MatIdentity.Core.Entities;
using Microsoft.EntityFrameworkCore;

namespace MatIdentity.Core.Clients;

/// <summary>
/// The look of the sign-in of the apps (<see cref="ClientBranding"/>, docs/ARCHITECTURE.md "Branded sign-in"): read without the pictures for every page of a sign-in,
/// the pictures alone for their addresses, saved through <c>/api/v1/clients</c>, removed with the app.
/// </summary>
public sealed class BrandingService
{
    private readonly MatIdentityDbContext _db;

    public BrandingService(MatIdentityDbContext db)
    {
        _db = db;
    }

    /// <summary>The brand of an app without its pictures, or null.</summary>
    public Task<BrandInfo?> GetAsync(string clientId, CancellationToken ct = default)
        => _db.Set<ClientBranding>().AsNoTracking()
            .Where(b => b.ClientId == clientId)
            .Select(b => new BrandInfo
            {
                ClientId = b.ClientId,
                Name = b.Name,
                Accent = b.Accent,
                HideIdentity = b.HideIdentity,
                LogoContentType = b.LogoContentType,
                LogoHash = b.LogoHash,
                BackgroundContentType = b.BackgroundContentType,
                BackgroundHash = b.BackgroundHash,
            })
            .FirstOrDefaultAsync(ct);

    /// <summary>The brands of these apps, by client id (the list of the API).</summary>
    public async Task<Dictionary<string, BrandInfo>> GetManyAsync(IReadOnlyCollection<string> clientIds, CancellationToken ct = default)
    {
        var list = await _db.Set<ClientBranding>().AsNoTracking()
            .Where(b => clientIds.Contains(b.ClientId))
            .Select(b => new BrandInfo
            {
                ClientId = b.ClientId,
                Name = b.Name,
                Accent = b.Accent,
                HideIdentity = b.HideIdentity,
                LogoContentType = b.LogoContentType,
                LogoHash = b.LogoHash,
                BackgroundContentType = b.BackgroundContentType,
                BackgroundHash = b.BackgroundHash,
            })
            .ToListAsync(ct);
        return list.ToDictionary(b => b.ClientId, StringComparer.Ordinal);
    }

    /// <summary>A picture of a brand, or null.</summary>
    public async Task<BrandImage?> ImageAsync(string clientId, BrandImageKind kind, CancellationToken ct = default)
    {
        var query = _db.Set<ClientBranding>().AsNoTracking().Where(b => b.ClientId == clientId);
        var found = kind == BrandImageKind.Logo
            ? await query.Select(b => new { Type = b.LogoContentType, Data = b.Logo, Hash = b.LogoHash }).FirstOrDefaultAsync(ct)
            : await query.Select(b => new { Type = b.BackgroundContentType, Data = b.Background, Hash = b.BackgroundHash }).FirstOrDefaultAsync(ct);
        return found is { Type: { } type, Data: { Length: > 0 } data, Hash: { } hash } ? new BrandImage(type, data, hash) : null;
    }

    /// <summary>
    /// Sets the brand of an app (<see cref="BrandingInput"/>: a picture that is not given keeps the stored one). The errors of <see cref="BrandingRules.Check"/>,
    /// nothing saved when there are any. The caller makes sure the app exists and that it may change it.
    /// </summary>
    public async Task<Dictionary<string, string>> SaveAsync(string clientId, BrandingInput input, CancellationToken ct = default)
    {
        var check = BrandingRules.Check(input);
        if (!check.Succeeded)
        {
            return check.Errors;
        }

        var row = await _db.Set<ClientBranding>().FirstOrDefaultAsync(b => b.ClientId == clientId, ct);
        if (row is null)
        {
            row = new ClientBranding { ClientId = clientId };
            _db.Add(row);
        }

        row.Name = input.Name!.Trim();
        row.Accent = input.Accent?.ToLowerInvariant();
        row.HideIdentity = input.HideIdentity;
        if (check.Logo is { } logo)
        {
            (row.LogoContentType, row.Logo, row.LogoHash) = (input.Logo!.ContentType, logo, BrandingRules.Hash(logo));
        }
        else if (input.RemoveLogo)
        {
            (row.LogoContentType, row.Logo, row.LogoHash) = (null, null, null);
        }

        if (check.Background is { } background)
        {
            (row.BackgroundContentType, row.Background, row.BackgroundHash) = (input.Background!.ContentType, background, BrandingRules.Hash(background));
        }
        else if (input.RemoveBackground)
        {
            (row.BackgroundContentType, row.Background, row.BackgroundHash) = (null, null, null);
        }

        await _db.SaveChangesAsync(ct);
        return check.Errors;
    }

    /// <summary>Removes the brand of an app (its pictures are dropped from the kept row too). False when it had none.</summary>
    public async Task<bool> RemoveAsync(string clientId, CancellationToken ct = default)
    {
        var row = await _db.Set<ClientBranding>().FirstOrDefaultAsync(b => b.ClientId == clientId, ct);
        if (row is null)
        {
            return false;
        }

        // Soft delete keeps the row: the pictures need not stay with it.
        (row.Logo, row.Background) = (null, null);
        _db.Remove(row);
        await _db.SaveChangesAsync(ct);
        return true;
    }
}
