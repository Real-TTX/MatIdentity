using MatIdentity.Core.Data;
using MatIdentity.Core.Entities;
using Microsoft.EntityFrameworkCore;

namespace MatIdentity.Core.Access;

/// <summary>The groups and who is in them.</summary>
public sealed class GroupService
{
    private readonly MatIdentityDbContext _db;

    public GroupService(MatIdentityDbContext db)
    {
        _db = db;
    }

    /// <summary>The groups with the number of (active, not deleted) members, by name.</summary>
    public async Task<List<(Group Group, int Members)>> GetAllAsync(CancellationToken ct = default)
    {
        var groups = await _db.Groups.AsNoTracking().OrderBy(g => g.Name).ToListAsync(ct);
        var counts = await _db.GroupMembers.Where(m => m.User!.UpdateState != UpdateState.Deleted)
            .GroupBy(m => m.GroupId).Select(g => new { g.Key, Count = g.Count() }).ToDictionaryAsync(x => x.Key, x => x.Count, ct);
        return groups.Select(g => (g, counts.GetValueOrDefault(g.Id))).ToList();
    }

    public Task<Group?> GetAsync(long id, CancellationToken ct = default) => _db.Groups.FirstOrDefaultAsync(g => g.Id == id, ct);

    public Task<bool> NameExistsAsync(string name, long? excludeId = null, CancellationToken ct = default)
    {
        var normalized = name.Trim().ToLower();
        return _db.Groups.AnyAsync(g => g.Name.ToLower() == normalized && (excludeId == null || g.Id != excludeId), ct);
    }

    /// <summary>The ids of the members of a group.</summary>
    public Task<List<long>> MemberIdsAsync(long groupId, CancellationToken ct = default)
        => _db.GroupMembers.Where(m => m.GroupId == groupId).Select(m => m.UserId).ToListAsync(ct);

    /// <summary>The ids of the groups a person is in.</summary>
    public Task<List<long>> GroupIdsOfAsync(long userId, CancellationToken ct = default)
        => _db.GroupMembers.Where(m => m.UserId == userId).Select(m => m.GroupId).ToListAsync(ct);

    /// <summary>Creates or changes a group and sets its members to exactly <paramref name="memberIds"/>.</summary>
    public async Task<Group> SaveAsync(long? id, string name, string? description, IEnumerable<long> memberIds, CancellationToken ct = default)
    {
        var group = id is > 0 ? await _db.Groups.FirstOrDefaultAsync(g => g.Id == id, ct) ?? throw new InvalidOperationException("No such group.") : new Group();
        group.Name = name.Trim();
        group.Description = string.IsNullOrWhiteSpace(description) ? null : description.Trim();
        if (group.Id == 0)
        {
            _db.Groups.Add(group);
            await _db.SaveChangesAsync(ct);
        }

        var wanted = memberIds.ToHashSet();
        var existing = await _db.GroupMembers.Where(m => m.GroupId == group.Id).ToListAsync(ct);
        _db.GroupMembers.RemoveRange(existing.Where(m => !wanted.Contains(m.UserId)));
        foreach (var userId in wanted.Except(existing.Select(m => m.UserId)))
        {
            _db.GroupMembers.Add(new GroupMember { GroupId = group.Id, UserId = userId });
        }

        await _db.SaveChangesAsync(ct);
        return group;
    }

    /// <summary>Sets the groups of a person to exactly <paramref name="groupIds"/> (from the page of the person).</summary>
    public async Task SetGroupsOfAsync(long userId, IEnumerable<long> groupIds, CancellationToken ct = default)
    {
        var wanted = groupIds.ToHashSet();
        var existing = await _db.GroupMembers.Where(m => m.UserId == userId).ToListAsync(ct);
        _db.GroupMembers.RemoveRange(existing.Where(m => !wanted.Contains(m.GroupId)));
        var valid = await _db.Groups.Where(g => wanted.Contains(g.Id)).Select(g => g.Id).ToListAsync(ct);
        foreach (var groupId in valid.Except(existing.Select(m => m.GroupId)))
        {
            _db.GroupMembers.Add(new GroupMember { GroupId = groupId, UserId = userId });
        }

        await _db.SaveChangesAsync(ct);
    }

    /// <summary>Removes the group, its memberships and what it was given in the apps.</summary>
    public async Task<bool> DeleteAsync(long id, CancellationToken ct = default)
    {
        var group = await _db.Groups.FirstOrDefaultAsync(g => g.Id == id, ct);
        if (group is null)
        {
            return false;
        }

        _db.GroupMembers.RemoveRange(await _db.GroupMembers.Where(m => m.GroupId == id).ToListAsync(ct));
        _db.AppGrants.RemoveRange(await _db.AppGrants.Where(a => a.GroupId == id).ToListAsync(ct));
        _db.Groups.Remove(group);
        await _db.SaveChangesAsync(ct);
        return true;
    }
}
