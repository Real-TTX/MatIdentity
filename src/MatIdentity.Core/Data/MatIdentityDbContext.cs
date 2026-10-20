using MatIdentity.Core.Entities;
using Microsoft.EntityFrameworkCore;
using OpenIddict.EntityFrameworkCore.Models;

namespace MatIdentity.Core.Data;

/// <summary>
/// EF Core context for the SQLite logic database. Enforces the project conventions centrally for the tables of MatIdentity:
/// PascalCase singular table names, a BIGINT <c>Id</c> primary key, audit columns that are filled automatically, and soft delete
/// (a <c>Remove</c> becomes an <see cref="UpdateState.Deleted"/> update and deleted rows are hidden by a global query filter).
/// <para>
/// The four tables of OpenIddict (clients, authorizations, scopes, tokens) live in the same database with a BIGINT key and PascalCase names
/// (<c>OidcApplication</c>, ...). They are OpenIddict's own entities, so they keep its columns and are not soft deleted: OpenIddict prunes
/// expired tokens itself, and a deleted client must really be gone.
/// </para>
/// </summary>
public class MatIdentityDbContext : DbContext
{
    private readonly ICurrentUserAccessor _currentUser;

    public MatIdentityDbContext(DbContextOptions<MatIdentityDbContext> options, ICurrentUserAccessor currentUser)
        : base(options)
    {
        _currentUser = currentUser;
    }

    public DbSet<User> Users => Set<User>();
    public DbSet<UserSession> UserSessions => Set<UserSession>();
    public DbSet<ActivityEntry> Activity => Set<ActivityEntry>();
    public DbSet<Passkey> Passkeys => Set<Passkey>();
    public DbSet<Group> Groups => Set<Group>();
    public DbSet<GroupMember> GroupMembers => Set<GroupMember>();
    public DbSet<AppPolicy> AppPolicies => Set<AppPolicy>();
    public DbSet<AppRole> AppRoles => Set<AppRole>();
    public DbSet<AppGrant> AppGrants => Set<AppGrant>();
    public DbSet<AppCallGrant> AppCallGrants => Set<AppCallGrant>();
    public DbSet<AccountToken> AccountTokens => Set<AccountToken>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.Entity<User>(e =>
        {
            e.ToTable("User");
            e.HasKey(x => x.Id);
            e.Property(x => x.Subject).HasMaxLength(64).IsRequired();
            e.Property(x => x.Username).HasMaxLength(128).IsRequired();
            e.Property(x => x.DisplayName).HasMaxLength(256);
            e.Property(x => x.Email).HasMaxLength(256);
            e.Property(x => x.PasswordHash).HasMaxLength(512);
            e.Property(x => x.Theme).HasMaxLength(16).IsRequired();
            e.Property(x => x.TotpSecret).HasMaxLength(1000);
            e.Property(x => x.RecoveryCodeHashes).HasMaxLength(1000);
            e.Property(x => x.Role).HasConversion<int>();
            e.HasIndex(x => x.Subject).IsUnique();
            // Unique only among non-deleted rows, so a username can be reused after a soft delete.
            e.HasIndex(x => x.Username).IsUnique().HasFilter("\"UpdateState\" <> 0");
            e.HasQueryFilter(x => x.UpdateState != UpdateState.Deleted);
        });

        modelBuilder.Entity<UserSession>(e =>
        {
            e.ToTable("UserSession");
            e.HasKey(x => x.Id);
            e.Property(x => x.Token).HasMaxLength(64).IsRequired();
            e.Property(x => x.UserAgent).HasMaxLength(512);
            e.Property(x => x.ClientIds).HasMaxLength(2000);
            e.Property(x => x.IpAddress).HasMaxLength(64);
            e.HasIndex(x => x.Token).IsUnique();
            e.HasIndex(x => x.UserId);
            e.HasOne(x => x.User)
                .WithMany(u => u.Sessions)
                .HasForeignKey(x => x.UserId)
                .OnDelete(DeleteBehavior.Cascade);
            e.HasQueryFilter(x => x.UpdateState != UpdateState.Deleted);
        });

        modelBuilder.Entity<ActivityEntry>(e =>
        {
            e.ToTable("ActivityEntry");
            e.HasKey(x => x.Id);
            e.Property(x => x.Kind).HasConversion<int>();
            e.Property(x => x.Username).HasMaxLength(128);
            e.Property(x => x.ClientId).HasMaxLength(100);
            e.Property(x => x.IpAddress).HasMaxLength(64);
            e.Property(x => x.Detail).HasMaxLength(500);
            e.HasIndex(x => x.CreateDate);
            e.HasIndex(x => x.Kind);
            e.HasQueryFilter(x => x.UpdateState != UpdateState.Deleted);
        });

        modelBuilder.Entity<Passkey>(e =>
        {
            e.ToTable("Passkey");
            e.HasKey(x => x.Id);
            e.Property(x => x.CredentialId).HasMaxLength(1400).IsRequired();
            e.Property(x => x.Name).HasMaxLength(100).IsRequired();
            e.HasIndex(x => x.CredentialId).IsUnique().HasFilter("\"UpdateState\" <> 0");
            e.HasIndex(x => x.UserId);
            e.HasOne(x => x.User).WithMany(u => u.Passkeys).HasForeignKey(x => x.UserId).OnDelete(DeleteBehavior.Cascade);
            e.HasQueryFilter(x => x.UpdateState != UpdateState.Deleted);
        });

        modelBuilder.Entity<Group>(e =>
        {
            e.ToTable("Group");
            e.HasKey(x => x.Id);
            e.Property(x => x.Name).HasMaxLength(100).IsRequired();
            e.Property(x => x.Description).HasMaxLength(500);
            e.HasIndex(x => x.Name).IsUnique().HasFilter("\"UpdateState\" <> 0");
            e.HasQueryFilter(x => x.UpdateState != UpdateState.Deleted);
        });

        modelBuilder.Entity<GroupMember>(e =>
        {
            e.ToTable("GroupMember");
            e.HasKey(x => x.Id);
            e.HasIndex(x => new { x.GroupId, x.UserId }).IsUnique().HasFilter("\"UpdateState\" <> 0");
            e.HasIndex(x => x.UserId);
            e.HasOne(x => x.Group).WithMany(g => g.Members).HasForeignKey(x => x.GroupId).OnDelete(DeleteBehavior.Cascade);
            e.HasOne(x => x.User).WithMany().HasForeignKey(x => x.UserId).OnDelete(DeleteBehavior.Cascade);
            e.HasQueryFilter(x => x.UpdateState != UpdateState.Deleted);
        });

        modelBuilder.Entity<AppPolicy>(e =>
        {
            e.ToTable("AppPolicy");
            e.HasKey(x => x.Id);
            e.Property(x => x.ClientId).HasMaxLength(100).IsRequired();
            e.Property(x => x.RoleMode).HasConversion<int>();
            e.HasIndex(x => x.ClientId).IsUnique().HasFilter("\"UpdateState\" <> 0");
            e.HasQueryFilter(x => x.UpdateState != UpdateState.Deleted);
        });

        modelBuilder.Entity<AppRole>(e =>
        {
            e.ToTable("AppRole");
            e.HasKey(x => x.Id);
            e.Property(x => x.ClientId).HasMaxLength(100).IsRequired();
            e.Property(x => x.Key).HasMaxLength(64).IsRequired();
            e.Property(x => x.Label).HasMaxLength(100).IsRequired();
            e.HasIndex(x => new { x.ClientId, x.Key }).IsUnique().HasFilter("\"UpdateState\" <> 0");
            e.HasQueryFilter(x => x.UpdateState != UpdateState.Deleted);
        });

        modelBuilder.Entity<AppGrant>(e =>
        {
            e.ToTable("AppGrant");
            e.HasKey(x => x.Id);
            e.Property(x => x.ClientId).HasMaxLength(100).IsRequired();
            e.Property(x => x.RoleKey).HasMaxLength(64);
            e.HasIndex(x => x.ClientId);
            e.HasIndex(x => x.UserId);
            e.HasIndex(x => x.GroupId);
            e.HasOne(x => x.User).WithMany().HasForeignKey(x => x.UserId).OnDelete(DeleteBehavior.Cascade);
            e.HasOne(x => x.Group).WithMany().HasForeignKey(x => x.GroupId).OnDelete(DeleteBehavior.Cascade);
            e.HasQueryFilter(x => x.UpdateState != UpdateState.Deleted);
        });

        modelBuilder.Entity<AppCallGrant>(e =>
        {
            e.ToTable("AppCallGrant");
            e.HasKey(x => x.Id);
            e.Property(x => x.CallerClientId).HasMaxLength(100).IsRequired();
            e.Property(x => x.TargetClientId).HasMaxLength(100).IsRequired();
            e.HasIndex(x => new { x.CallerClientId, x.TargetClientId }).IsUnique().HasFilter("\"UpdateState\" <> 0");
            e.HasQueryFilter(x => x.UpdateState != UpdateState.Deleted);
        });

        modelBuilder.Entity<AccountToken>(e =>
        {
            e.ToTable("AccountToken");
            e.HasKey(x => x.Id);
            e.Property(x => x.Purpose).HasConversion<int>();
            e.Property(x => x.TokenHash).HasMaxLength(64).IsRequired();
            e.Property(x => x.Email).HasMaxLength(256);
            e.HasIndex(x => x.TokenHash).IsUnique();
            e.HasIndex(x => new { x.UserId, x.Purpose });
            e.HasOne(x => x.User).WithMany().HasForeignKey(x => x.UserId).OnDelete(DeleteBehavior.Cascade);
            e.HasQueryFilter(x => x.UpdateState != UpdateState.Deleted);
        });

        // OpenIddict: its entities with a BIGINT key, in tables named like ours.
        modelBuilder.UseOpenIddict<long>();
        modelBuilder.Entity<OpenIddictEntityFrameworkCoreApplication<long>>().ToTable("OidcApplication");
        modelBuilder.Entity<OpenIddictEntityFrameworkCoreAuthorization<long>>().ToTable("OidcAuthorization");
        modelBuilder.Entity<OpenIddictEntityFrameworkCoreScope<long>>().ToTable("OidcScope");
        modelBuilder.Entity<OpenIddictEntityFrameworkCoreToken<long>>().ToTable("OidcToken");
    }

    public override int SaveChanges(bool acceptAllChangesOnSuccess)
    {
        ApplyAudit();
        return base.SaveChanges(acceptAllChangesOnSuccess);
    }

    public override Task<int> SaveChangesAsync(bool acceptAllChangesOnSuccess, CancellationToken cancellationToken = default)
    {
        ApplyAudit();
        return base.SaveChangesAsync(acceptAllChangesOnSuccess, cancellationToken);
    }

    /// <summary>Fills audit columns and turns hard deletes into soft deletes (only for the entities of MatIdentity, see the class summary).</summary>
    private void ApplyAudit()
    {
        var now = DateTime.UtcNow;
        var userId = _currentUser.UserId;

        foreach (var entry in ChangeTracker.Entries<AuditableEntity>())
        {
            switch (entry.State)
            {
                case EntityState.Added:
                    entry.Entity.CreateDate = now;
                    entry.Entity.CreateUserId = userId;
                    entry.Entity.UpdateDate = now;
                    entry.Entity.UpdateUserId = userId;
                    entry.Entity.UpdateState = UpdateState.Created;
                    break;

                case EntityState.Modified:
                    entry.Entity.UpdateDate = now;
                    entry.Entity.UpdateUserId = userId;
                    if (entry.Entity.UpdateState != UpdateState.Deleted)
                    {
                        entry.Entity.UpdateState = UpdateState.Updated;
                    }

                    break;

                case EntityState.Deleted:
                    // Soft delete: keep the row, flag it and hide it via the query filter.
                    entry.State = EntityState.Modified;
                    entry.Entity.UpdateDate = now;
                    entry.Entity.UpdateUserId = userId;
                    entry.Entity.UpdateState = UpdateState.Deleted;
                    break;
            }
        }
    }
}
