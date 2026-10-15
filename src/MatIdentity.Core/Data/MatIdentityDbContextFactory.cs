using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace MatIdentity.Core.Data;

/// <summary>
/// Design-time factory used by the EF Core tools (<c>dotnet ef migrations …</c>).
/// It builds the context against a throwaway SQLite file and a system user accessor,
/// so migrations can be created without booting the full web host.
/// </summary>
public sealed class MatIdentityDbContextFactory : IDesignTimeDbContextFactory<MatIdentityDbContext>
{
    public MatIdentityDbContext CreateDbContext(string[] args)
    {
        var options = new DbContextOptionsBuilder<MatIdentityDbContext>()
            .UseSqlite("Data Source=matidentity-design.db")
            .Options;

        return new MatIdentityDbContext(options, new SystemCurrentUserAccessor());
    }
}
