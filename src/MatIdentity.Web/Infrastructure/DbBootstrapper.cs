using MatIdentity.Core.Activity;
using MatIdentity.Core.Clients;
using MatIdentity.Core.Configuration;
using MatIdentity.Core.Data;
using MatIdentity.Core.Entities;
using MatIdentity.Core.Users;
using MatIdentity.Web.Support;
using Microsoft.Extensions.Options;

namespace MatIdentity.Web.Infrastructure;

/// <summary>
/// At start: removes a migration lock left behind by a stopped process, applies the EF Core migrations, makes sure MatIdentity's own API has its scope
/// (<c>app:matidentity</c>), keeps the activity list small, and seeds the first administrator on an empty database (headless setups only) and the test account in Development.
/// </summary>
public static class DbBootstrapper
{
    /// <summary>How long the activity list keeps its lines.</summary>
    public const int ActivityDays = 90;

    public static async Task InitializeAsync(IServiceProvider services, ILogger logger)
    {
        using var scope = services.CreateScope();
        var provider = scope.ServiceProvider;

        var database = provider.GetRequiredService<DatabaseService>();
        if (await database.ReleaseStaleMigrationLockAsync())
        {
            logger.LogWarning("Removed a migration lock left behind by a process that was stopped while it migrated the database.");
        }

        await database.MigrateAsync();

        await provider.GetRequiredService<ClientService>().EnsureAppScopeAsync(ClientRules.SelfId, Ui.App.Name);
        await provider.GetRequiredService<ActivityService>().PruneAsync(ActivityDays);

        var users = provider.GetRequiredService<UserService>();
        var options = provider.GetRequiredService<IOptions<MatIdentityOptions>>().Value;
        var environment = provider.GetRequiredService<IHostEnvironment>();

        // Seed the initial administrator only on a fresh database AND only when explicitly enabled
        // (headless/automated deployments). Otherwise the first-run setup page creates the admin.
        if (options.Admin.Seed && await users.CountAsync() == 0)
        {
            var admin = options.Admin;
            await users.CreateAsync(admin.Username, admin.DisplayName, null, admin.Password, UserRole.Admin, mustChangePassword: true);
            logger.LogWarning("Seeded initial administrator '{Username}'. The initial password must be changed on first login.", admin.Username);
        }

        // Local/dev only (never in Production): a ready-to-use test account so testing never touches the real admin.
        if (environment.IsDevelopment() && !await users.UsernameExistsAsync(DevAccount.Username))
        {
            await users.CreateAsync(DevAccount.Username, "Admin", DevAccount.Username, DevAccount.Password, UserRole.Admin, mustChangePassword: false);
            logger.LogWarning("Seeded local test account '{Username}' (Development only).", DevAccount.Username);
        }
    }
}

/// <summary>The ready-to-use account of a Development start (never in Production): its user name is also its e-mail address.</summary>
public static class DevAccount
{
    public const string Username = "admin@example.com";
    public const string Password = "Start12345";
}
