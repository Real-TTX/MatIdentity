using MatIdentity.Core.Activity;
using MatIdentity.Core.Auth;
using MatIdentity.Core.Clients;
using MatIdentity.Core.Configuration;
using MatIdentity.Core.Security;
using MatIdentity.Core.Users;
using Microsoft.Extensions.DependencyInjection;

namespace MatIdentity.Core;

/// <summary>
/// Registers the MatIdentity domain/services. The hosting layer is still responsible for the infrastructure that needs configuration:
/// the <c>MatIdentityDbContext</c> (connection string), OpenIddict (keys, endpoints), Data Protection, options binding, <c>AppPaths</c>
/// and <c>ICurrentUserAccessor</c>.
/// </summary>
public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddMatIdentityCore(this IServiceCollection services)
    {
        services.AddSingleton<IPasswordHasher, Pbkdf2PasswordHasher>();
        services.AddSingleton<ISecretProtector, DataProtectionSecretProtector>();
        services.AddSingleton<JsonConfigStore>();
        services.AddSingleton<SystemConfigService>();

        // Per-request services (depend on the scoped DbContext and on the OpenIddict managers).
        services.AddScoped<AuthService>();
        services.AddScoped<SessionService>();
        services.AddScoped<UserService>();
        services.AddScoped<ActivityService>();
        services.AddScoped<ClientService>();
        services.AddScoped<TokenRevoker>();

        return services;
    }
}
