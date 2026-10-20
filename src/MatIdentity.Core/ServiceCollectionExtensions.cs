using MatIdentity.Core.Activity;
using MatIdentity.Core.Auth;
using MatIdentity.Core.Clients;
using MatIdentity.Core.Configuration;
using MatIdentity.Core.Security;
using MatIdentity.Core.Users;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

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

        // Mail: MatSMTP (the web project registers its MailRelay from MATSMTP_*) or the own server of the settings.
        services.TryAddSingleton(new MatIdentity.Core.Mail.MailRelay());
        services.TryAddSingleton<MatIdentity.Core.Mail.IMailTransport, MatIdentity.Core.Mail.SmtpMailTransport>();
        services.AddSingleton<MatIdentity.Core.Mail.MailService>();
        services.AddSingleton<MatIdentity.Core.Mail.MailQueue>();
        services.AddHostedService<MatIdentity.Core.Mail.MailQueueWorker>();

        // Per-request services (depend on the scoped DbContext and on the OpenIddict managers).
        services.AddScoped<AuthService>();
        services.AddScoped<SessionService>();
        services.AddScoped<TwoFactorService>();
        services.AddScoped<PasskeyService>();
        services.AddScoped<MatIdentity.Core.Data.DatabaseService>();
        services.AddSingleton(TimeProvider.System);
        services.AddScoped<UserService>();
        services.AddScoped<AccountTokenService>();
        services.AddScoped<AccountMailService>();
        services.AddScoped<ActivityService>();
        services.AddScoped<ClientService>();
        services.AddScoped<TokenRevoker>();
        services.AddScoped<MatIdentity.Core.Access.PermissionService>();
        services.AddScoped<MatIdentity.Core.Access.GroupService>();

        return services;
    }
}
