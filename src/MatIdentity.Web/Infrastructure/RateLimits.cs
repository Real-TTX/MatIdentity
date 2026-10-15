using System.Threading.RateLimiting;

namespace MatIdentity.Web.Infrastructure;

/// <summary>
/// Limits per client address, so nobody can try passwords or secrets by the thousand: the sign-in page, the token endpoint (client secrets)
/// and the anonymous platform endpoints. Behind a proxy the address is the one the proxy saw (forwarded headers from known proxies only).
/// </summary>
public static class RateLimits
{
    public const string SignIn = "sign-in";
    public const string Token = "token";
    public const string Api = "api";

    public static IServiceCollection AddMatIdentityRateLimits(this IServiceCollection services)
        => services.AddRateLimiter(options =>
        {
            options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            options.AddPolicy(SignIn, http => PerAddress(http, 20));
            options.AddPolicy(Token, http => PerAddress(http, 120));
            options.AddPolicy(Api, http => PerAddress(http, 240));
        });

    private static RateLimitPartition<string> PerAddress(HttpContext http, int perMinute)
        => RateLimitPartition.GetFixedWindowLimiter(
            http.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            _ => new FixedWindowRateLimiterOptions { PermitLimit = perMinute, Window = TimeSpan.FromMinutes(1), QueueLimit = 0 });
}
