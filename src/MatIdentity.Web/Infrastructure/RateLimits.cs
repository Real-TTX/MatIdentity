using System.Threading.RateLimiting;

namespace MatIdentity.Web.Infrastructure;

/// <summary>
/// Limits per client address, so nobody can try passwords, codes or secrets by the thousand: the sign-in pages and the passkey ceremonies, the token
/// endpoint (client secrets) and the anonymous platform endpoints. Behind a proxy the address is the one the proxy saw (forwarded headers from known proxies only).
/// The numbers per minute can be changed (<c>MatIdentity__RateLimits__SignIn</c>, <c>__Token</c>, <c>__Api</c>); the tests raise them, because all their requests come from one address.
/// </summary>
public static class RateLimits
{
    public const string SignIn = "sign-in";
    public const string Token = "token";
    public const string Api = "api";

    public static IServiceCollection AddMatIdentityRateLimits(this IServiceCollection services, IConfiguration configuration)
    {
        var section = configuration.GetSection("MatIdentity:RateLimits");
        var signIn = section.GetValue("SignIn", 20);
        var token = section.GetValue("Token", 120);
        var api = section.GetValue("Api", 240);
        return services.AddRateLimiter(options =>
        {
            options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            // Only attempts count (a POST), not opening the page: a person who opens the form a few times is no attacker.
            options.AddPolicy(SignIn, http => HttpMethods.IsGet(http.Request.Method) ? RateLimitPartition.GetNoLimiter("get") : PerAddress(http, signIn));
            options.AddPolicy(Token, http => PerAddress(http, token));
            options.AddPolicy(Api, http => PerAddress(http, api));
        });
    }

    private static RateLimitPartition<string> PerAddress(HttpContext http, int perMinute)
        => RateLimitPartition.GetFixedWindowLimiter(
            http.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            _ => new FixedWindowRateLimiterOptions { PermitLimit = perMinute, Window = TimeSpan.FromMinutes(1), QueueLimit = 0 });
}
