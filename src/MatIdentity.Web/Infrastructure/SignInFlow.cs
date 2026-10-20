using System.Security.Claims;
using MatIdentity.Core.Activity;
using MatIdentity.Core.Auth;
using MatIdentity.Core.Entities;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Caching.Memory;

namespace MatIdentity.Web.Infrastructure;

/// <summary>
/// The end of every sign-in (password alone, password and code, password and passkey, passkey alone): the session in the database, the cookie,
/// the line in the activity list. And the state between the password and the second step: a short cookie of its own (five minutes) that says
/// whose password was right, never a session.
/// </summary>
public static class SignInFlow
{
    /// <summary>The cookie between the password and the second step.</summary>
    public const string TwoFactorScheme = "MatIdentity.TwoFactor";

    private const string RememberClaim = "matidentity:remember";

    /// <summary>Wrong codes in a row before the person has to start with the password again.</summary>
    public const int MaxSecondStepAttempts = 5;

    public static async Task CompleteAsync(HttpContext http, User user, bool remember, string? how)
    {
        var services = http.RequestServices;
        var sessions = services.GetRequiredService<SessionService>();

        // A new sign-in replaces the session this browser had (another person may have used it).
        var previous = await http.AuthenticateAsync(AuthConstants.CookieScheme);
        if (previous.Succeeded && previous.Principal.GetSessionToken() is { } token)
        {
            await sessions.InvalidateAsync(token, http.RequestAborted);
        }

        var ip = http.Connection.RemoteIpAddress?.ToString();
        var session = await sessions.CreateAsync(user.Id, http.Request.Headers.UserAgent.ToString(), ip, http.RequestAborted);
        await http.SignInAsync(AuthConstants.CookieScheme, PrincipalFactory.Build(user, session.Token), new AuthenticationProperties { IsPersistent = remember });
        await http.SignOutAsync(TwoFactorScheme);
        services.GetRequiredService<IMemoryCache>().Remove(AttemptsKey(user.Id));
        await services.GetRequiredService<ActivityService>().WriteAsync(ActivityKind.SignIn, user, ipAddress: ip, detail: how, ct: http.RequestAborted);
    }

    /// <summary>
    /// Writes the cookie again with the current values of <paramref name="user"/> (a new theme, a password changed), for the same session and as persistent as
    /// it was: "stay signed in" survives it.
    /// </summary>
    public static async Task RenewCookieAsync(HttpContext http, User user)
    {
        var current = await http.AuthenticateAsync(AuthConstants.CookieScheme);
        await http.SignInAsync(AuthConstants.CookieScheme, PrincipalFactory.Build(user, http.User.GetSessionToken() ?? string.Empty),
            new AuthenticationProperties { IsPersistent = current.Properties?.IsPersistent ?? false });
    }

    /// <summary>Remembers that the password of <paramref name="user"/> was right; the second step is next.</summary>
    public static Task BeginSecondStepAsync(HttpContext http, User user, bool remember)
    {
        var identity = new ClaimsIdentity(
            [new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()), new Claim(RememberClaim, remember ? "true" : "false")],
            TwoFactorScheme);
        return http.SignInAsync(TwoFactorScheme, new ClaimsPrincipal(identity));
    }

    /// <summary>Whose password was right (and whether to stay signed in), or null when the five minutes are over or nobody started.</summary>
    public static async Task<(long UserId, bool Remember)?> PendingAsync(HttpContext http)
    {
        var result = await http.AuthenticateAsync(TwoFactorScheme);
        return result.Succeeded && long.TryParse(result.Principal.FindFirstValue(ClaimTypes.NameIdentifier), out var id)
            ? (id, result.Principal.FindFirstValue(RememberClaim) == "true")
            : null;
    }

    /// <summary>Counts a wrong code; true when the person has to start again (the pending state is gone then).</summary>
    public static async Task<bool> FailedAttemptAsync(HttpContext http, long userId)
    {
        var cache = http.RequestServices.GetRequiredService<IMemoryCache>();
        var attempts = cache.Get<int>(AttemptsKey(userId)) + 1;
        cache.Set(AttemptsKey(userId), attempts, TimeSpan.FromMinutes(15));
        if (attempts < MaxSecondStepAttempts)
        {
            return false;
        }

        cache.Remove(AttemptsKey(userId));
        await http.SignOutAsync(TwoFactorScheme);
        return true;
    }

    private static string AttemptsKey(long userId) => "second-step-attempts:" + userId;
}
