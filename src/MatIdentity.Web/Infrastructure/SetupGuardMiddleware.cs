using MatIdentity.Core.Users;

namespace MatIdentity.Web.Infrastructure;

/// <summary>Tracks whether first-run setup is complete, so the guard skips the DB check on every
/// request once at least one user exists. Registered as a singleton.</summary>
public sealed class SetupState
{
    public volatile bool Completed;
}

/// <summary>
/// On a fresh install (no users yet) every page is redirected to the first-run setup (<c>/Setup</c>), which creates the first administrator.
/// The static files, the platform API (<c>/api</c>: health must answer before the setup) and the discovery document stay reachable.
/// Once a user exists this becomes a no-op.
/// </summary>
public sealed class SetupGuardMiddleware
{
    private const string SetupPath = "/Setup";
    private readonly RequestDelegate _next;
    private readonly SetupState _state;

    public SetupGuardMiddleware(RequestDelegate next, SetupState state)
    {
        _next = next;
        _state = state;
    }

    public async Task InvokeAsync(HttpContext context, UserService users)
    {
        if (!_state.Completed)
        {
            if (await users.CountAsync(context.RequestAborted) > 0)
            {
                _state.Completed = true;
            }
            else if (!context.Request.Path.StartsWithSegments(SetupPath) && !Paths.IsOpenBeforeSignIn(context.Request.Path))
            {
                context.Response.Redirect(SetupPath);
                return;
            }
        }

        await _next(context);
    }
}

/// <summary>The addresses the guards leave alone.</summary>
public static class Paths
{
    private static readonly string[] Static = ["/css", "/js", "/img", "/matui", "/manifest.webmanifest", "/favicon.ico"];

    /// <summary>Files, the platform API and the machine side of OpenID Connect (discovery, keys, token, user info).</summary>
    public static bool IsOpenBeforeSignIn(PathString path)
        => Static.Any(p => path.StartsWithSegments(p))
           || path.StartsWithSegments("/api")
           || path.StartsWithSegments("/.well-known")
           || path.StartsWithSegments("/connect/token")
           || path.StartsWithSegments("/connect/userinfo")
           || path.StartsWithSegments("/connect/introspect")
           || path.StartsWithSegments("/connect/revoke")
           || path.StartsWithSegments("/connect/jwks");
}
