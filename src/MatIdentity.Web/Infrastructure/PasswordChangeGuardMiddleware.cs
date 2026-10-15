namespace MatIdentity.Web.Infrastructure;

/// <summary>
/// While a user is flagged <c>MustChangePassword</c> (e.g. the seeded admin), this middleware sends every page to the password tab of the account,
/// with the address that was asked for as <c>returnUrl</c>: an app that sent the person here to sign in gets them back after the change.
/// Account pages, sign-out, files and the machine endpoints stay open.
/// </summary>
public sealed class PasswordChangeGuardMiddleware
{
    private const string ChangePasswordPath = "/Account/Profile";
    private readonly RequestDelegate _next;

    public PasswordChangeGuardMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var user = context.User;
        var path = context.Request.Path;
        if (user.Identity?.IsAuthenticated == true && user.MustChangePassword()
            && !path.StartsWithSegments("/Account")
            && !path.StartsWithSegments("/connect/logout")
            && !Paths.IsOpenBeforeSignIn(path))
        {
            var target = ChangePasswordPath + "?tab=password";
            if (HttpMethods.IsGet(context.Request.Method))
            {
                target += "&returnUrl=" + Uri.EscapeDataString(context.Request.PathBase + path + context.Request.QueryString);
            }

            context.Response.Redirect(target);
            return;
        }

        await _next(context);
    }
}
