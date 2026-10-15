using MatIdentity.Core.Users;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;

namespace MatIdentity.Web.Infrastructure;

/// <summary>The few endpoints the pages' JavaScript uses (the theme).</summary>
public static class ApiEndpoints
{
    public static void MapThemeApi(this WebApplication app)
    {
        // Remembers the theme on the account (the browser applies it itself right away) and refreshes the cookie claim. The toolkit's theme button posts
        // the choice as a form (theme=system|light|dark) with the anti-forgery token of the page.
        app.MapPost("/api/theme", async (HttpContext http, IAntiforgery antiforgery, UserService users, CancellationToken ct) =>
        {
            try
            {
                await antiforgery.ValidateRequestAsync(http);
            }
            catch (AntiforgeryValidationException)
            {
                return Results.BadRequest();
            }

            var theme = http.Request.Form["theme"].ToString();
            var userId = http.User.GetUserId();
            if (userId is null || theme is not ("system" or "light" or "dark"))
            {
                return Results.BadRequest();
            }

            var user = await users.SetThemeAsync(userId.Value, theme, ct);
            if (user is null)
            {
                return Results.NotFound();
            }

            await http.SignInAsync(AuthConstants.CookieScheme, PrincipalFactory.Build(user, http.User.GetSessionToken() ?? string.Empty));
            return Results.NoContent();
        }).RequireAuthorization().DisableAntiforgery();
    }
}
