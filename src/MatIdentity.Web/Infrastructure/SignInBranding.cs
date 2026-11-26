using MatIdentity.Core.Clients;
using Microsoft.AspNetCore.WebUtilities;

namespace MatIdentity.Web.Infrastructure;

/// <summary>
/// The brand of the sign-in a request belongs to (docs/ARCHITECTURE.md "Branded sign-in"): the pages Login, Forgot, Reset, TwoFactor, Register, Verify, NoAccess and
/// AccessDenied look like the app whose sign-in it is (its name, logo, accent, background) and, when the app hides MatIdentity, show nothing of it.
/// <para>
/// Where the brand comes from, first match wins: <c>?brand=&lt;clientId&gt;</c> (the links of the mails), <c>?app=</c> of NoAccess, the authorize request in the
/// <c>returnUrl</c> (query or form; its <c>client_id</c>, and an app without a brand ends the brand), else the cookie <c>mid.brand</c> (30 minutes), which carries
/// it through the flow (Forgot, the mail, Reset, back to the sign-in). A brand is looked up only for the id of a registered app.
/// </para>
/// </summary>
public static class SignInBranding
{
    public const string CookieName = "mid.brand";

    public const string QueryKey = "brand";

    public static readonly TimeSpan CookieLifetime = TimeSpan.FromMinutes(30);

    /// <summary>The pages of a sign-in that take a brand.</summary>
    public static readonly IReadOnlyList<string> Pages =
        ["/Account/Login", "/Account/Forgot", "/Account/Reset", "/Account/TwoFactor", "/Account/Register", "/Account/Verify", "/Account/NoAccess", "/Account/AccessDenied"];

    private static readonly object ItemKey = new();

    /// <summary>
    /// The brand of this request, or null (worked out once per request). It also keeps the cookie in step: set when the request names a brand, removed when it names an
    /// app without one; a page of the sign-in works it out before its answer starts (<see cref="UseSignInBranding"/>).
    /// </summary>
    public static async Task<SignInBrand?> ResolveAsync(HttpContext http)
    {
        ArgumentNullException.ThrowIfNull(http);
        if (http.Items.TryGetValue(ItemKey, out var known))
        {
            return known as SignInBrand;
        }

        var (clientId, named) = await NamedAsync(http);
        clientId ??= named ? null : http.Request.Cookies[CookieName];
        var brand = await LookUpAsync(http, clientId);
        http.Items[ItemKey] = brand;

        if (named && !http.Response.HasStarted)
        {
            if (brand is not null)
            {
                http.Response.Cookies.Append(CookieName, brand.ClientId, new CookieOptions
                {
                    HttpOnly = true,
                    SameSite = SameSiteMode.Lax,
                    Secure = http.Request.IsHttps,
                    IsEssential = true,
                    MaxAge = CookieLifetime,
                    Path = "/",
                });
            }
            else if (http.Request.Cookies.ContainsKey(CookieName))
            {
                http.Response.Cookies.Delete(CookieName, new CookieOptions { Path = "/" });
            }
        }

        return brand;
    }

    /// <summary>The brand of this request when it is known already (the layout, after <see cref="ResolveAsync"/>).</summary>
    public static SignInBrand? Current(HttpContext http) => http.Items.TryGetValue(ItemKey, out var known) ? known as SignInBrand : null;

    /// <summary>
    /// Where a sign-in goes on: the request it came from (a local address), else the address of the branded app (a sign-in of MatOS that started at a link of a mail
    /// ends in MatOS, not on the home page of MatIdentity), else <c>/</c>.
    /// </summary>
    public static string ContinueTo(HttpContext http, string? returnUrl)
    {
        if (LocalUrl.IsLocal(returnUrl) && returnUrl != "/")
        {
            return returnUrl!;
        }

        return Current(http)?.HomeUrl ?? "/";
    }

    /// <summary>Works out the brand at the start of every page of a sign-in, so its cookie can still be set (the layout renders after the answer has begun).</summary>
    public static IApplicationBuilder UseSignInBranding(this IApplicationBuilder app)
        => app.Use(async (http, next) =>
        {
            if (Pages.Any(p => http.Request.Path.Equals(p, StringComparison.OrdinalIgnoreCase)))
            {
                await ResolveAsync(http);
            }

            await next(http);
        });

    /// <summary>The client id the request names, and whether it names one at all (an authorize request of an app without a brand names "none").</summary>
    private static async Task<(string? ClientId, bool Named)> NamedAsync(HttpContext http)
    {
        var request = http.Request;
        if (request.Query[QueryKey].ToString() is { Length: > 0 } brand)
        {
            return (brand, true);
        }

        if (request.Path.Equals("/Account/NoAccess", StringComparison.OrdinalIgnoreCase) && request.Query["app"].ToString() is { Length: > 0 } app)
        {
            return (app, true);
        }

        var returnUrl = request.Query["returnUrl"].ToString();
        if (returnUrl.Length == 0 && HttpMethods.IsPost(request.Method) && request.HasFormContentType)
        {
            returnUrl = (await request.ReadFormAsync(http.RequestAborted))["ReturnUrl"].ToString();
        }

        return AuthorizeClientId(returnUrl) is { } clientId ? (clientId, true) : (null, false);
    }

    /// <summary>The <c>client_id</c> of a local address of the authorize endpoint (<c>/connect/authorize?client_id=…</c>), else null.</summary>
    public static string? AuthorizeClientId(string? returnUrl)
    {
        if (!LocalUrl.IsLocal(returnUrl))
        {
            return null;
        }

        var question = returnUrl!.IndexOf('?', StringComparison.Ordinal);
        var path = question < 0 ? returnUrl : returnUrl[..question];
        if (question < 0 || !path.EndsWith("/connect/authorize", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        return QueryHelpers.ParseQuery(returnUrl[question..]).TryGetValue("client_id", out var id) && id.ToString() is { Length: > 0 } value ? value : null;
    }

    /// <summary>The brand of a registered app, or null (an id that is not an app's never reaches the database of brands).</summary>
    private static async Task<SignInBrand?> LookUpAsync(HttpContext http, string? clientId)
    {
        if (!ClientRules.IsValidClientId(clientId))
        {
            return null;
        }

        var services = http.RequestServices;
        if (await services.GetRequiredService<ClientService>().GetAsync(clientId!, http.RequestAborted) is not { } client
            || await services.GetRequiredService<BrandingService>().GetAsync(clientId!, http.RequestAborted) is not { } info)
        {
            return null;
        }

        return new SignInBrand(info, client.HomeUrl);
    }
}

/// <summary>The brand of a sign-in as the pages use it: the brand, the address of the app, and the addresses of its pictures and stylesheet.</summary>
public sealed record SignInBrand(BrandInfo Info, string? HomeUrl)
{
    public string ClientId => Info.ClientId;

    public string Name => Info.Name;

    public bool HideIdentity => Info.HideIdentity;

    /// <summary>The first letters of the name, for the tile when there is no logo.</summary>
    public string Letters => BrandingRules.Letters(Info.Name);

    public string? LogoUrl => Info.LogoHash is { } hash ? BrandingEndpoints.Path(ClientId, "logo", hash) : null;

    public string ThemeUrl => BrandingEndpoints.Path(ClientId, "theme.css", Info.ThemeVersion);

    /// <summary>The icon of the tab: the logo, else a tile with the first letters in the accent.</summary>
    public string IconUrl => LogoUrl ?? BrandingEndpoints.Path(ClientId, "icon.svg", BrandingRules.Hash(System.Text.Encoding.UTF8.GetBytes($"{Info.Name}|{Info.Accent}")));

    public string? IconType => Info.LogoContentType ?? BrandingRules.Svg;
}
