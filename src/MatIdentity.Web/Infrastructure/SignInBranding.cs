using MatIdentity.Core.Clients;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.WebUtilities;

namespace MatIdentity.Web.Infrastructure;

/// <summary>
/// The brand of the sign-in a request belongs to (docs/ARCHITECTURE.md "Branded sign-in"): the pages Login, Forgot, Reset, TwoFactor, Register, Verify, NoAccess,
/// AccessDenied, ChangePassword, the sign-out question (Logout) and the error pages (StatusCode, Error) look like the app whose sign-in it is (its name, logo,
/// accent, background) and, when the app hides MatIdentity, show nothing of it.
/// <para>
/// Where the brand comes from, first match wins: the request of an app in the <c>returnUrl</c> (query or form; the <c>client_id</c> of a local
/// <c>/connect/authorize</c> or <c>/connect/logout</c>, and an app without a brand ends the brand), the OpenID Connect request being answered (an error page of
/// <c>/connect/authorize</c>), then <c>?brand=&lt;clientId&gt;</c> (the links of the mails) and <c>?app=</c> of NoAccess, else the cookie <c>mid.brand</c>
/// (30 minutes), which carries it through the flow (Forgot, the mail, Reset, back to the sign-in). The request of the app always wins over <c>?brand</c>: a page
/// never shows one app's brand while it signs the person in to another. A brand is looked up only for the id of a registered app.
/// </para>
/// </summary>
public static class SignInBranding
{
    public const string CookieName = "mid.brand";

    public const string QueryKey = "brand";

    public static readonly TimeSpan CookieLifetime = TimeSpan.FromMinutes(30);

    /// <summary>The pages of a sign-in that take a brand.</summary>
    public static readonly IReadOnlyList<string> Pages =
        ["/Account/Login", "/Account/Forgot", "/Account/Reset", "/Account/TwoFactor", "/Account/Register", "/Account/Verify", "/Account/NoAccess", "/Account/AccessDenied",
         "/Account/ChangePassword", "/Account/Logout", "/Error"];

    /// <summary>The error pages of a status (<c>/StatusCode/429</c>, ...): they take the brand too.</summary>
    public const string StatusCodePrefix = "/StatusCode";

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

    /// <summary>The pages of the account that take a brand when a link names it (<see cref="AccountBrandAsync"/>).</summary>
    public static readonly IReadOnlyList<string> AccountPages = ["/Account/Profile", "/Account/Security"];

    private static readonly object AccountItemKey = new();

    /// <summary>
    /// The brand of a page of the account (<see cref="AccountPages"/>), or null: only the <c>?brand=&lt;clientId&gt;</c> of the request names it (a broker's link to its
    /// person's password or second step, e.g. MatOS's tab Security), never the cookie of a sign-in, so MatIdentity's own account stays its own. The pages carry the
    /// <c>brand</c> on in their links, forms and redirects. A brand is looked up only for the id of a registered app with a look.
    /// </summary>
    public static async Task<SignInBrand?> AccountBrandAsync(HttpContext http)
    {
        ArgumentNullException.ThrowIfNull(http);
        if (http.Items.TryGetValue(AccountItemKey, out var known))
        {
            return known as SignInBrand;
        }

        var brand = await LookUpAsync(http, http.Request.Query[QueryKey].ToString());
        http.Items[AccountItemKey] = brand;
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
            if (IsBrandedPage(http.Request.Path))
            {
                await ResolveAsync(http);
            }

            await next(http);
        });

    /// <summary>Whether a path is one of the pages that take a brand (the pages of a sign-in, and the error pages of a status).</summary>
    public static bool IsBrandedPage(PathString path)
        => Pages.Any(p => path.Equals(p, StringComparison.OrdinalIgnoreCase)) || path.StartsWithSegments(StatusCodePrefix, StringComparison.OrdinalIgnoreCase);

    /// <summary>An error page, re-executed for another request: its body is not read again (the cookie carries the brand there).</summary>
    private static bool IsErrorPage(PathString path)
        => path.StartsWithSegments(StatusCodePrefix, StringComparison.OrdinalIgnoreCase) || path.Equals("/Error", StringComparison.OrdinalIgnoreCase);

    /// <summary>The client id the request names, and whether it names one at all (a request of an app without a brand names "none").</summary>
    private static async Task<(string? ClientId, bool Named)> NamedAsync(HttpContext http)
    {
        var request = http.Request;

        // The request of an app the page continues with decides: a ?brand beside it would dress up the sign-in of one app as another's.
        var returnUrl = request.Query["returnUrl"].ToString();
        if (returnUrl.Length == 0 && HttpMethods.IsPost(request.Method) && request.HasFormContentType && !IsErrorPage(request.Path))
        {
            returnUrl = (await request.ReadFormAsync(http.RequestAborted))["ReturnUrl"].ToString();
        }

        if (AppRequestClientId(returnUrl) is { } requested)
        {
            return (requested, true);
        }

        // An error page of an endpoint of OpenID Connect (a request OpenIddict refused, shown by /StatusCode): the app that sent it.
        if (http.GetOpenIddictServerRequest()?.ClientId is { Length: > 0 } answering)
        {
            return (answering, true);
        }

        if (request.Query[QueryKey].ToString() is { Length: > 0 } brand)
        {
            return (brand, true);
        }

        if (request.Path.Equals("/Account/NoAccess", StringComparison.OrdinalIgnoreCase) && request.Query["app"].ToString() is { Length: > 0 } app)
        {
            return (app, true);
        }

        return (null, false);
    }

    /// <summary>The <c>client_id</c> of a local address of the authorize endpoint (<c>/connect/authorize?client_id=…</c>), else null.</summary>
    public static string? AuthorizeClientId(string? returnUrl) => EndpointClientId(returnUrl, "/connect/authorize");

    /// <summary>The <c>client_id</c> of a local address of the authorize or the end-session endpoint (<c>/connect/logout?client_id=…</c>), else null.</summary>
    public static string? AppRequestClientId(string? returnUrl)
        => EndpointClientId(returnUrl, "/connect/authorize") ?? EndpointClientId(returnUrl, "/connect/logout");

    private static string? EndpointClientId(string? returnUrl, string endpoint)
    {
        if (!LocalUrl.IsLocal(returnUrl))
        {
            return null;
        }

        var question = returnUrl!.IndexOf('?', StringComparison.Ordinal);
        var path = question < 0 ? returnUrl : returnUrl[..question];
        if (question < 0 || !path.EndsWith(endpoint, StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        return QueryHelpers.ParseQuery(returnUrl[question..]).TryGetValue("client_id", out var id) && id.ToString() is { Length: > 0 } value ? value : null;
    }

    /// <summary>
    /// The brand a caller of the API names for the mails it triggers (header <see cref="MailBrandHeader"/>: the client id of a branded app, sent by the broker that
    /// manages it, e.g. MatOS for the invitation and the new password of its people), or null. An id that is not a branded app is ignored: the mail is MatIdentity's.
    /// </summary>
    public static async Task<BrandInfo?> MailBrandAsync(HttpContext http)
        => http.Request.Headers[MailBrandHeader].ToString().Trim() is { Length: > 0 } clientId ? (await LookUpAsync(http, clientId))?.Info : null;

    /// <summary>The header of <see cref="MailBrandAsync"/>.</summary>
    public const string MailBrandHeader = "X-Mat-Brand";

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
