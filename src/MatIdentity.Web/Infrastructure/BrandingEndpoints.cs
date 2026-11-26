using System.Net;
using System.Text;
using MatIdentity.Core.Clients;
using Microsoft.Net.Http.Headers;

namespace MatIdentity.Web.Infrastructure;

/// <summary>
/// The pictures and the stylesheet of the brands of the sign-in (docs/ARCHITECTURE.md "Branded sign-in"), served from MatIdentity's own address, for anybody (the
/// sign-in shows them before anyone is signed in):
/// <code>
/// GET /branding/{clientId}/logo          the logo (image/svg+xml or image/png)
/// GET /branding/{clientId}/background    the background (image/jpeg, image/png or image/webp)
/// GET /branding/{clientId}/icon.svg      the icon of the tab without a logo: the first letters of the name on the accent
/// GET /branding/{clientId}/theme.css     the accent and the background of the brand's pages
/// </code>
/// Each with an ETag (304 for <c>If-None-Match</c>), a year of caching with the current <c>?v=</c> (the addresses the pages and the API give carry it), an hour without,
/// <c>X-Content-Type-Options: nosniff</c>, and for the pictures <c>Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; sandbox</c>: an SVG is only
/// ever shown through <c>&lt;img&gt;</c>, and opened by itself it runs nothing.
/// </summary>
public static class BrandingEndpoints
{
    public const string PicturePolicy = "default-src 'none'; style-src 'unsafe-inline'; sandbox";

    /// <summary>The address of a part of a brand with its version (<c>/branding/matos/logo?v=…</c>).</summary>
    public static string Path(string clientId, string part, string version) => $"/branding/{Uri.EscapeDataString(clientId)}/{part}?v={version}";

    public static void MapBrandingEndpoints(this WebApplication app)
    {
        var group = app.MapGroup("/branding/{clientId}").AllowAnonymous().DisableAntiforgery();

        group.MapGet("/logo", (string clientId, string? v, HttpContext http, BrandingService branding) => PictureAsync(clientId, BrandImageKind.Logo, v, http, branding));
        group.MapGet("/background", (string clientId, string? v, HttpContext http, BrandingService branding) => PictureAsync(clientId, BrandImageKind.Background, v, http, branding));

        group.MapGet("/icon.svg", async (string clientId, string? v, HttpContext http, BrandingService branding) =>
        {
            if (!ClientRules.IsValidClientId(clientId) || await branding.GetAsync(clientId, http.RequestAborted) is not { } brand)
            {
                return Results.NotFound();
            }

            var svg = Icon(brand);
            var hash = BrandingRules.Hash(Encoding.UTF8.GetBytes($"{brand.Name}|{brand.Accent}"));
            Headers(http, hash, v, picture: true);
            return Results.Bytes(Encoding.UTF8.GetBytes(svg), BrandingRules.Svg, entityTag: new EntityTagHeaderValue($"\"{hash}\""));
        });

        group.MapGet("/theme.css", async (string clientId, string? v, HttpContext http, BrandingService branding) =>
        {
            if (!ClientRules.IsValidClientId(clientId) || await branding.GetAsync(clientId, http.RequestAborted) is not { } brand)
            {
                return Results.NotFound();
            }

            Headers(http, brand.ThemeVersion, v, picture: false);
            return Results.Bytes(Encoding.UTF8.GetBytes(Theme(brand)), "text/css; charset=utf-8", entityTag: new EntityTagHeaderValue($"\"{brand.ThemeVersion}\""));
        });
    }

    /// <summary>
    /// What the brand changes in the toolkit's look: its accent (<c>--mat-app-accent</c> of <c>[data-app="brand"]</c>, which the toolkit turns into every shade, light and
    /// dark) and its background picture (<c>--mi-brand-image</c>; <c>matidentity.css</c> lays it over a gradient from the accent).
    /// </summary>
    public static string Theme(BrandInfo brand)
    {
        var css = new StringBuilder("/* The look of a branded sign-in. */\n");
        if (brand.Accent is { } accent && BrandingRules.IsValidAccent(accent))
        {
            css.Append("[data-app=\"brand\"] { --mat-app-accent: ").Append(accent).Append("; }\n");
        }

        if (brand.BackgroundHash is { } background)
        {
            css.Append(".mi-brand { --mi-brand-image: url(\"").Append(Path(brand.ClientId, "background", background)).Append("\"); }\n");
        }

        return css.ToString();
    }

    /// <summary>A tile with the first letters of the name on the accent (the toolkit's default without one).</summary>
    public static string Icon(BrandInfo brand)
    {
        var fill = brand.Accent is { } accent && BrandingRules.IsValidAccent(accent) ? accent : "#5b5fe6";
        var letters = WebUtility.HtmlEncode(BrandingRules.Letters(brand.Name));
        var size = letters.Length > 1 ? 26 : 34;
        return "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 64 64\">" +
               $"<rect width=\"64\" height=\"64\" rx=\"14\" fill=\"{fill}\"/>" +
               $"<text x=\"32\" y=\"{32 + (size * 0.35):0}\" font-family=\"system-ui, -apple-system, Segoe UI, sans-serif\" font-size=\"{size}\" font-weight=\"700\" text-anchor=\"middle\" fill=\"#ffffff\">{letters}</text>" +
               "</svg>";
    }

    private static async Task<IResult> PictureAsync(string clientId, BrandImageKind kind, string? v, HttpContext http, BrandingService branding)
    {
        if (!ClientRules.IsValidClientId(clientId) || await branding.ImageAsync(clientId, kind, http.RequestAborted) is not { } image)
        {
            return Results.NotFound();
        }

        Headers(http, image.Hash, v, picture: true);
        return Results.Bytes(image.Data, image.ContentType, entityTag: new EntityTagHeaderValue($"\"{image.Hash}\""));
    }

    private static void Headers(HttpContext http, string hash, string? version, bool picture)
    {
        var headers = http.Response.Headers;
        headers.CacheControl = version == hash ? "public, max-age=31536000, immutable" : "public, max-age=3600";
        headers.XContentTypeOptions = "nosniff";
        if (picture)
        {
            headers.ContentSecurityPolicy = PicturePolicy;
        }
    }
}
