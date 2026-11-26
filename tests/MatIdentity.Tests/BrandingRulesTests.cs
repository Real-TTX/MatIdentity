using System.Text;
using MatIdentity.Core.Clients;
using MatIdentity.Web.Infrastructure;

namespace MatIdentity.Tests;

/// <summary>The rules of the look of a sign-in (docs/ARCHITECTURE.md "Branded sign-in"), without the site: the limits, the types, and where a brand comes from.</summary>
public sealed class BrandingRulesTests
{
    public const string SvgLogo = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10"><circle cx="5" cy="5" r="4" fill="#1d4ed8"/></svg>""";

    /// <summary>A PNG of one pixel.</summary>
    public const string PngBase64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==";

    public static string Base64(string text) => Convert.ToBase64String(Encoding.UTF8.GetBytes(text));

    /// <summary>The start of a JPEG and some bytes: what the check looks at.</summary>
    public static byte[] Jpeg(int length)
    {
        var bytes = new byte[length];
        bytes[0] = 0xFF;
        bytes[1] = 0xD8;
        bytes[2] = 0xFF;
        bytes[3] = 0xE0;
        return bytes;
    }

    private static BrandingInput Valid() => new()
    {
        Name = "MatOS",
        Accent = "#1d4ed8",
        HideIdentity = true,
        Logo = new BrandImageInput(BrandingRules.Svg, Base64(SvgLogo)),
        Background = new BrandImageInput(BrandingRules.Jpeg, Convert.ToBase64String(Jpeg(64))),
    };

    [Fact]
    public void A_valid_brand_has_no_errors_and_its_pictures_decoded()
    {
        var check = BrandingRules.Check(Valid());
        Assert.True(check.Succeeded, string.Join("; ", check.Errors.Values));
        Assert.Equal(SvgLogo, Encoding.UTF8.GetString(check.Logo!));
        Assert.Equal(64, check.Background!.Length);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void A_brand_has_a_name(string? name)
        => Assert.Contains("branding.name", BrandingRules.Check(Valid() with { Name = name }).Errors.Keys);

    [Fact]
    public void A_name_is_at_most_sixty_characters()
        => Assert.Contains("branding.name", BrandingRules.Check(Valid() with { Name = new string('a', BrandingRules.MaxNameLength + 1) }).Errors.Keys);

    [Theory]
    [InlineData("#1d4ed8", true)]
    [InlineData("#ABCDEF", true)]
    [InlineData("blue", false)]
    [InlineData("#abc", false)]
    [InlineData("#1d4ed8; background: red", false)]
    public void The_accent_is_six_hex_digits(string accent, bool valid)
        => Assert.Equal(valid, !BrandingRules.Check(Valid() with { Accent = accent }).Errors.ContainsKey("branding.accent"));

    [Fact]
    public void No_accent_is_fine() => Assert.True(BrandingRules.Check(Valid() with { Accent = null }).Succeeded);

    [Fact]
    public void A_logo_is_svg_or_png_and_at_most_256_KiB()
    {
        Assert.True(BrandingRules.Check(Valid() with { Logo = new BrandImageInput(BrandingRules.Png, PngBase64) }).Succeeded);
        Assert.Contains("branding.logo", BrandingRules.Check(Valid() with { Logo = new BrandImageInput(BrandingRules.Jpeg, Convert.ToBase64String(Jpeg(64))) }).Errors.Keys);

        var png = Convert.FromBase64String(PngBase64);
        var atLimit = new byte[BrandingRules.MaxLogoBytes];
        png.CopyTo(atLimit, 0);
        Assert.True(BrandingRules.Check(Valid() with { Logo = new BrandImageInput(BrandingRules.Png, Convert.ToBase64String(atLimit)) }).Succeeded);

        var tooLarge = new byte[BrandingRules.MaxLogoBytes + 1];
        png.CopyTo(tooLarge, 0);
        var errors = BrandingRules.Check(Valid() with { Logo = new BrandImageInput(BrandingRules.Png, Convert.ToBase64String(tooLarge)) }).Errors;
        Assert.Contains("256 KiB", errors["branding.logo"]);
    }

    [Fact]
    public void A_background_is_jpeg_png_or_webp_and_at_most_2_MiB()
    {
        var webp = new byte[32];
        "RIFF"u8.CopyTo(webp);
        "WEBP"u8.CopyTo(webp.AsSpan(8));
        Assert.True(BrandingRules.Check(Valid() with { Background = new BrandImageInput(BrandingRules.Webp, Convert.ToBase64String(webp)) }).Succeeded);
        Assert.Contains("branding.background", BrandingRules.Check(Valid() with { Background = new BrandImageInput(BrandingRules.Svg, Base64(SvgLogo)) }).Errors.Keys);
        Assert.True(BrandingRules.Check(Valid() with { Background = new BrandImageInput(BrandingRules.Jpeg, Convert.ToBase64String(Jpeg(BrandingRules.MaxBackgroundBytes))) }).Succeeded);
        var errors = BrandingRules.Check(Valid() with { Background = new BrandImageInput(BrandingRules.Jpeg, Convert.ToBase64String(Jpeg(BrandingRules.MaxBackgroundBytes + 1))) }).Errors;
        Assert.Contains("2 MiB", errors["branding.background"]);
    }

    [Fact]
    public void A_picture_is_what_its_type_says()
    {
        // An SVG sent as a PNG, a PNG sent as an SVG, text that is no SVG, bytes that are no Base64, nothing at all.
        Assert.Contains("branding.logo", BrandingRules.Check(Valid() with { Logo = new BrandImageInput(BrandingRules.Png, Base64(SvgLogo)) }).Errors.Keys);
        Assert.Contains("branding.logo", BrandingRules.Check(Valid() with { Logo = new BrandImageInput(BrandingRules.Svg, PngBase64) }).Errors.Keys);
        Assert.Contains("branding.logo", BrandingRules.Check(Valid() with { Logo = new BrandImageInput(BrandingRules.Svg, Base64("<html><body>hi</body></html>")) }).Errors.Keys);
        Assert.Contains("branding.logo", BrandingRules.Check(Valid() with { Logo = new BrandImageInput(BrandingRules.Svg, "not base64 at all!") }).Errors.Keys);
        Assert.Contains("branding.logo", BrandingRules.Check(Valid() with { Logo = new BrandImageInput(BrandingRules.Svg, string.Empty) }).Errors.Keys);
        Assert.Contains("branding.background", BrandingRules.Check(Valid() with { Background = new BrandImageInput(BrandingRules.Jpeg, PngBase64) }).Errors.Keys);
    }

    [Theory]
    [InlineData("MatOS", "MO")]
    [InlineData("My Cloud", "MC")]
    [InlineData("home", "H")]
    public void A_brand_without_a_logo_shows_its_first_letters(string name, string letters) => Assert.Equal(letters, BrandingRules.Letters(name));

    [Theory]
    [InlineData("/connect/authorize?client_id=matos&response_type=code", "matos")]
    [InlineData("/id/connect/authorize?response_type=code&client_id=matos", "matos")]
    [InlineData("/connect/authorize?response_type=code", null)]
    [InlineData("/Account/Profile?client_id=matos", null)]
    [InlineData("https://evil.example/connect/authorize?client_id=matos", null)]
    [InlineData("//evil.example/connect/authorize?client_id=matos", null)]
    [InlineData(null, null)]
    public void The_brand_of_a_sign_in_is_the_client_of_its_local_authorize_request(string? returnUrl, string? clientId)
        => Assert.Equal(clientId, SignInBranding.AuthorizeClientId(returnUrl));

    [Fact]
    public void The_stylesheet_of_a_brand_sets_its_accent_and_its_picture()
    {
        var brand = new BrandInfo { ClientId = "matos", Name = "MatOS", Accent = "#1d4ed8", BackgroundContentType = BrandingRules.Jpeg, BackgroundHash = "0123456789abcdef" };
        var css = BrandingEndpoints.Theme(brand);
        Assert.Contains("[data-app=\"brand\"] { --mat-app-accent: #1d4ed8; }", css);
        Assert.Contains("url(\"/branding/matos/background?v=0123456789abcdef\")", css);
        Assert.DoesNotContain("--mi-brand-image", BrandingEndpoints.Theme(brand with { BackgroundHash = null }));
    }

    [Fact]
    public void The_icon_of_a_brand_without_a_logo_escapes_its_name()
    {
        var svg = BrandingEndpoints.Icon(new BrandInfo { ClientId = "x", Name = "<b> & co", Accent = "#1d4ed8" });
        Assert.DoesNotContain("<b>", svg);
        Assert.Contains("fill=\"#1d4ed8\"", svg);
    }
}
