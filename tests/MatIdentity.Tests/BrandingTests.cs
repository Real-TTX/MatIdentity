using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using MatIdentity.Core.Entities;
using MatIdentity.Core.Users;
using Microsoft.Extensions.DependencyInjection;

namespace MatIdentity.Tests;

/// <summary>
/// The branded sign-in (docs/ARCHITECTURE.md "Branded sign-in"): an app that a broker gave a look (MatOS) has its sign-in in its own look and, when it hides
/// MatIdentity, without a trace of it; every other app keeps MatIdentity's sign-in as it was. The pictures, the limits, the API and the way through Forgot and Reset.
/// </summary>
[Collection(TestCollection.Name)]
public sealed partial class BrandingTests
{
    private const string Redirect = "https://os.example.test/signin-oidc";
    private const string Home = "https://os.example.test/";

    private readonly IdentityFactory _site;

    public BrandingTests(IdentityFactory site)
    {
        _site = site;
    }

    [Fact]
    public async Task A_branded_sign_in_shows_the_app_and_nothing_of_MatIdentity()
    {
        await BrandAsync("matos-look");
        var browser = _site.Browser();
        var login = await LoginUrlAsync(browser, "matos-look");
        var response = await browser.GetAsync(login);
        var html = await response.Content.ReadAsStringAsync();

        Assert.Contains("Sign in to MatOS", html);
        Assert.Contains("<title>Sign in · MatOS</title>", WebUtility.HtmlDecode(html));
        Assert.Contains("data-app=\"brand\"", html);
        Assert.Contains("/branding/matos-look/logo?v=", html);
        Assert.Contains("/branding/matos-look/theme.css?v=", html);
        Assert.Contains("mi-brand", html);
        Assert.DoesNotContain("Sign in once, for all your apps.", html);
        Assert.DoesNotContain("/img/logo.svg", html);
        Assert.DoesNotContain("/img/favicon.svg", html);
        Assert.DoesNotContain("manifest", html);
        AssertNoIdentity(html);

        // The brand is kept for the rest of the flow, for half an hour, and only for this site.
        var cookie = Assert.Single(response.Headers.GetValues("Set-Cookie"), c => c.StartsWith("mid.brand=", StringComparison.Ordinal));
        Assert.Contains("mid.brand=matos-look", cookie);
        Assert.Contains("httponly", cookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("samesite=lax", cookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("max-age=1800", cookie, StringComparison.OrdinalIgnoreCase);

        // The form works as always and goes back to the request of the app.
        Assert.StartsWith("/connect/authorize", await IdentityFactory.SignInAsync(browser, login));
    }

    [Fact]
    public async Task Every_other_sign_in_stays_MatIdentitys_also_right_after_a_branded_one()
    {
        await BrandAsync("matos-before");
        await RegisterAsync("plain-app", branding: null);
        var browser = _site.Browser();

        var branded = await browser.GetStringAsync(await LoginUrlAsync(browser, "matos-before"));
        Assert.Contains("Sign in to MatOS", branded);

        // The cookie of the branded sign-in does not dress up the sign-in of another app: that app's request ends the brand.
        var response = await browser.GetAsync(await LoginUrlAsync(browser, "plain-app"));
        var html = await response.Content.ReadAsStringAsync();
        AssertMatIdentity(html);
        Assert.Contains("Sign in once, for all your apps.", html);
        Assert.Contains(response.Headers.GetValues("Set-Cookie"), c => c.StartsWith("mid.brand=;", StringComparison.Ordinal));

        // MatIdentity's own sign-in is as it was.
        AssertMatIdentity(await _site.Browser().GetStringAsync("/Account/Login"));
    }

    [Fact]
    public async Task An_unknown_or_unbranded_app_gives_no_brand()
    {
        await RegisterAsync("plain-named", branding: null);
        AssertMatIdentity(await _site.Browser().GetStringAsync("/Account/Login?brand=nobody-here"));
        AssertMatIdentity(await _site.Browser().GetStringAsync("/Account/Login?brand=plain-named"));
        AssertMatIdentity(await _site.Browser().GetStringAsync("/Account/Login?brand=Not%20an%20id"));

        // A cookie the browser made up names nothing either.
        var browser = _site.Browser();
        using var request = new HttpRequestMessage(HttpMethod.Get, "/Account/Login");
        request.Headers.Add("Cookie", "mid.brand=nobody-here");
        AssertMatIdentity(await (await browser.SendAsync(request)).Content.ReadAsStringAsync());

        Assert.Equal(HttpStatusCode.NotFound, (await _site.Browser().GetAsync("/branding/nobody-here/logo")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await _site.Browser().GetAsync("/branding/plain-named/theme.css")).StatusCode);
    }

    [Fact]
    public async Task The_logo_is_served_with_a_policy_that_runs_nothing_and_is_cached()
    {
        await BrandAsync("matos-svg");
        var url = (await GetBrandingAsync("matos-svg")).GetProperty("logoUrl").GetString()!;
        Assert.StartsWith("http://localhost/branding/matos-svg/logo?v=", url);

        var browser = _site.Browser();
        var response = await browser.GetAsync(new Uri(url).PathAndQuery);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("image/svg+xml", response.Content.Headers.ContentType!.MediaType);
        Assert.Equal(BrandingRulesTests.SvgLogo, await response.Content.ReadAsStringAsync());
        Assert.StartsWith("default-src 'none'; style-src 'unsafe-inline'; sandbox", string.Join(", ", response.Headers.GetValues("Content-Security-Policy")));
        Assert.Equal("nosniff", string.Join(", ", response.Headers.GetValues("X-Content-Type-Options")));
        Assert.Contains("immutable", response.Headers.CacheControl!.ToString());
        var etag = response.Headers.ETag!;

        using var again = new HttpRequestMessage(HttpMethod.Get, new Uri(url).PathAndQuery);
        again.Headers.IfNoneMatch.Add(etag);
        Assert.Equal(HttpStatusCode.NotModified, (await browser.SendAsync(again)).StatusCode);

        // The stylesheet of the brand: its accent; and the icon of the tab.
        var css = await browser.GetStringAsync("/branding/matos-svg/theme.css");
        Assert.Contains("--mat-app-accent: #1d4ed8", css);
        var icon = await browser.GetAsync("/branding/matos-svg/icon.svg");
        Assert.Equal(HttpStatusCode.OK, icon.StatusCode);
        Assert.Contains("sandbox", string.Join(", ", icon.Headers.GetValues("Content-Security-Policy")));
    }

    [Fact]
    public async Task The_API_checks_the_limits_and_saves_nothing_that_is_wrong()
    {
        var png = Convert.FromBase64String(BrandingRulesTests.PngBase64);
        var tooLarge = new byte[(256 * 1024) + 1];
        png.CopyTo(tooLarge, 0);

        var cases = new (object Branding, string Field)[]
        {
            (new { name = "MatOS", logo = new { contentType = "image/png", data = Convert.ToBase64String(tooLarge) } }, "branding.logo"),
            (new { name = "MatOS", background = new { contentType = "image/jpeg", data = Convert.ToBase64String(BrandingRulesTests.Jpeg((2 * 1024 * 1024) + 1)) } }, "branding.background"),
            (new { name = "MatOS", logo = new { contentType = "image/gif", data = BrandingRulesTests.PngBase64 } }, "branding.logo"),
            (new { name = "MatOS", logo = new { contentType = "image/png", data = BrandingRulesTests.Base64(BrandingRulesTests.SvgLogo) } }, "branding.logo"),
            (new { name = "MatOS", accent = "blue" }, "branding.accent"),
            (new { accent = "#1d4ed8" }, "branding.name"),
            ("MatOS", "branding"),
        };

        foreach (var (branding, field) in cases)
        {
            var response = await _site.Api().PutAsJsonAsync("/api/v1/clients/matos-limits", Body(branding));
            var text = await response.Content.ReadAsStringAsync();
            Assert.True(response.StatusCode == HttpStatusCode.BadRequest, field + ": " + text);
            using var doc = JsonDocument.Parse(text);
            Assert.True(doc.RootElement.GetProperty("errors").TryGetProperty(field, out _), field + ": " + text);
        }

        // Nothing was saved: not the app, not its look.
        Assert.Equal(HttpStatusCode.NotFound, (await _site.Api().GetAsync("/api/v1/clients/matos-limits")).StatusCode);
    }

    [Fact]
    public async Task The_API_answers_the_look_without_the_pictures_keeps_it_and_removes_it()
    {
        await BrandAsync("matos-api", background: true);
        var brand = await GetBrandingAsync("matos-api");
        Assert.Equal("MatOS", brand.GetProperty("name").GetString());
        Assert.Equal("#1d4ed8", brand.GetProperty("accent").GetString());
        Assert.True(brand.GetProperty("hideIdentity").GetBoolean());
        Assert.True(brand.GetProperty("hasLogo").GetBoolean());
        Assert.True(brand.GetProperty("hasBackground").GetBoolean());
        Assert.Equal("image/svg+xml", brand.GetProperty("logoContentType").GetString());
        Assert.Contains("/branding/matos-api/background?v=", brand.GetProperty("backgroundUrl").GetString());
        Assert.False(brand.TryGetProperty("data", out _));
        Assert.DoesNotContain(BrandingRulesTests.Base64(BrandingRulesTests.SvgLogo), await _site.Api().GetStringAsync("/api/v1/clients"));

        // A PUT without branding keeps it; a branding without the pictures keeps them; null removes a picture.
        await PutAsync("matos-api", new { displayName = "MatOS", managedBy = "matos" });
        Assert.True((await GetBrandingAsync("matos-api")).GetProperty("hasLogo").GetBoolean());
        await PutAsync("matos-api", Body(new { name = "MatOS Home", accent = "#0f766e", hideIdentity = true }));
        brand = await GetBrandingAsync("matos-api");
        Assert.Equal("MatOS Home", brand.GetProperty("name").GetString());
        Assert.True(brand.GetProperty("hasLogo").GetBoolean());
        Assert.True(brand.GetProperty("hasBackground").GetBoolean());
        await PutAsync("matos-api", Body(new { name = "MatOS", logo = (object?)null }));
        brand = await GetBrandingAsync("matos-api");
        Assert.False(brand.GetProperty("hasLogo").GetBoolean());
        Assert.True(brand.GetProperty("hasBackground").GetBoolean());
        Assert.False(brand.GetProperty("hideIdentity").GetBoolean());

        // "branding": null removes the whole look, and its pictures are gone.
        var background = new Uri(brand.GetProperty("backgroundUrl").GetString()!).PathAndQuery;
        await PutAsync("matos-api", new { managedBy = "matos", branding = (object?)null });
        Assert.Equal(JsonValueKind.Null, (await GetClientAsync("matos-api")).GetProperty("branding").ValueKind);
        Assert.Equal(HttpStatusCode.NotFound, (await _site.Browser().GetAsync(background)).StatusCode);
    }

    [Fact]
    public async Task Only_the_manager_of_an_app_gives_it_a_look_and_it_goes_with_the_app()
    {
        await BrandAsync("matos-owned");
        var other = await _site.Api().PutAsJsonAsync("/api/v1/clients/matos-owned", new { managedBy = "someone-else", branding = new { name = "Phish" } });
        Assert.Equal(HttpStatusCode.Conflict, other.StatusCode);
        var unnamed = await _site.Api().PutAsJsonAsync("/api/v1/clients/matos-owned", new { branding = new { name = "Phish" } });
        Assert.Equal(HttpStatusCode.Conflict, unnamed.StatusCode);
        Assert.Equal("MatOS", (await GetBrandingAsync("matos-owned")).GetProperty("name").GetString());

        // Removing the app removes its look: a new app of the same id starts without it.
        Assert.Equal(HttpStatusCode.NoContent, (await _site.Api().DeleteAsync("/api/v1/clients/matos-owned?managedBy=matos")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await _site.Browser().GetAsync("/branding/matos-owned/logo")).StatusCode);
        await RegisterAsync("matos-owned", branding: null);
        Assert.Equal(JsonValueKind.Null, (await GetClientAsync("matos-owned")).GetProperty("branding").ValueKind);
    }

    [Fact]
    public async Task The_brand_goes_with_a_forgotten_password_through_the_mail_to_the_new_password()
    {
        await BrandAsync("matos-forgot");
        using (var scope = _site.Services.CreateScope())
        {
            await scope.ServiceProvider.GetRequiredService<UserService>().CreateAsync("brandforget", "Brand Forget", "brandforget@example.test", "Person-Pass-1", UserRole.User);
        }

        var browser = _site.Browser();
        var login = await LoginUrlAsync(browser, "matos-forgot");
        var returnUrl = WebUtility.UrlDecode(login["/Account/Login?returnUrl=".Length..]);
        var forgotPage = "/Account/Forgot?returnUrl=" + Uri.EscapeDataString(returnUrl);
        await browser.GetStringAsync(login);
        var forgot = await browser.GetStringAsync(forgotPage);
        Assert.Contains("/branding/matos-forgot/logo", forgot);
        AssertNoIdentity(forgot);

        var asked = await IdentityFactory.PostFormAsync(browser, forgotPage, new() { ["Login"] = "brandforget", ["ReturnUrl"] = returnUrl });
        var sent = await asked.Content.ReadAsStringAsync();
        Assert.Contains("the link is on its way", sent);
        AssertNoIdentity(sent);

        // The mail speaks of MatOS and its link carries the brand.
        var mail = await _site.Mails.WaitForAsync("brandforget@example.test", "set a new password");
        Assert.StartsWith("MatOS:", mail.Subject);
        Assert.Contains("your account at MatOS", mail.Text);
        Assert.DoesNotContain("MatIdentity", mail.Text);
        var link = LinkRegex().Match(mail.Text);
        Assert.True(link.Success, mail.Text);
        Assert.Contains("&brand=matos-forgot", link.Value);

        // Opened in another browser (no cookie): the page of the link is MatOS's, and so is the sign-in after it.
        var other = _site.Browser();
        var reset = new Uri(link.Value).PathAndQuery;
        var page = await other.GetStringAsync(reset);
        Assert.Contains("Set a new password", page);
        Assert.Contains("/branding/matos-forgot/logo", page);
        AssertNoIdentity(page);
        var set = await IdentityFactory.PostFormAsync(other, reset, new() { ["Token"] = link.Groups[1].Value, ["Input.Password"] = "Brand-Pass-2024", ["Input.ConfirmPassword"] = "Brand-Pass-2024" });
        Assert.Equal(HttpStatusCode.Redirect, set.StatusCode);
        var back = set.Headers.Location!.OriginalString;
        Assert.Equal("/Account/Login?passwordSet=true&brand=matos-forgot", back, ignoreCase: true);
        var signIn = await other.GetStringAsync(back);
        Assert.Contains("Sign in to MatOS", signIn);
        Assert.Contains("Your password is set.", signIn);
        AssertNoIdentity(signIn);

        // Without a request of the app to go back to, the sign-in ends in the app, not on MatIdentity's home page.
        Assert.Equal(Home, await IdentityFactory.SignInAsync(other, back, "brandforget", "Brand-Pass-2024"));
    }

    [Fact]
    public async Task The_request_of_the_app_decides_the_brand_not_a_brand_named_beside_it()
    {
        await BrandAsync("matos-mask");
        await RegisterAsync("plain-target", branding: null);
        var browser = _site.Browser();
        await browser.GetStringAsync(await LoginUrlAsync(browser, "matos-mask"));

        // A link that names MatOS's brand but signs in to another app: the page is that app's sign-in (MatIdentity's), and the brand of the flow ends.
        var login = await LoginUrlAsync(browser, "plain-target");
        var response = await browser.GetAsync(login + "&brand=matos-mask");
        var html = await response.Content.ReadAsStringAsync();
        AssertMatIdentity(html);
        Assert.Contains(response.Headers.GetValues("Set-Cookie"), c => c.StartsWith("mid.brand=;", StringComparison.Ordinal));
        AssertMatIdentity(await browser.GetStringAsync("/Account/Forgot"));
    }

    [Fact]
    public async Task The_sign_out_question_of_a_branded_app_is_in_its_look()
    {
        await BrandAsync("matos-out");
        await CreatePersonAsync("brandout", mustChange: false);
        var browser = _site.Browser();
        await IdentityFactory.SignInAsync(browser, "/Account/Login", "brandout", "Person-Pass-1");

        // A sign-out of the app without the ID token of the person: the question comes, in the look of the app, and Cancel goes back to it.
        var logout = await browser.GetAsync($"/connect/logout?client_id=matos-out&post_logout_redirect_uri={Uri.EscapeDataString(Home)}");
        Assert.Equal(HttpStatusCode.Redirect, logout.StatusCode);
        var question = logout.Headers.Location!.OriginalString;
        Assert.StartsWith("/Account/Logout?returnUrl=", question);
        var html = await browser.GetStringAsync(question);
        Assert.Contains("Sign out?", html);
        Assert.Contains("/branding/matos-out/logo", html);
        Assert.Contains($"href=\"{Home}\"", html);
        AssertNoIdentity(html);
    }

    [Fact]
    public async Task An_error_during_a_branded_sign_in_stays_in_its_look()
    {
        await BrandAsync("matos-error");
        var browser = _site.Browser();
        await browser.GetStringAsync(await LoginUrlAsync(browser, "matos-error"));

        var html = await browser.GetStringAsync("/StatusCode/429");
        Assert.Contains("Too many attempts", html);
        Assert.Contains("/branding/matos-error/logo", html);
        Assert.Contains($"href=\"{Home}\"", html);
        AssertNoIdentity(html);

        // A request of the app that MatIdentity refuses names the app itself.
        var refused = await _site.Browser().GetAsync($"/connect/authorize?client_id=matos-error&response_type=code&scope=openid&redirect_uri={Uri.EscapeDataString("https://elsewhere.example.test/cb")}");
        var page = await refused.Content.ReadAsStringAsync();
        Assert.Contains("/branding/matos-error/logo", page);
        AssertNoIdentity(page);

        AssertMatIdentity(await _site.Browser().GetStringAsync("/StatusCode/404"));
    }

    [Fact]
    public async Task A_password_that_must_change_is_changed_in_the_look_of_the_sign_in()
    {
        await BrandAsync("matos-change");
        await CreatePersonAsync("brandchange", mustChange: true);
        var browser = _site.Browser();
        var login = await LoginUrlAsync(browser, "matos-change");
        var authorize = await IdentityFactory.SignInAsync(browser, login, "brandchange", "Person-Pass-1");
        var guard = await browser.GetAsync(authorize);
        Assert.Equal(HttpStatusCode.Redirect, guard.StatusCode);
        var change = guard.Headers.Location!.OriginalString;
        Assert.StartsWith("/Account/ChangePassword?returnUrl=", change);

        var html = await browser.GetStringAsync(change);
        Assert.Contains("Set your own password", html);
        Assert.Contains("/branding/matos-change/logo", html);
        AssertNoIdentity(html);

        var saved = await IdentityFactory.PostFormAsync(browser, change, new()
        {
            ["Input.CurrentPassword"] = "Person-Pass-1",
            ["Input.NewPassword"] = "Brand-Change-2024",
            ["Input.ConfirmPassword"] = "Brand-Change-2024",
            ["ReturnUrl"] = authorize,
        });
        Assert.Equal(HttpStatusCode.Redirect, saved.StatusCode);
        Assert.Equal(authorize, saved.Headers.Location!.OriginalString);

        // Without a brand the step is the password tab of the account, as before.
        await CreatePersonAsync("plainchange", mustChange: true);
        var plain = _site.Browser();
        await IdentityFactory.SignInAsync(plain, "/Account/Login", "plainchange", "Person-Pass-1");
        var step = await plain.GetAsync("/Account/ChangePassword?returnUrl=%2F");
        Assert.Equal("/Account/Profile?tab=password&returnUrl=%2F", step.Headers.Location!.OriginalString);
    }

    [Fact]
    public async Task A_broker_names_its_brand_for_the_mails_of_its_people()
    {
        await BrandAsync("matos-mail");
        var subject = await CreatePersonAsync("brandmail", mustChange: false);

        using var request = new HttpRequestMessage(HttpMethod.Post, $"/api/v1/people/{subject}/actions/resetPassword");
        request.Headers.Add("X-Mat-Brand", "matos-mail");
        Assert.True((await _site.Api().SendAsync(request)).IsSuccessStatusCode);
        var mail = await _site.Mails.WaitForAsync("brandmail@example.test", "set a new password");
        Assert.StartsWith("MatOS:", mail.Subject);
        Assert.DoesNotContain("MatIdentity", mail.Text);
        Assert.Contains("&brand=matos-mail", mail.Text);

        using var invite = new HttpRequestMessage(HttpMethod.Post, $"/api/v1/people/{subject}/actions/invite");
        invite.Headers.Add("X-Mat-Brand", "matos-mail");
        Assert.True((await _site.Api().SendAsync(invite)).IsSuccessStatusCode);
        var invitation = await _site.Mails.WaitForAsync("brandmail@example.test", "your account");
        Assert.Equal("MatOS: your account", invitation.Subject);
        Assert.DoesNotContain("MatIdentity", invitation.Text);
        Assert.Contains("&brand=matos-mail", invitation.Text);
    }

    [Fact]
    public async Task The_account_opened_from_a_link_of_the_app_is_in_its_look_and_keeps_it()
    {
        await BrandAsync("matos-account");
        await RegisterAsync("plain-account", branding: null);
        await CreatePersonAsync("brandaccount", mustChange: false);
        var browser = _site.Browser();
        await IdentityFactory.SignInAsync(browser, "/Account/Login", "brandaccount", "Person-Pass-1");

        // The second step, as MatOS's tab Security links it: the app's look, its way back, nothing of MatIdentity, every link and form keeps the brand.
        var security = await browser.GetStringAsync("/Account/Security?brand=matos-account");
        Assert.Contains("data-app=\"brand\"", security);
        Assert.Contains("mi-brand-page", security);
        Assert.Contains("/branding/matos-account/theme.css?v=", security);
        Assert.Contains("<title>Account · MatOS</title>", WebUtility.HtmlDecode(security));
        Assert.Contains($"href=\"{Home}\"", security);
        Assert.Contains("Back to MatOS", security);
        Assert.Contains("Authenticator app", security);
        Assert.Contains("data-passkey-register", security);
        Assert.Contains("/Account/Security?brand=matos-account&amp;handler=Begin", security);
        Assert.Contains("/Account/Profile?tab=password&amp;brand=matos-account", security);
        Assert.DoesNotContain("mat-nav", security);
        AssertNoIdentity(security);

        // Setting up the app goes on in the look, and the authenticator app shows the app's name.
        var begin = await IdentityFactory.PostFormAsync(browser, "/Account/Security?brand=matos-account", new(), "/Account/Security?handler=Begin&brand=matos-account");
        Assert.Equal(HttpStatusCode.Redirect, begin.StatusCode);
        var setup = begin.Headers.Location!.OriginalString;
        Assert.Contains("brand=matos-account", setup);
        var scan = await browser.GetStringAsync(setup);
        Assert.Contains("QR code for your authenticator app", scan);
        Assert.Contains("/Account/Security?brand=matos-account&amp;handler=Confirm", scan);
        AssertNoIdentity(scan);

        // The sign-in password, as MatOS's tab Password links it.
        var password = await browser.GetStringAsync("/Account/Profile?tab=password&brand=matos-account");
        Assert.Contains("data-app=\"brand\"", password);
        Assert.Contains("Change password", password);
        AssertNoIdentity(password);

        // MatIdentity's own account stays its own: without ?brand (the cookie of a branded sign-in names none here), for an app without a look, for an unknown id.
        AssertMatIdentity(await browser.GetStringAsync("/Account/Security"));
        AssertMatIdentity(await browser.GetStringAsync("/Account/Security?brand=plain-account"));
        AssertMatIdentity(await browser.GetStringAsync("/Account/Profile?brand=nobody-here"));
        var cookieOnly = new HttpRequestMessage(HttpMethod.Get, "/Account/Profile");
        cookieOnly.Headers.Add("Cookie", "mid.brand=matos-account");
        var shell = await (await browser.SendAsync(cookieOnly)).Content.ReadAsStringAsync();
        Assert.Contains("mat-nav", shell);
        Assert.DoesNotContain("mi-brand", shell);
    }

    private async Task<string> CreatePersonAsync(string username, bool mustChange)
    {
        using var scope = _site.Services.CreateScope();
        var user = await scope.ServiceProvider.GetRequiredService<UserService>()
            .CreateAsync(username, "Brand Person", username + "@example.test", "Person-Pass-1", UserRole.User, mustChangePassword: mustChange);
        return user.Subject;
    }

    [GeneratedRegex(@"http://localhost/Account/Reset\?token=([A-Za-z0-9_-]+)&brand=[a-z0-9_-]+")]
    private static partial Regex LinkRegex();

    /// <summary>No word of MatIdentity in a page (its own stylesheet and script are files with that name, which nobody sees).</summary>
    private static void AssertNoIdentity(string html)
    {
        var visible = html.Replace("/css/matidentity.css", string.Empty, StringComparison.Ordinal).Replace("/js/matidentity.js", string.Empty, StringComparison.Ordinal);
        Assert.DoesNotContain("matidentity", visible, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("/img/logo.svg", visible);
    }

    /// <summary>MatIdentity's own sign-in, unchanged: its name, logo, accent and manifest.</summary>
    private static void AssertMatIdentity(string html)
    {
        Assert.Contains("data-app=\"matidentity\"", html);
        Assert.Contains("/img/logo.svg", html);
        Assert.Contains("/img/favicon.svg", html);
        Assert.Contains("manifest.webmanifest", html);
        Assert.DoesNotContain("mi-brand", html);
        Assert.DoesNotContain("/branding/", html);
        Assert.DoesNotContain("Sign in to MatOS", html);
    }

    /// <summary>The sign-in an app sends a person to: its authorize request, which redirects to the form.</summary>
    private static async Task<string> LoginUrlAsync(HttpClient browser, string clientId)
    {
        var challenge = Convert.ToBase64String(SHA256.HashData(Encoding.ASCII.GetBytes("verifier-" + Guid.NewGuid().ToString("N")))).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var authorize = $"/connect/authorize?client_id={clientId}&response_type=code&scope={Uri.EscapeDataString("openid profile email")}" +
                        $"&redirect_uri={Uri.EscapeDataString(Redirect)}&code_challenge={challenge}&code_challenge_method=S256&state=xyz";
        var response = await browser.GetAsync(authorize);
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        var login = response.Headers.Location!.OriginalString;
        Assert.StartsWith("/Account/Login?returnUrl=", login);
        return login;
    }

    /// <summary>MatOS as a broker registers its own client with its look (an SVG logo, an accent, MatIdentity hidden).</summary>
    private Task BrandAsync(string clientId, bool background = false)
        => RegisterAsync(clientId, new
        {
            name = "MatOS",
            accent = "#1d4ed8",
            hideIdentity = true,
            logo = new { contentType = "image/svg+xml", data = BrandingRulesTests.Base64(BrandingRulesTests.SvgLogo) },
            background = background ? new { contentType = "image/jpeg", data = Convert.ToBase64String(BrandingRulesTests.Jpeg(512)) } : null,
        });

    private Task RegisterAsync(string clientId, object? branding)
        => PutAsync(clientId, Body(branding));

    private static Registration Body(object? branding) => new("MatOS", Home, [Redirect], [Home], "matos", branding);

    private async Task PutAsync(string clientId, object body)
    {
        var response = await _site.Api().PutAsJsonAsync($"/api/v1/clients/{clientId}", body);
        Assert.True(response.IsSuccessStatusCode, await response.Content.ReadAsStringAsync());
    }

    private async Task<JsonElement> GetClientAsync(string clientId)
    {
        using var doc = JsonDocument.Parse(await _site.Api().GetStringAsync($"/api/v1/clients/{clientId}"));
        return doc.RootElement.Clone();
    }

    private async Task<JsonElement> GetBrandingAsync(string clientId) => (await GetClientAsync(clientId)).GetProperty("branding");

    /// <summary>A client as MatOS registers it (with its mark), and the look of its sign-in.</summary>
    private sealed record Registration(string DisplayName, string HomeUrl, string[] RedirectUris, string[] PostLogoutRedirectUris, string ManagedBy, object? Branding);
}
