using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace MatIdentity.Tests;

/// <summary>The platform contract of MatDesign docs/PLATFORM.md as MatIdentity answers it: shapes, status codes, access, the rules of a definition.</summary>
[Collection(TestCollection.Name)]
public sealed partial class PlatformApiTests
{
    private readonly IdentityFactory _site;

    public PlatformApiTests(IdentityFactory site)
    {
        _site = site;
    }

    [Fact]
    public async Task Health_answers_without_a_key()
    {
        var response = await _site.CreateClient().GetAsync("/api/health");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal("ok", doc.RootElement.GetProperty("status").GetString());
        Assert.Equal("matidentity", doc.RootElement.GetProperty("app").GetString());
        Assert.Contains(doc.RootElement.GetProperty("checks").EnumerateArray(), c => c.GetProperty("name").GetString() == "database");
    }

    [Fact]
    public async Task The_definition_answers_without_a_key_and_with_an_etag()
    {
        var client = _site.CreateClient();
        var response = await client.GetAsync("/api");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var etag = response.Headers.ETag!.Tag;

        using var request = new HttpRequestMessage(HttpMethod.Get, "/api");
        request.Headers.TryAddWithoutValidation("If-None-Match", etag);
        Assert.Equal(HttpStatusCode.NotModified, (await client.SendAsync(request)).StatusCode);

        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(1, doc.RootElement.GetProperty("contract").GetInt32());
        Assert.Equal("matidentity", doc.RootElement.GetProperty("app").GetProperty("id").GetString());
        Assert.True(doc.RootElement.GetProperty("auth").GetProperty("apiKey").GetBoolean());
    }

    [Fact]
    public async Task The_definition_is_consistent_and_names_only_icons_of_the_sprite()
    {
        using var doc = JsonDocument.Parse(await _site.CreateClient().GetStringAsync("/api"));
        var root = doc.RootElement;
        var state = root.GetProperty("state").EnumerateArray().Select(s => s.GetProperty("key").GetString()!).ToHashSet();
        var fields = root.GetProperty("configure").EnumerateArray().Select(f => f.GetProperty("key").GetString()!).ToHashSet();
        var actions = root.GetProperty("actions").EnumerateArray().Select(a => a.GetProperty("id").GetString()!).ToHashSet();

        foreach (var section in root.GetProperty("pages").EnumerateArray().SelectMany(p => p.GetProperty("sections").EnumerateArray()))
        {
            var kind = section.GetProperty("kind").GetString();
            var known = kind switch { "tiles" => state, "form" => fields, "actions" => actions, _ => [] };
            foreach (var item in section.GetProperty("items").EnumerateArray().Select(i => i.GetString()!))
            {
                Assert.True(known.Contains(item), $"The {kind} section names {item}, which the definition does not have.");
            }
        }

        var sprite = SymbolRegex().Matches(File.ReadAllText(Path.Combine(WebRoot(), "matui", "matui-icons.svg"))).Select(m => m.Groups[1].Value).ToHashSet();
        var icons = root.GetProperty("pages").EnumerateArray().Select(p => p.GetProperty("icon").GetString()!)
            .Concat(root.GetProperty("actions").EnumerateArray().Select(a => a.GetProperty("icon").GetString()!))
            .Concat(root.GetProperty("state").EnumerateArray().Where(s => s.TryGetProperty("icon", out _)).Select(s => s.GetProperty("icon").GetString()!));
        Assert.All(icons, icon => Assert.True(sprite.Contains(icon), $"{icon} is not in the sprite"));
    }

    [Fact]
    public async Task State_configure_and_actions_need_the_key()
    {
        var anonymous = _site.CreateClient();
        Assert.Equal(HttpStatusCode.Unauthorized, (await anonymous.GetAsync("/api/state")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await anonymous.GetAsync("/api/configure")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await anonymous.PostAsync("/api/actions/signOutEveryone", null)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await anonymous.GetAsync("/api/v1/clients")).StatusCode);

        var wrong = _site.CreateClient();
        wrong.DefaultRequestHeaders.Add("X-Api-Key", "wrong");
        Assert.Equal(HttpStatusCode.Unauthorized, (await wrong.GetAsync("/api/state")).StatusCode);

        var api = _site.Api();
        using var state = JsonDocument.Parse(await api.GetStringAsync("/api/state"));
        Assert.True(state.RootElement.GetProperty("values").GetProperty("users").GetProperty("value").GetInt32() >= 1);
        Assert.Equal(HttpStatusCode.OK, (await api.GetAsync("/api/state/users")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await api.GetAsync("/api/state/nothing")).StatusCode);
    }

    [Fact]
    public async Task Configure_checks_every_value_and_saves_nothing_when_one_is_wrong()
    {
        var api = _site.Api();
        var bad = await api.PutAsJsonAsync("/api/configure", new { values = new { instanceName = "Home ID", sessionLifetimeDays = 0, nothing = 1 } });
        Assert.Equal(HttpStatusCode.BadRequest, bad.StatusCode);
        using (var errors = JsonDocument.Parse(await bad.Content.ReadAsStringAsync()))
        {
            Assert.True(errors.RootElement.GetProperty("errors").TryGetProperty("nothing", out _));
        }

        var unchanged = JsonDocument.Parse(await api.GetStringAsync("/api/configure"));
        Assert.NotEqual("Home ID", unchanged.RootElement.GetProperty("values").GetProperty("instanceName").GetString());

        var outOfRange = await api.PutAsJsonAsync("/api/configure", new { values = new { sessionLifetimeDays = 0 } });
        Assert.Equal(HttpStatusCode.BadRequest, outOfRange.StatusCode);

        var good = await api.PutAsJsonAsync("/api/configure", new { values = new { instanceName = "Home ID", sessionLifetimeDays = 30 } });
        Assert.Equal(HttpStatusCode.OK, good.StatusCode);
        using var saved = JsonDocument.Parse(await good.Content.ReadAsStringAsync());
        Assert.Equal("Home ID", saved.RootElement.GetProperty("values").GetProperty("instanceName").GetString());
        Assert.Equal(30, saved.RootElement.GetProperty("values").GetProperty("sessionLifetimeDays").GetInt32());

        // Back to the default, so the other tests see the usual name.
        await api.PutAsJsonAsync("/api/configure", new { values = new { instanceName = "MatIdentity", sessionLifetimeDays = 14 } });
    }

    [Fact]
    public async Task An_unknown_action_is_404()
        => Assert.Equal(HttpStatusCode.NotFound, (await _site.Api().PostAsync("/api/actions/nothing", null)).StatusCode);

    [Fact]
    public async Task The_client_api_never_returns_a_secret_again_and_deletes_only_its_own()
    {
        var api = _site.Api();
        var created = await api.PutAsJsonAsync("/api/v1/clients/matapitest", new { displayName = "Api test", redirectUris = new[] { "https://api.test/signin-oidc" }, managedBy = "mattiverse" });
        Assert.Equal(HttpStatusCode.OK, created.StatusCode);
        using (var first = JsonDocument.Parse(await created.Content.ReadAsStringAsync()))
        {
            Assert.False(string.IsNullOrEmpty(first.RootElement.GetProperty("clientSecret").GetString()));
        }

        var changed = await api.PutAsJsonAsync("/api/v1/clients/matapitest", new { displayName = "Api test 2" });
        using (var second = JsonDocument.Parse(await changed.Content.ReadAsStringAsync()))
        {
            Assert.False(second.RootElement.TryGetProperty("clientSecret", out _));
            Assert.Equal("Api test 2", second.RootElement.GetProperty("client").GetProperty("displayName").GetString());
            Assert.Equal("https://api.test/signin-oidc", second.RootElement.GetProperty("client").GetProperty("redirectUris")[0].GetString());
        }

        var listed = await api.GetStringAsync("/api/v1/clients");
        Assert.DoesNotContain("secret", listed, StringComparison.OrdinalIgnoreCase);

        var invalid = await api.PutAsJsonAsync("/api/v1/clients/Bad%20Id", new { displayName = "x", redirectUris = new[] { "https://x.test/cb" } });
        Assert.Equal(HttpStatusCode.BadRequest, invalid.StatusCode);

        Assert.Equal(HttpStatusCode.Conflict, (await api.DeleteAsync("/api/v1/clients/matapitest?managedBy=someone")).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await api.DeleteAsync("/api/v1/clients/matapitest?managedBy=mattiverse")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await api.GetAsync("/api/v1/clients/matapitest")).StatusCode);
    }

    [Fact]
    public async Task The_pages_ask_for_the_sign_in_and_open_after_it()
    {
        var browser = _site.Browser();
        var home = await browser.GetAsync("/Apps");
        Assert.Equal(HttpStatusCode.Redirect, home.StatusCode);
        Assert.StartsWith("/Account/Login", home.Headers.Location!.PathAndQuery.TrimStart());

        await IdentityFactory.SignInAsync(browser, "/Account/Login?returnUrl=%2FApps");
        await _site.Api().PutAsJsonAsync("/api/v1/clients/matpages", new { displayName = "Pages", redirectUris = new[] { "https://pages.test/signin-oidc" } });
        foreach (var page in new[] { "/", "/Apps", "/Apps/Edit", "/Apps/Edit?id=matpages", "/Apps/Access?id=matpages", "/Users", "/Users/Edit", "/Groups", "/Groups/Edit", "/Activity", "/Settings", "/Account/Profile", "/Account/Profile?tab=password", "/Account/Profile?tab=sessions", "/Account/Security", "/Account/Security?setup=true", "/Account/NoAccess?app=matpages" })
        {
            var response = await browser.GetAsync(page);
            Assert.True(response.StatusCode == HttpStatusCode.OK, $"{page}: {(int)response.StatusCode}");
            var html = await response.Content.ReadAsStringAsync();
            Assert.Contains("data-app=\"matidentity\"", html);
        }
    }

    private static string WebRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "MatIdentity.slnx")))
        {
            dir = dir.Parent;
        }

        return Path.Combine(dir!.FullName, "src", "MatIdentity.Web", "wwwroot");
    }

    [GeneratedRegex(@"<symbol id=""mat-i-([a-z0-9-]+)""")]
    private static partial Regex SymbolRegex();
}
