using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using MatIdentity.Core.Access;
using MatIdentity.Web.Platform;
using MatPlatform;
using Microsoft.Extensions.DependencyInjection;

namespace MatIdentity.Tests;

/// <summary>
/// MatIdentity as the provider of <c>identity.oidc</c> (MatDesign docs/PLATFORM.md, "Bindings"): a binding is an OpenID Connect client, made the same way as one of
/// <c>/api/v1/clients</c>; the broker endpoints <c>/api/bindings</c> and the Connections area of an administrator.
/// </summary>
[Collection(TestCollection.Name)]
public sealed partial class IdentityBindingTests
{
    private const string Bindings = "/api/bindings/identity.oidc/";

    private readonly IdentityFactory _site;

    public IdentityBindingTests(IdentityFactory site)
    {
        _site = site;
    }

    private static StringContent Json(object body) => new(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json");

    private static object Body(string name, object? consumer = null, Dictionary<string, string>? parameters = null, bool renew = false, string managedBy = "mattiverse") => new
    {
        version = 1,
        managedBy,
        consumer = consumer ?? new { name, url = "https://drive.example.test", urls = new[] { "https://drive.example.test", "http://nas.local:4810/" }, internalUrl = "http://mattiverse-matdrive-web:4810" },
        provider = new { url = "https://id.example.test", internalUrl = "http://mattiverse-matidentity-matidentity:2300" },
        @params = parameters ?? new Dictionary<string, string>(),
        renew,
    };

    private async Task<JsonElement> BindAsync(string consumer, object body)
    {
        var response = await _site.Api().PutAsync(Bindings + consumer, Json(body));
        var text = await response.Content.ReadAsStringAsync();
        Assert.True(response.StatusCode == HttpStatusCode.OK, $"{(int)response.StatusCode}: {text}");
        return JsonDocument.Parse(text).RootElement.GetProperty("variables").Clone();
    }

    private async Task<JsonElement?> ClientAsync(string clientId)
    {
        var response = await _site.Api().GetAsync("/api/v1/clients/" + clientId);
        return response.StatusCode == HttpStatusCode.NotFound ? null : JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement.Clone();
    }

    private static string[] Strings(JsonElement array) => [.. array.EnumerateArray().Select(e => e.GetString()!)];

    /// <summary>What the token endpoint says to a secret: 401 when it does not authenticate the client, 400 (the made-up refresh token) when it does.</summary>
    private async Task<HttpStatusCode> TokenEndpointAsync(string clientId, string secret)
        => (await _site.CreateClient().PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token",
            ["refresh_token"] = "made-up",
            ["client_id"] = clientId,
            ["client_secret"] = secret,
        }))).StatusCode;

    [Fact]
    public async Task The_definition_is_valid_and_offers_identity_oidc_and_uses_mail_smtp()
    {
        var sprite = MatPlatformValidator.ReadSprite(Path.Combine(WebRoot(), "matui", "matui-icons.svg"));
        foreach (var smtp in new[] { new MatSmtpSettings(), new MatSmtpSettings { Host = "matsmtp", FromAddress = "id@example.test" } })
        {
            foreach (var language in MatPlatformOptions.Languages)
            {
                var definition = MatPlatformBuilder.Build(o => IdentityPlatform.Describe(o, smtp), language);
                Assert.Empty(MatPlatformValidator.Validate(definition, sprite));
            }
        }

        // The definition the site answers, in both languages: the words of the capability follow the caller.
        foreach (var (language, label) in new[] { ("en", "Signs people in for"), ("de", "Meldet Personen an für") })
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, "/api");
            request.Headers.AcceptLanguage.ParseAdd(language);
            var json = await (await _site.CreateClient().SendAsync(request)).Content.ReadAsStringAsync();
            Assert.Empty(MatPlatformValidator.Validate(json, sprite));
            using var doc = JsonDocument.Parse(json);
            var provided = Assert.Single(doc.RootElement.GetProperty("provides").EnumerateArray());
            Assert.Equal(MatCapabilities.IdentityOidc, provided.GetProperty("capability").GetString());
            Assert.Equal(1, provided.GetProperty("version").GetInt32());
            Assert.Equal(label, provided.GetProperty("label").GetString());
            var consumed = Assert.Single(doc.RootElement.GetProperty("consumes").EnumerateArray());
            Assert.Equal(MatCapabilities.MailSmtp, consumed.GetProperty("capability").GetString());
            Assert.True(consumed.GetProperty("optional").GetBoolean());
            Assert.Contains("/api/bindings", Strings(doc.RootElement.GetProperty("endpoints")));
        }
    }

    [Fact]
    public async Task A_binding_is_a_client_for_every_address_with_the_back_channel_at_the_internal_one_and_the_roles_of_the_app()
    {
        // The app names its roles in its /api (contract 2, with members MatIdentity does not know); MatIdentity reads them at the internal address.
        _site.AppDefinitions["http://mattiverse-matdrive-web:4810/api"] = """
            { "contract": 2, "app": { "id": "matdrive", "name": "MatDrive" }, "contributes": { "launchers": [ { "id": "drive" } ] },
              "roles": [ { "key": "owner", "label": "Owner" }, { "key": "viewer", "label": "Viewer" } ] }
            """;

        var variables = await BindAsync("matdrive", Body("MatDrive"));

        // The four variables of identity.oidc: the authority is MatIdentity's public address (the issuer), not the one the broker guessed.
        Assert.Equal(
            ["MATIDENTITY_AUTHORITY", "MATIDENTITY_INTERNAL_URL", "MATIDENTITY_CLIENT_ID", "MATIDENTITY_CLIENT_SECRET"],
            variables.EnumerateObject().Select(p => p.Name).ToArray());
        Assert.Equal("http://localhost", variables.GetProperty("MATIDENTITY_AUTHORITY").GetString());
        Assert.Equal("http://mattiverse-matidentity-matidentity:2300", variables.GetProperty("MATIDENTITY_INTERNAL_URL").GetString());
        Assert.Equal("matdrive", variables.GetProperty("MATIDENTITY_CLIENT_ID").GetString());
        var secret = variables.GetProperty("MATIDENTITY_CLIENT_SECRET").GetString()!;
        Assert.Equal(43, secret.Length);

        var client = (await ClientAsync("matdrive"))!.Value;
        Assert.Equal("MatDrive", client.GetProperty("displayName").GetString());
        Assert.Equal("https://drive.example.test", client.GetProperty("homeUrl").GetString());
        Assert.Equal(["https://drive.example.test/signin-oidc", "http://nas.local:4810/signin-oidc"], Strings(client.GetProperty("redirectUris")));
        Assert.Equal(["https://drive.example.test/signout-callback-oidc", "http://nas.local:4810/signout-callback-oidc"], Strings(client.GetProperty("postLogoutRedirectUris")));
        Assert.Equal("http://mattiverse-matdrive-web:4810/signout-backchannel", client.GetProperty("backchannelLogoutUri").GetString());
        Assert.Equal("mattiverse", client.GetProperty("managedBy").GetString());
        Assert.True(client.GetProperty("allowSignIn").GetBoolean());
        Assert.False(client.GetProperty("allowMachine").GetBoolean());
        Assert.False(client.GetProperty("isPublic").GetBoolean());

        using (var scope = _site.Services.CreateScope())
        {
            var permissions = scope.ServiceProvider.GetRequiredService<PermissionService>();
            Assert.Equal(["owner", "viewer"], (await permissions.RolesAsync("matdrive")).Select(r => r.Key).ToArray());
            var policy = await permissions.PolicyAsync("matdrive");
            Assert.False(policy.CallsAllApps);
        }

        // The secret signs the app in at the token endpoint.
        Assert.Equal(HttpStatusCode.BadRequest, await TokenEndpointAsync("matdrive", secret));
        await _site.Api().DeleteAsync(Bindings + "matdrive?managedBy=mattiverse");
    }

    [Fact]
    public async Task The_parameters_of_the_consumer_name_its_paths_and_an_empty_backchannel_means_none()
    {
        var consumer = new { name = "MatCustom", urls = new[] { "https://custom.example.test/" }, internalUrl = "http://custom:8080/" };
        await BindAsync("matcustom", Body("MatCustom", consumer, new Dictionary<string, string> { ["callback"] = "/auth/callback", ["signedOut"] = "auth/out", ["backchannel"] = "" }));

        var client = (await ClientAsync("matcustom"))!.Value;
        Assert.Equal(["https://custom.example.test/auth/callback"], Strings(client.GetProperty("redirectUris")));
        Assert.Equal(["https://custom.example.test/auth/out"], Strings(client.GetProperty("postLogoutRedirectUris")));
        Assert.False(client.TryGetProperty("backchannelLogoutUri", out _));

        // Another path of the back-channel logout, at the internal address.
        await BindAsync("matcustom", Body("MatCustom", consumer, new Dictionary<string, string> { ["backchannel"] = "/bc" }));
        Assert.Equal("http://custom:8080/bc", (await ClientAsync("matcustom"))!.Value.GetProperty("backchannelLogoutUri").GetString());
        await _site.Api().DeleteAsync(Bindings + "matcustom?managedBy=mattiverse");
    }

    [Fact]
    public async Task Binding_again_hands_out_no_secret_and_a_renewed_secret_replaces_the_old_one_at_once()
    {
        var first = (await BindAsync("matrenew", Body("MatRenew"))).GetProperty("MATIDENTITY_CLIENT_SECRET").GetString()!;

        // The same request again is the same client: no secret (the broker keeps the one it got), the name follows.
        var again = await BindAsync("matrenew", Body("MatRenew 2"));
        Assert.True(again.GetProperty("MATIDENTITY_CLIENT_SECRET").GetProperty("isSet").GetBoolean());
        Assert.Equal("matrenew", again.GetProperty("MATIDENTITY_CLIENT_ID").GetString());
        Assert.Equal("MatRenew 2", (await ClientAsync("matrenew"))!.Value.GetProperty("displayName").GetString());
        Assert.Equal(HttpStatusCode.BadRequest, await TokenEndpointAsync("matrenew", first));

        var renewed = (await BindAsync("matrenew", Body("MatRenew 2", renew: true))).GetProperty("MATIDENTITY_CLIENT_SECRET").GetString()!;
        Assert.NotEqual(first, renewed);
        // RFC 6749, 5.2: the old secret no longer authenticates the client (401), the new one does (400 for the made-up refresh token).
        Assert.Equal(HttpStatusCode.Unauthorized, await TokenEndpointAsync("matrenew", first));
        Assert.Equal(HttpStatusCode.BadRequest, await TokenEndpointAsync("matrenew", renewed));
        await _site.Api().DeleteAsync(Bindings + "matrenew?managedBy=mattiverse");
    }

    [Fact]
    public async Task The_list_shows_the_clients_with_a_mark_and_a_binding_is_removed_only_with_its_mark()
    {
        var api = _site.Api();
        await BindAsync("matlisted", Body("MatListed"));
        Assert.Equal(HttpStatusCode.OK, (await api.PutAsJsonAsync("/api/v1/clients/matscripted", new { displayName = "Scripted", redirectUris = new[] { "https://s.test/signin-oidc" }, managedBy = "script" })).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await api.PutAsJsonAsync("/api/v1/clients/matunmarked", new { displayName = "Unmarked", redirectUris = new[] { "https://u.test/signin-oidc" } })).StatusCode);

        using (var list = JsonDocument.Parse(await api.GetStringAsync("/api/bindings")))
        {
            var bindings = list.RootElement.GetProperty("bindings").EnumerateArray().ToList();
            var listed = Assert.Single(bindings, b => b.GetProperty("consumer").GetString() == "matlisted");
            Assert.Equal(MatCapabilities.IdentityOidc, listed.GetProperty("capability").GetString());
            Assert.Equal("MatListed", listed.GetProperty("name").GetString());
            Assert.Equal("mattiverse", listed.GetProperty("managedBy").GetString());
            Assert.True(listed.GetProperty("since").GetDateTimeOffset() > DateTimeOffset.UtcNow.AddMinutes(-5));
            Assert.Contains(bindings, b => b.GetProperty("consumer").GetString() == "matscripted" && b.GetProperty("managedBy").GetString() == "script");
            // An app added without a mark (under Apps) is no binding.
            Assert.DoesNotContain(bindings, b => b.GetProperty("consumer").GetString() == "matunmarked");
        }

        // Only with its own mark (or none given); never an app without a mark.
        Assert.Equal(HttpStatusCode.NotFound, (await api.DeleteAsync(Bindings + "matlisted?managedBy=manual")).StatusCode);
        Assert.NotNull(await ClientAsync("matlisted"));
        Assert.Equal(HttpStatusCode.NoContent, (await api.DeleteAsync(Bindings + "matlisted?managedBy=mattiverse")).StatusCode);
        Assert.Null(await ClientAsync("matlisted"));
        Assert.Equal(HttpStatusCode.NotFound, (await api.DeleteAsync(Bindings + "matlisted?managedBy=mattiverse")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await api.DeleteAsync(Bindings + "matunmarked")).StatusCode);
        Assert.NotNull(await ClientAsync("matunmarked"));
        Assert.Equal(HttpStatusCode.NoContent, (await api.DeleteAsync(Bindings + "matscripted")).StatusCode);

        // /api/v1 keeps its own rule: an empty mark removes the app without one.
        Assert.Equal(HttpStatusCode.NoContent, (await api.DeleteAsync("/api/v1/clients/matunmarked?managedBy=")).StatusCode);
    }

    [Fact]
    public async Task A_consumer_id_of_one_letter_gets_a_client_id_of_two()
    {
        var variables = await BindAsync("x", Body("X"));
        Assert.Equal("x-app", variables.GetProperty("MATIDENTITY_CLIENT_ID").GetString());
        Assert.NotNull(await ClientAsync("x-app"));
        Assert.Equal(HttpStatusCode.NoContent, (await _site.Api().DeleteAsync(Bindings + "x?managedBy=mattiverse")).StatusCode);
        Assert.Null(await ClientAsync("x-app"));
    }

    [Fact]
    public async Task Only_the_key_changes_bindings()
    {
        var anonymous = _site.CreateClient();
        Assert.Equal(HttpStatusCode.Unauthorized, (await anonymous.GetAsync("/api/bindings")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await anonymous.PutAsync(Bindings + "matnokey", Json(Body("No key")))).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await anonymous.GetAsync("/api/connections")).StatusCode);
        Assert.Null(await ClientAsync("matnokey"));

        // A capability MatIdentity does not provide, a version it does not speak.
        var api = _site.Api();
        Assert.Equal(HttpStatusCode.NotFound, (await api.PutAsync("/api/bindings/office.edit/matdrive", Json(Body("MatDrive")))).StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, (await api.PutAsync(Bindings + "matdrive", Json(new { version = 2, managedBy = "mattiverse", consumer = new { name = "MatDrive" } }))).StatusCode);
        Assert.Null(await ClientAsync("matdrive"));
    }

    [Fact]
    public async Task A_client_that_cannot_be_saved_is_refused_with_its_reason_not_a_failure()
    {
        // An address that is not one: MatPlatform 2.2.0 answers 400 with the reason (MatBindingRefusedException), never a 500.
        var refused = await _site.Api().PutAsync(Bindings + "matbroken", Json(Body("Broken", new { name = "Broken", url = "not an address", internalUrl = "http://mattiverse-matbroken-web:80" })));
        Assert.Equal(HttpStatusCode.BadRequest, refused.StatusCode);
        var errors = JsonDocument.Parse(await refused.Content.ReadAsStringAsync()).RootElement.GetProperty("errors");
        Assert.Contains("matbroken", errors.EnumerateObject().First().Value.GetString(), StringComparison.Ordinal);
        Assert.Null(await ClientAsync("matbroken"));
    }

    [Fact]
    public async Task An_administrator_connects_an_app_by_hand_and_sees_its_values_once()
    {
        var browser = await _site.AdminAsync();

        // English like the rest of MatIdentity, whatever language the browser asks for.
        using (var german = new HttpRequestMessage(HttpMethod.Get, "/Connections"))
        {
            german.Headers.AcceptLanguage.ParseAdd("de-DE");
            var page = await (await browser.SendAsync(german)).Content.ReadAsStringAsync();
            Assert.Contains("Connect an app by hand", page);
            Assert.Contains("Signs people in for", page);
            Assert.Contains("mail.smtp", page);
            Assert.DoesNotContain("Bietet an", page);
        }

        var connected = await PostAsync(browser, new() { ["do"] = "connect", ["name"] = "MatDrive Hand" });
        Assert.Contains("Connected: MatDrive Hand", connected);
        var secret = Value(connected, "MATIDENTITY_CLIENT_SECRET");
        Assert.Equal("matdrive-hand", Value(connected, "MATIDENTITY_CLIENT_ID"));
        Assert.Equal("http://localhost", Value(connected, "MATIDENTITY_AUTHORITY"));
        Assert.Equal(HttpStatusCode.BadRequest, await TokenEndpointAsync("matdrive-hand", secret));

        // Once: the next view shows the connection, not the secret.
        var later = await browser.GetStringAsync("/Connections");
        Assert.Contains("matdrive-hand", later);
        Assert.DoesNotContain(secret, later);

        // A client without addresses yet (they are added under Apps), marked as made by hand.
        var client = (await ClientAsync("matdrive-hand"))!.Value;
        Assert.Equal("manual", client.GetProperty("managedBy").GetString());
        Assert.Equal("MatDrive Hand", client.GetProperty("displayName").GetString());
        Assert.Empty(Strings(client.GetProperty("redirectUris")));

        // The addresses an administrator added stay when the secret is renewed here.
        Assert.Equal(HttpStatusCode.OK, (await _site.Api().PutAsJsonAsync("/api/v1/clients/matdrive-hand", new { redirectUris = new[] { "https://hand.test/signin-oidc" } })).StatusCode);
        var renewed = Value(await PostAsync(browser, new() { ["do"] = "renew", ["consumer"] = "matdrive-hand" }), "MATIDENTITY_CLIENT_SECRET");
        Assert.NotEqual(secret, renewed);
        Assert.Equal(HttpStatusCode.Unauthorized, await TokenEndpointAsync("matdrive-hand", secret));
        Assert.Equal(["https://hand.test/signin-oidc"], Strings((await ClientAsync("matdrive-hand"))!.Value.GetProperty("redirectUris")));

        // Connected already: the same name again is refused.
        Assert.Contains("is connected already", await PostAsync(browser, new() { ["do"] = "connect", ["name"] = "MatDrive Hand" }));

        Assert.Contains("Connection removed.", await PostAsync(browser, new() { ["do"] = "remove", ["consumer"] = "matdrive-hand" }));
        Assert.Null(await ClientAsync("matdrive-hand"));
    }

    [Fact]
    public async Task The_Connections_area_is_for_administrators_only()
    {
        var anonymous = _site.Browser();
        var page = await anonymous.GetAsync("/Connections");
        Assert.Equal(HttpStatusCode.Redirect, page.StatusCode);
        var form = await anonymous.PostAsync(MatConnectionEndpoints.FormPath, new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["do"] = "connect", ["capability"] = MatCapabilities.IdentityOidc, ["name"] = "Sneaky",
        }));
        Assert.Equal(HttpStatusCode.Forbidden, form.StatusCode);
        Assert.Null(await ClientAsync("sneaky"));
    }

    /// <summary>Posts a form of the Connections area (with the anti-forgery token of the page) and returns the page it goes back to.</summary>
    private static async Task<string> PostAsync(HttpClient browser, Dictionary<string, string> fields)
    {
        var page = await browser.GetStringAsync("/Connections");
        fields["__RequestVerificationToken"] = TokenRegex().Match(page).Groups[1].Value;
        fields["capability"] = MatCapabilities.IdentityOidc;
        fields["returnUrl"] = "/Connections";
        var response = await browser.PostAsync(MatConnectionEndpoints.FormPath, new FormUrlEncodedContent(fields));
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Equal("/Connections", response.Headers.Location!.OriginalString);
        return await browser.GetStringAsync("/Connections");
    }

    /// <summary>A value the Connections area shows once, by its variable.</summary>
    private static string Value(string page, string variable)
    {
        var match = Regex.Match(page, $@"<dt><code>{variable}</code></dt><dd><code id=""[^""]+"">([^<]*)</code>");
        Assert.True(match.Success, $"{variable} is not shown.");
        return WebUtility.HtmlDecode(match.Groups[1].Value);
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

    [GeneratedRegex(@"name=""__RequestVerificationToken"" value=""([^""]+)""")]
    private static partial Regex TokenRegex();
}
