using MatIdentity.Web.Infrastructure;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Web;

namespace MatIdentity.Tests;

/// <summary>
/// OpenID Connect end to end against the site in memory: an app registered through the API, a person signing in with the form, the code
/// exchanged with PKCE, the user info, single sign-on without the form, and a machine token that opens the platform API.
/// </summary>
[Collection(TestCollection.Name)]
public sealed class OidcFlowTests
{
    private const string Redirect = "https://split.test/signin-oidc";
    private readonly IdentityFactory _site;

    public OidcFlowTests(IdentityFactory site)
    {
        _site = site;
    }

    [Fact]
    public async Task The_discovery_document_names_the_endpoints()
    {
        using var doc = JsonDocument.Parse(await _site.CreateClient().GetStringAsync("/.well-known/openid-configuration"));
        var root = doc.RootElement;
        Assert.EndsWith("/connect/authorize", root.GetProperty("authorization_endpoint").GetString());
        Assert.EndsWith("/connect/token", root.GetProperty("token_endpoint").GetString());
        Assert.EndsWith("/connect/userinfo", root.GetProperty("userinfo_endpoint").GetString());
        Assert.EndsWith("/connect/logout", root.GetProperty("end_session_endpoint").GetString());
        Assert.Contains("S256", root.GetProperty("code_challenge_methods_supported").EnumerateArray().Select(e => e.GetString()));

        using var keys = JsonDocument.Parse(await _site.CreateClient().GetStringAsync("/.well-known/jwks"));
        Assert.Equal("RSA", keys.RootElement.GetProperty("keys")[0].GetProperty("kty").GetString());
    }

    [Fact]
    public async Task A_person_signs_in_to_an_app_and_the_next_time_without_the_form()
    {
        var secret = await RegisterAsync("matsplit-flow", allowSignIn: true, allowMachine: false);
        var browser = _site.Browser();

        // The app sends the person to MatIdentity; without a session the form comes first.
        var (verifier, challenge) = Pkce();
        var authorize = $"/connect/authorize?client_id=matsplit-flow&response_type=code&scope={Uri.EscapeDataString("openid profile email roles offline_access")}" +
                        $"&redirect_uri={Uri.EscapeDataString(Redirect)}&code_challenge={challenge}&code_challenge_method=S256&state=xyz";
        var first = await browser.GetAsync(authorize);
        Assert.Equal(HttpStatusCode.Redirect, first.StatusCode);
        var login = first.Headers.Location!.OriginalString;
        Assert.StartsWith("/Account/Login?returnUrl=", login);

        // After the sign-in the browser goes back to the request, and from there to the app with a code.
        var back = await IdentityFactory.SignInAsync(browser, login);
        Assert.StartsWith("/connect/authorize", back);
        var code = await CodeAsync(browser, back);

        var tokens = await ExchangeAsync("matsplit-flow", secret, code, verifier);
        Assert.False(string.IsNullOrEmpty(tokens.GetProperty("id_token").GetString()));
        Assert.False(string.IsNullOrEmpty(tokens.GetProperty("refresh_token").GetString()));

        var identity = Claims(tokens.GetProperty("id_token").GetString()!);
        Assert.Equal(DevAccount.Username, identity.GetProperty("preferred_username").GetString());
        Assert.Equal("admin", identity.GetProperty("role").GetString());
        Assert.Equal(DevAccount.Username, identity.GetProperty("email").GetString());

        // The user info answers the access token.
        var api = _site.CreateClient();
        api.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokens.GetProperty("access_token").GetString());
        using var info = JsonDocument.Parse(await api.GetStringAsync("/connect/userinfo"));
        Assert.Equal("Admin", info.RootElement.GetProperty("name").GetString());
        Assert.Equal(identity.GetProperty("sub").GetString(), info.RootElement.GetProperty("sub").GetString());

        // Single sign-on: the second time the code comes without the form.
        var (verifier2, challenge2) = Pkce();
        var again = await browser.GetAsync(authorize.Replace(challenge, challenge2));
        Assert.Equal(HttpStatusCode.Redirect, again.StatusCode);
        Assert.StartsWith(Redirect, again.Headers.Location!.OriginalString);
        var code2 = HttpUtility.ParseQueryString(again.Headers.Location!.Query)["code"]!;
        Assert.True((await ExchangeAsync("matsplit-flow", secret, code2, verifier2)).TryGetProperty("access_token", out _));

        // A refresh token gets a new access token.
        var refreshed = await PostTokenAsync(new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token",
            ["refresh_token"] = tokens.GetProperty("refresh_token").GetString()!,
            ["client_id"] = "matsplit-flow",
            ["client_secret"] = secret,
        });
        Assert.True(refreshed.TryGetProperty("access_token", out _));
    }

    [Fact]
    public async Task A_sign_in_request_without_pkce_or_with_an_unknown_address_is_refused()
    {
        await RegisterAsync("matsplit-strict", allowSignIn: true, allowMachine: false);
        var client = _site.Browser();

        var withoutPkce = await client.GetAsync($"/connect/authorize?client_id=matsplit-strict&response_type=code&scope=openid&redirect_uri={Uri.EscapeDataString(Redirect)}");
        Assert.True(withoutPkce.StatusCode is HttpStatusCode.BadRequest || withoutPkce.Headers.Location?.OriginalString.Contains("error=") == true);

        var (_, challenge) = Pkce();
        var elsewhere = await client.GetAsync($"/connect/authorize?client_id=matsplit-strict&response_type=code&scope=openid&redirect_uri={Uri.EscapeDataString("https://evil.test/cb")}&code_challenge={challenge}&code_challenge_method=S256");
        Assert.Equal(HttpStatusCode.BadRequest, elsewhere.StatusCode);
        Assert.Null(elsewhere.Headers.Location);
    }

    [Fact]
    public async Task A_machine_token_opens_the_platform_api_and_a_token_for_another_app_does_not()
    {
        var secret = await RegisterAsync("mattiverse-test", allowSignIn: false, allowMachine: true);

        var token = await PostTokenAsync(new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = "mattiverse-test",
            ["client_secret"] = secret,
            ["scope"] = "app:matidentity",
        });
        var access = token.GetProperty("access_token").GetString()!;
        Assert.Equal("matidentity", Claims(access).GetProperty("aud").GetString());

        var api = _site.CreateClient();
        api.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", access);
        Assert.Equal(HttpStatusCode.OK, (await api.GetAsync("/api/state")).StatusCode);

        // An app added later is callable too (its scope is granted to every app that calls apps).
        await RegisterAsync("matlater", allowSignIn: true, allowMachine: false);
        var forLater = await PostTokenAsync(new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = "mattiverse-test",
            ["client_secret"] = secret,
            ["scope"] = "app:matlater",
        });
        var laterToken = forLater.GetProperty("access_token").GetString()!;
        Assert.Equal("matlater", Claims(laterToken).GetProperty("aud").GetString());

        // ... but that token is not one for MatIdentity's API.
        var other = _site.CreateClient();
        other.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", laterToken);
        Assert.Equal(HttpStatusCode.Unauthorized, (await other.GetAsync("/api/state")).StatusCode);
    }

    [Fact]
    public async Task A_wrong_secret_gets_no_token()
    {
        await RegisterAsync("matwrong", allowSignIn: false, allowMachine: true);
        var response = await _site.CreateClient().PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = "matwrong",
            ["client_secret"] = "not-the-secret",
            ["scope"] = "app:matidentity",
        }));
        // RFC 6749, 5.2: a client that fails to authenticate gets invalid_client with 401.
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Contains("invalid_client", await response.Content.ReadAsStringAsync());
    }

    /// <summary>Registers an app through the client API (as Mattiverse does) and returns its secret.</summary>
    private async Task<string> RegisterAsync(string id, bool allowSignIn, bool allowMachine)
    {
        var body = new { displayName = id, allowSignIn, allowMachine, callsAllApps = allowMachine, redirectUris = allowSignIn ? new[] { Redirect } : Array.Empty<string>(), managedBy = "tests" };
        var response = await _site.Api().PutAsJsonAsync($"/api/v1/clients/{id}", body);
        var text = await response.Content.ReadAsStringAsync();
        Assert.True(response.IsSuccessStatusCode, text);
        using var doc = JsonDocument.Parse(text);
        return doc.RootElement.GetProperty("clientSecret").GetString()!;
    }

    private async Task<string> CodeAsync(HttpClient browser, string authorize)
    {
        var response = await browser.GetAsync(authorize);
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        var location = response.Headers.Location!;
        Assert.StartsWith(Redirect, location.OriginalString);
        var query = HttpUtility.ParseQueryString(location.Query);
        Assert.Equal("xyz", query["state"]);
        return query["code"]!;
    }

    private Task<JsonElement> ExchangeAsync(string clientId, string secret, string code, string verifier)
        => PostTokenAsync(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = Redirect,
            ["client_id"] = clientId,
            ["client_secret"] = secret,
            ["code_verifier"] = verifier,
        });

    private async Task<JsonElement> PostTokenAsync(Dictionary<string, string> form)
    {
        var response = await _site.CreateClient().PostAsync("/connect/token", new FormUrlEncodedContent(form));
        var text = await response.Content.ReadAsStringAsync();
        Assert.True(response.IsSuccessStatusCode, text);
        return JsonDocument.Parse(text).RootElement.Clone();
    }

    private static (string Verifier, string Challenge) Pkce()
    {
        var verifier = Base64Url(RandomNumberGenerator.GetBytes(32));
        return (verifier, Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(verifier))));
    }

    /// <summary>The payload of a JWT (not checked: the tests only read what is in it).</summary>
    private static JsonElement Claims(string jwt)
    {
        var part = jwt.Split('.')[1].Replace('-', '+').Replace('_', '/');
        part = part.PadRight(part.Length + ((4 - (part.Length % 4)) % 4), '=');
        return JsonDocument.Parse(Convert.FromBase64String(part)).RootElement.Clone();
    }

    private static string Base64Url(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
