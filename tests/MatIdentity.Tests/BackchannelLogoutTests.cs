using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Web;
using MatIdentity.Core.Auth;
using MatIdentity.Core.Users;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace MatIdentity.Tests;

/// <summary>
/// OpenID Connect Back-Channel Logout: the ID token names the session (sid), and when the session ends here the app gets a signed logout token at its
/// back-channel address; a person out everywhere is announced with sub alone.
/// </summary>
[Collection(TestCollection.Name)]
public sealed class BackchannelLogoutTests
{
    private const string Redirect = "https://split.test/signin-oidc";
    private const string SignedOut = "https://split.test/signout-callback-oidc";
    private readonly IdentityFactory _site;

    public BackchannelLogoutTests(IdentityFactory site)
    {
        _site = site;
    }

    [Fact]
    public async Task The_discovery_document_says_back_channel_logout_is_supported()
    {
        using var doc = JsonDocument.Parse(await _site.CreateClient().GetStringAsync("/.well-known/openid-configuration"));
        Assert.True(doc.RootElement.GetProperty("backchannel_logout_supported").GetBoolean());
        Assert.True(doc.RootElement.GetProperty("backchannel_logout_session_supported").GetBoolean());
    }

    [Fact]
    public async Task Signing_out_here_sends_the_app_a_signed_logout_token_for_the_session()
    {
        var secret = await RegisterAsync("matsplit-bcl", "https://split.test/backchannel");
        var browser = _site.Browser();
        var idToken = await SignInToAppAsync(browser, "matsplit-bcl", secret);
        var claims = new JsonWebToken(idToken);
        var sid = claims.GetClaim("sid").Value;
        Assert.False(string.IsNullOrEmpty(sid));

        var logout = await browser.GetAsync("/connect/logout?post_logout_redirect_uri=" + Uri.EscapeDataString(SignedOut) + "&id_token_hint=" + idToken);
        Assert.Equal(HttpStatusCode.Redirect, logout.StatusCode);

        var token = await WaitForLogoutTokenAsync("https://split.test/backchannel", t => t.TryGetClaim("sid", out var s) && s.Value == sid);
        var result = await ValidateAsync(token, "matsplit-bcl");
        Assert.True(result.IsValid, result.Exception?.Message);
        Assert.Equal("logout+jwt", token.Typ);
        Assert.Equal(claims.Subject, token.Subject);
        Assert.Contains("http://schemas.openid.net/event/backchannel-logout", token.GetClaim("events").Value);
        Assert.False(token.TryGetClaim("nonce", out _));
    }

    [Fact]
    public async Task A_person_out_everywhere_is_announced_to_every_app_with_the_subject_alone()
    {
        await RegisterAsync("matpaper-bcl", "https://paper.test/backchannel");
        string subject;
        long id;
        using (var scope = _site.Services.CreateScope())
        {
            var person = await scope.ServiceProvider.GetRequiredService<UserService>().CreateAsync("leaving", "Leaving", null, "Person-Pass-1", Core.Entities.UserRole.User);
            (subject, id) = (person.Subject, person.Id);
        }

        using (var scope = _site.Services.CreateScope())
        {
            // What disabling the account does.
            await scope.ServiceProvider.GetRequiredService<SessionService>().InvalidateAllAsync(id);
        }

        var token = await WaitForLogoutTokenAsync("https://paper.test/backchannel", t => t.Subject == subject);
        Assert.False(token.TryGetClaim("sid", out _));
        Assert.True((await ValidateAsync(token, "matpaper-bcl")).IsValid);
    }

    private async Task<JsonWebToken> WaitForLogoutTokenAsync(string address, Func<JsonWebToken, bool> match)
    {
        for (var i = 0; i < 100; i++)
        {
            var found = _site.Backchannel
                .Where(r => r.Address.AbsoluteUri == address && r.Form.ContainsKey("logout_token"))
                .Select(r => new JsonWebToken(r.Form["logout_token"]))
                .FirstOrDefault(match);
            if (found is not null)
            {
                return found;
            }

            await Task.Delay(50);
        }

        throw new TimeoutException("No logout token at " + address);
    }

    private async Task<TokenValidationResult> ValidateAsync(JsonWebToken token, string audience)
    {
        var keys = new JsonWebKeySet(await _site.CreateClient().GetStringAsync("/.well-known/jwks"));
        return await new JsonWebTokenHandler().ValidateTokenAsync(token.EncodedToken, new TokenValidationParameters
        {
            ValidIssuer = "http://localhost/",
            ValidAudience = audience,
            IssuerSigningKeys = keys.GetSigningKeys(),
            ValidTypes = ["logout+jwt"],
        });
    }

    private async Task<string> RegisterAsync(string id, string backchannel)
    {
        var body = new { displayName = id, allowSignIn = true, openToEveryone = true, redirectUris = new[] { Redirect }, postLogoutRedirectUris = new[] { SignedOut }, backchannelLogoutUri = backchannel, managedBy = "tests" };
        var response = await _site.Api().PutAsJsonAsync($"/api/v1/clients/{id}", body);
        var text = await response.Content.ReadAsStringAsync();
        Assert.True(response.IsSuccessStatusCode, text);
        using var doc = JsonDocument.Parse(text);
        Assert.Equal(backchannel, doc.RootElement.GetProperty("client").GetProperty("backchannelLogoutUri").GetString());
        return doc.RootElement.GetProperty("clientSecret").GetString()!;
    }

    /// <summary>The development account signs in to the app; its ID token.</summary>
    private async Task<string> SignInToAppAsync(HttpClient browser, string clientId, string secret)
    {
        var verifier = Base64Url(RandomNumberGenerator.GetBytes(32));
        var challenge = Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));
        var authorize = $"/connect/authorize?client_id={clientId}&response_type=code&scope=openid%20profile&redirect_uri={Uri.EscapeDataString(Redirect)}" +
                        $"&code_challenge={challenge}&code_challenge_method=S256&state=s";
        var login = (await browser.GetAsync(authorize)).Headers.Location!.OriginalString;
        var back = await IdentityFactory.SignInAsync(browser, login);
        var code = HttpUtility.ParseQueryString((await browser.GetAsync(back)).Headers.Location!.Query)["code"]!;
        var response = await _site.CreateClient().PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = Redirect,
            ["client_id"] = clientId,
            ["client_secret"] = secret,
            ["code_verifier"] = verifier,
        }));
        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return doc.RootElement.GetProperty("id_token").GetString()!;
    }

    private static string Base64Url(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
