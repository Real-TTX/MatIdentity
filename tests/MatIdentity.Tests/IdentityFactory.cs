using MatIdentity.Web.Infrastructure;
using System.Net;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;

namespace MatIdentity.Tests;

/// <summary>
/// The whole site in memory on its own empty data folder, in Development (so the account <c>admin@example.com</c> / <c>Start12345</c> exists) and with the
/// platform key <see cref="ApiKey"/>. Shared by the tests of one collection; the folder is removed at the end.
/// </summary>
public sealed class IdentityFactory : WebApplicationFactory<Program>
{
    public const string ApiKey = "test-key-0123456789";

    private readonly string _data = Path.Combine(Path.GetTempPath(), "matidentity-tests-" + Guid.NewGuid().ToString("N"));

    public IdentityFactory()
    {
        // Program reads these before the host is built, so they are given as environment variables (one collection at a time, see TestCollection).
        Environment.SetEnvironmentVariable("MatIdentity__DataPath", _data);
        Environment.SetEnvironmentVariable("MAT_API_KEY", ApiKey);
        // All requests of the tests come from one address: the limit of the sign-in (20 a minute) would stop them.
        Environment.SetEnvironmentVariable("MatIdentity__RateLimits__SignIn", "10000");
        // A replayed refresh token is caught at once (the default leeway is for apps that renew twice in parallel).
        Environment.SetEnvironmentVariable("MatIdentity__RefreshTokenReuseLeewaySeconds", "0");
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder) => builder.UseEnvironment("Development");

    /// <summary>A client that keeps cookies and does not follow redirects (the tests look at each step).</summary>
    public HttpClient Browser() => CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, HandleCookies = true });

    public HttpClient Api()
    {
        var client = CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        client.DefaultRequestHeaders.Add("X-Api-Key", ApiKey);
        return client;
    }

    /// <summary>Signs the development account in through the form (with its anti-forgery token) and returns where the form sends the browser.</summary>
    public static async Task<string> SignInAsync(HttpClient browser, string loginUrl, string username = DevAccount.Username, string password = DevAccount.Password)
    {
        var form = await browser.GetStringAsync(loginUrl);
        var token = Regex.Match(form, @"name=""__RequestVerificationToken"" type=""hidden"" value=""([^""]+)""").Groups[1].Value;
        var returnUrl = WebUtility.HtmlDecode(Regex.Match(form, @"id=""ReturnUrl"" name=""ReturnUrl"" value=""([^""]*)""").Groups[1].Value);
        var response = await browser.PostAsync(loginUrl, new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["__RequestVerificationToken"] = token,
            ["ReturnUrl"] = returnUrl,
            ["Input.Username"] = username,
            ["Input.Password"] = password,
            ["Input.RememberMe"] = "true",
        }));
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        return response.Headers.Location!.OriginalString;
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        try
        {
            Directory.Delete(_data, recursive: true);
        }
        catch (IOException)
        {
            // SQLite may still hold the file for a moment; the temp folder is cleaned by the system later.
        }
        catch (UnauthorizedAccessException)
        {
        }
    }
}

/// <summary>The tests against the site run one after another (they share environment variables and a database).</summary>
[CollectionDefinition(Name)]
public sealed class TestCollection : ICollectionFixture<IdentityFactory>
{
    public const string Name = "site";
}
