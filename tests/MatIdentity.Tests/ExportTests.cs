using System.Net;
using System.Net.Http.Json;
using System.Text.Json;

namespace MatIdentity.Tests;

/// <summary>The configuration as JSON: apps, groups, people and settings, never a secret.</summary>
[Collection(TestCollection.Name)]
public sealed class ExportTests
{
    private readonly IdentityFactory _site;

    public ExportTests(IdentityFactory site)
    {
        _site = site;
    }

    [Fact]
    public async Task The_configuration_is_exported_without_any_secret()
    {
        var registered = await _site.Api().PutAsJsonAsync("/api/v1/clients/matexport", new { displayName = "MatExport", redirectUris = new[] { "https://export.test/signin-oidc" }, managedBy = "tests" });
        using var created = JsonDocument.Parse(await registered.Content.ReadAsStringAsync());
        var secret = created.RootElement.GetProperty("clientSecret").GetString()!;

        var admin = await _site.AdminAsync();
        var response = await admin.GetAsync("/Settings?handler=Export");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("application/json", response.Content.Headers.ContentType!.MediaType);
        var text = await response.Content.ReadAsStringAsync();

        using var doc = JsonDocument.Parse(text);
        Assert.Equal("matidentity-configuration", doc.RootElement.GetProperty("format").GetString());
        Assert.Contains(doc.RootElement.GetProperty("apps").EnumerateArray(), a => a.GetProperty("clientId").GetString() == "matexport");
        Assert.Contains(doc.RootElement.GetProperty("people").EnumerateArray(), p => p.GetProperty("username").GetString() == "admin@example.com");

        Assert.DoesNotContain(secret, text);
        Assert.DoesNotContain("pbkdf2", text);
        Assert.DoesNotContain("relay-secret", text);
        Assert.DoesNotContain("passwordHash", text, StringComparison.OrdinalIgnoreCase);

        // Only for administrators.
        Assert.NotEqual(HttpStatusCode.OK, (await _site.Browser().GetAsync("/Settings?handler=Export")).StatusCode);
    }
}
