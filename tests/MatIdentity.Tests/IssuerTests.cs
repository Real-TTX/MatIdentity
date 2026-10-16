using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;

namespace MatIdentity.Tests;

/// <summary>
/// With a fixed public address (MatIdentity__Issuer) the discovery document names it for every endpoint, also when it is read at another address
/// (an app inside Docker reads it at the internal one).
/// </summary>
[Collection(TestCollection.Name)]
public sealed class IssuerTests
{
    [Fact]
    public async Task The_discovery_document_names_the_public_address_whoever_asks()
    {
        var data = Path.Combine(Path.GetTempPath(), "matidentity-issuer-" + Guid.NewGuid().ToString("N"));
        var before = (Environment.GetEnvironmentVariable("MatIdentity__DataPath"), Environment.GetEnvironmentVariable("MatIdentity__Issuer"));
        Environment.SetEnvironmentVariable("MatIdentity__DataPath", data);
        Environment.SetEnvironmentVariable("MatIdentity__Issuer", "https://id.example.com");
        try
        {
            await using var site = new WebApplicationFactory<Program>().WithWebHostBuilder(b => b.UseEnvironment("Development"));
            var client = site.CreateClient(new WebApplicationFactoryClientOptions { BaseAddress = new Uri("http://matidentity-internal:2300") });
            using var doc = JsonDocument.Parse(await client.GetStringAsync("/.well-known/openid-configuration"));
            var root = doc.RootElement;
            Assert.Equal("https://id.example.com/", root.GetProperty("issuer").GetString());
            Assert.Equal("https://id.example.com/connect/authorize", root.GetProperty("authorization_endpoint").GetString());
            Assert.Equal("https://id.example.com/connect/token", root.GetProperty("token_endpoint").GetString());
            Assert.Equal("https://id.example.com/connect/logout", root.GetProperty("end_session_endpoint").GetString());
            Assert.Equal("https://id.example.com/.well-known/jwks", root.GetProperty("jwks_uri").GetString());
        }
        finally
        {
            Environment.SetEnvironmentVariable("MatIdentity__DataPath", before.Item1);
            Environment.SetEnvironmentVariable("MatIdentity__Issuer", before.Item2);
        }
    }
}
