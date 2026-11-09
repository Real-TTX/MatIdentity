using System.Net;
using MatPlatform;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;

namespace MatIdentity.Tests;

/// <summary>
/// MAT_FRAME_ANCESTORS (MatDesign docs/PLATFORM.md "Shown inside another app"): Mattiverse may show MatIdentity in its window when the variable names it;
/// without it the pages keep the SAMEORIGIN of their forms.
/// </summary>
[Collection(TestCollection.Name)]
public sealed class FrameAncestorsTests(IdentityFactory site)
{
    [Fact]
    public async Task Without_the_variable_the_sign_in_page_cannot_be_framed_by_another_site()
    {
        var response = await site.Browser().GetAsync("/Account/Login");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("SAMEORIGIN", response.Headers.GetValues("X-Frame-Options").Single());
        Assert.False(response.Headers.Contains("Content-Security-Policy"));
    }

    [Fact]
    public async Task With_it_Mattiverse_may_frame_every_answer()
    {
        var data = Path.Combine(Path.GetTempPath(), "matidentity-frames-" + Guid.NewGuid().ToString("N"));
        var before = Environment.GetEnvironmentVariable("MatIdentity__DataPath");
        Environment.SetEnvironmentVariable("MatIdentity__DataPath", data);
        try
        {
            await using var framed = new WebApplicationFactory<Program>().WithWebHostBuilder(b => b
                .UseEnvironment("Development")
                .UseSetting(MatFrameAncestors.Variable, "http://localhost:8030 https://mattiverse.example.com"));
            var browser = framed.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

            foreach (var path in new[] { "/Account/Login", "/.well-known/openid-configuration", "/" })
            {
                var response = await browser.GetAsync(path);
                Assert.False(response.Headers.Contains("X-Frame-Options"), path);
                Assert.Equal("frame-ancestors 'self' http://localhost:8030 https://mattiverse.example.com", response.Headers.GetValues("Content-Security-Policy").Single());
            }
        }
        finally
        {
            Environment.SetEnvironmentVariable("MatIdentity__DataPath", before);
        }
    }
}
