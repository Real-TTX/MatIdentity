using MatIdentity.Web.Infrastructure;

namespace MatIdentity.Tests;

/// <summary>Where a passkey sign-in may send the browser: only to MatIdentity itself.</summary>
public sealed class LocalUrlTests
{
    [Theory]
    [InlineData("/", true)]
    [InlineData("/connect/authorize?client_id=x", true)]
    [InlineData("//evil.example", false)]
    [InlineData("/\evil.example", false)]
    [InlineData("https://evil.example", false)]
    [InlineData("evil", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void Only_addresses_of_MatIdentity_are_local(string? url, bool local)
    {
        Assert.Equal(local, LocalUrl.IsLocal(url));
        Assert.Equal(local ? url : "/", LocalUrl.OrHome(url));
    }
}
