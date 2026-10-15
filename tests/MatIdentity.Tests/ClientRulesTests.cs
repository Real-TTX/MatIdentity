using MatIdentity.Core.Clients;
using MatIdentity.Core.Configuration;

namespace MatIdentity.Tests;

/// <summary>The rules of an app (client) and of the settings, without the site.</summary>
public sealed class ClientRulesTests
{
    private static ClientInfo Valid() => new()
    {
        ClientId = "matsplit",
        DisplayName = "MatSplit",
        RedirectUris = ["https://split.example.com/signin-oidc"],
    };

    [Theory]
    [InlineData("matsplit", true)]
    [InlineData("mat-split_2", true)]
    [InlineData("m", false)]
    [InlineData("MatSplit", false)]
    [InlineData("-matsplit", false)]
    [InlineData("mat split", false)]
    public void A_client_id_is_small_letters_digits_dash_and_underscore(string id, bool valid)
        => Assert.Equal(valid, ClientRules.IsValidClientId(id));

    [Fact]
    public void A_valid_app_has_no_errors() => Assert.Empty(ClientRules.Validate(Valid()));

    [Fact]
    public void MatIdentity_itself_is_not_an_app_to_add()
        => Assert.Contains("clientId", ClientRules.Validate(Valid() with { ClientId = "matidentity" }).Keys);

    [Fact]
    public void An_app_that_signs_people_in_needs_a_sign_in_address()
        => Assert.Contains("redirectUris", ClientRules.Validate(Valid() with { RedirectUris = [] }).Keys);

    [Theory]
    [InlineData("https://split.example.com/signin-oidc#x")]
    [InlineData("split.example.com/signin-oidc")]
    [InlineData("javascript:alert(1)")]
    [InlineData("ftp://split.example.com/")]
    public void A_redirect_address_is_absolute_http_without_fragment(string uri)
        => Assert.Contains("redirectUris", ClientRules.Validate(Valid() with { RedirectUris = [uri] }).Keys);

    [Fact]
    public void A_public_app_cannot_call_other_apps()
        => Assert.Contains("allowMachine", ClientRules.Validate(Valid() with { IsPublic = true, AllowMachine = true }).Keys);

    [Fact]
    public void An_app_does_something()
        => Assert.Contains("allowSignIn", ClientRules.Validate(Valid() with { AllowSignIn = false, AllowMachine = false }).Keys);

    [Fact]
    public void Addresses_are_split_by_lines_spaces_and_commas_without_duplicates()
        => Assert.Equal(["https://a.test/cb", "https://b.test/cb"], ClientRules.SplitUris("https://a.test/cb\r\nhttps://b.test/cb, https://a.test/cb"));

    [Fact]
    public void A_new_secret_is_long_and_url_safe()
    {
        var secret = ClientService.NewSecret();
        Assert.Equal(43, secret.Length);
        Assert.Matches("^[A-Za-z0-9_-]+$", secret);
        Assert.NotEqual(secret, ClientService.NewSecret());
    }

    [Theory]
    [InlineData("https://id.example.com", true)]
    [InlineData("http://localhost:2300", true)]
    [InlineData("https://id.example.com/?x=1", false)]
    [InlineData("id.example.com", false)]
    public void An_issuer_is_an_absolute_address_without_query(string value, bool valid)
        => Assert.Equal(valid, SystemConfigService.IsValidIssuer(value));

    [Fact]
    public void Settings_out_of_range_are_errors()
    {
        var errors = SystemConfigService.Validate(new SystemConfig { InstanceName = "", SessionLifetimeDays = 0, AccessTokenMinutes = 2 });
        Assert.Equal(["accessTokenMinutes", "instanceName", "sessionLifetimeDays"], errors.Keys.Order());
    }
}
