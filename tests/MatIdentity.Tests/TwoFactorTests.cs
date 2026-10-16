using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using MatIdentity.Core.Auth;
using MatIdentity.Core.Entities;
using MatIdentity.Core.Security;
using MatIdentity.Core.Users;
using Microsoft.Extensions.DependencyInjection;

namespace MatIdentity.Tests;

/// <summary>The authenticator app: the algorithm against RFC 6238, and the second step of a sign-in against the site in memory.</summary>
[Collection(TestCollection.Name)]
public sealed partial class TwoFactorTests
{
    // The secret of the test vectors of RFC 6238 (SHA-1): the ASCII of "12345678901234567890".
    private static readonly string RfcSecret = Totp.ToBase32(Encoding.ASCII.GetBytes("12345678901234567890"));

    private readonly IdentityFactory _site;

    public TwoFactorTests(IdentityFactory site)
    {
        _site = site;
    }

    [Theory]
    [InlineData(59L, "287082")]
    [InlineData(1111111109L, "081804")]
    [InlineData(1111111111L, "050471")]
    [InlineData(1234567890L, "005924")]
    [InlineData(2000000000L, "279037")]
    [InlineData(20000000000L, "353130")]
    public void The_codes_are_those_of_rfc_6238(long unixSeconds, string expected)
        => Assert.Equal(expected, Totp.Code(RfcSecret, Totp.StepOf(DateTimeOffset.FromUnixTimeSeconds(unixSeconds))));

    [Fact]
    public void A_code_is_valid_for_its_step_and_the_neighbours_and_never_twice()
    {
        var now = DateTimeOffset.FromUnixTimeSeconds(1_700_000_000);
        var step = Totp.StepOf(now);
        Assert.Equal(step, Totp.Verify(RfcSecret, Totp.Code(RfcSecret, step), now, 0));
        Assert.Equal(step - 1, Totp.Verify(RfcSecret, Totp.Code(RfcSecret, step - 1), now, 0));
        Assert.Equal(step + 1, Totp.Verify(RfcSecret, Totp.Code(RfcSecret, step + 1), now, 0));
        Assert.Null(Totp.Verify(RfcSecret, Totp.Code(RfcSecret, step - 2), now, 0));
        Assert.Null(Totp.Verify(RfcSecret, Totp.Code(RfcSecret, step), now, lastUsedStep: step));
        Assert.Equal(step, Totp.Verify(RfcSecret, Totp.Code(RfcSecret, step)[..3] + " " + Totp.Code(RfcSecret, step)[3..], now, 0));
        Assert.Null(Totp.Verify(RfcSecret, "12345", now, 0));
        Assert.Null(Totp.Verify(RfcSecret, "abcdef", now, 0));
    }

    [Fact]
    public void Base32_goes_there_and_back()
    {
        var bytes = Enumerable.Range(0, 37).Select(i => (byte)(i * 7)).ToArray();
        Assert.Equal(bytes, Totp.FromBase32(Totp.ToBase32(bytes)));
        Assert.Equal(32, Totp.NewSecret().Length);
        Assert.StartsWith("otpauth://totp/Home%20ID:anna?secret=", Totp.KeyUri("Home ID", "anna", "ABC"));
    }

    [Fact]
    public async Task With_an_authenticator_app_the_password_alone_is_not_enough()
    {
        var (user, secret, recovery) = await PersonWithAuthenticatorAsync("totp-tina");
        var browser = _site.Browser();

        // The password is right: the second step comes, not a session.
        var next = await IdentityFactory.SignInAsync(browser, "/Account/Login?returnUrl=%2FAccount%2FProfile", "totp-tina", "Person-Pass-1");
        Assert.StartsWith("/Account/TwoFactor", next);
        Assert.Equal(HttpStatusCode.Redirect, (await browser.GetAsync("/Account/Profile")).StatusCode);

        // A wrong code is refused, the right one signs in and goes where the person wanted.
        var (wrongStatus, wrongBody) = await PostCodeAsync(browser, next, "000000");
        Assert.Equal(HttpStatusCode.OK, wrongStatus);
        Assert.Contains("is not right", wrongBody);
        var code = Totp.Code(secret, Totp.StepOf(DateTimeOffset.UtcNow));
        var (okStatus, _, location) = await PostCodeFullAsync(browser, next, code);
        Assert.Equal(HttpStatusCode.Redirect, okStatus);
        Assert.Equal("/Account/Profile", location);
        Assert.Equal(HttpStatusCode.OK, (await browser.GetAsync("/Account/Profile")).StatusCode);

        // A recovery code works once.
        var other = _site.Browser();
        var again = await IdentityFactory.SignInAsync(other, "/Account/Login", "totp-tina", "Person-Pass-1");
        Assert.Equal(HttpStatusCode.Redirect, (await PostCodeFullAsync(other, again, recovery[0].ToUpperInvariant())).Status);
        var third = _site.Browser();
        var once = await IdentityFactory.SignInAsync(third, "/Account/Login", "totp-tina", "Person-Pass-1");
        Assert.Equal(HttpStatusCode.OK, (await PostCodeFullAsync(third, once, recovery[0])).Status);

        using var scope = _site.Services.CreateScope();
        Assert.Equal(TwoFactorService.RecoveryCodeCount - 1, TwoFactorService.RecoveryCodesLeft((await scope.ServiceProvider.GetRequiredService<UserService>().GetAsync(user.Id))!));
    }

    [Fact]
    public async Task Five_wrong_codes_send_the_person_back_to_the_password()
    {
        await PersonWithAuthenticatorAsync("totp-tom");
        var browser = _site.Browser();
        var next = await IdentityFactory.SignInAsync(browser, "/Account/Login", "totp-tom", "Person-Pass-1");
        for (var i = 1; i < 5; i++)
        {
            Assert.Equal(HttpStatusCode.OK, (await PostCodeFullAsync(browser, next, "111111")).Status);
        }

        var (status, _, location) = await PostCodeFullAsync(browser, next, "111111");
        Assert.Equal(HttpStatusCode.Redirect, status);
        Assert.StartsWith("/Account/Login", location);
        Assert.Equal(HttpStatusCode.Redirect, (await browser.GetAsync(next)).StatusCode);
    }

    private async Task<(User User, string Secret, IReadOnlyList<string> Recovery)> PersonWithAuthenticatorAsync(string username)
    {
        using var scope = _site.Services.CreateScope();
        var user = await scope.ServiceProvider.GetRequiredService<UserService>().CreateAsync(username, username, null, "Person-Pass-1", UserRole.User);
        var twoFactor = scope.ServiceProvider.GetRequiredService<TwoFactorService>();
        var secret = await twoFactor.BeginSetupAsync(user.Id);
        // The step before now: the code of the setup must not block the code of the sign-in that follows.
        var recovery = await twoFactor.ConfirmSetupAsync(user.Id, Totp.Code(secret, Totp.StepOf(DateTimeOffset.UtcNow) - 1));
        Assert.NotNull(recovery);
        return (user, secret, recovery!);
    }

    private static async Task<(HttpStatusCode Status, string Body)> PostCodeAsync(HttpClient browser, string page, string code)
    {
        var (status, body, _) = await PostCodeFullAsync(browser, page, code);
        return (status, body);
    }

    private static async Task<(HttpStatusCode Status, string Body, string? Location)> PostCodeFullAsync(HttpClient browser, string page, string code)
    {
        var form = await browser.GetStringAsync(page);
        var token = TokenRegex().Match(form).Groups[1].Value;
        var response = await browser.PostAsync(page, new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["__RequestVerificationToken"] = token,
            ["Code"] = code,
        }));
        return (response.StatusCode, await response.Content.ReadAsStringAsync(), response.Headers.Location?.OriginalString);
    }

    [GeneratedRegex(@"name=""__RequestVerificationToken"" type=""hidden"" value=""([^""]+)""")]
    private static partial Regex TokenRegex();
}
