using System.Net;
using System.Net.Http.Json;
using System.Text.RegularExpressions;

namespace MatIdentity.Tests;

/// <summary>Registration (off by default): the account works only after the address is confirmed; a known address gets the same answer and no mail.</summary>
[Collection(TestCollection.Name)]
public sealed class RegistrationTests
{
    private readonly IdentityFactory _site;

    public RegistrationTests(IdentityFactory site)
    {
        _site = site;
    }

    [Fact]
    public async Task A_person_registers_confirms_the_address_and_signs_in()
    {
        // Off by default: no page.
        Assert.Equal(HttpStatusCode.Redirect, (await _site.Browser().GetAsync("/Account/Register")).StatusCode);

        Assert.Equal(HttpStatusCode.OK, (await _site.Api().PutAsJsonAsync("/api/configure", new { values = new { allowRegistration = true } })).StatusCode);
        try
        {
            var browser = _site.Browser();
            Assert.Contains("Create an account", await browser.GetStringAsync("/Account/Login"));
            var fields = new Dictionary<string, string>
            {
                ["Input.Username"] = "newcomer",
                ["Input.DisplayName"] = "Nora Newcomer",
                ["Input.Email"] = "nora@example.test",
                ["Input.Password"] = "Green-Lamp-Window",
                ["Input.ConfirmPassword"] = "Green-Lamp-Window",
            };
            var registered = await IdentityFactory.PostFormAsync(browser, "/Account/Register", fields);
            Assert.Contains("open the link we sent", await registered.Content.ReadAsStringAsync());

            // Not before the address is confirmed.
            var early = await IdentityFactory.PostFormAsync(_site.Browser(), "/Account/Login", new() { ["Input.Username"] = "newcomer", ["Input.Password"] = "Green-Lamp-Window" });
            Assert.Contains("Confirm your e-mail address first", await early.Content.ReadAsStringAsync());

            var mail = await _site.Mails.WaitForAsync("nora@example.test", "confirm your e-mail address");
            var key = Regex.Match(mail.Text, @"/Account/Verify\?token=([A-Za-z0-9_-]+)").Groups[1].Value;
            Assert.Contains("Address confirmed", await _site.Browser().GetStringAsync("/Account/Verify?token=" + key));
            Assert.Equal("/", await IdentityFactory.SignInAsync(_site.Browser(), "/Account/Login", "newcomer", "Green-Lamp-Window"));

            // The same address again: the same answer, no second account, no mail.
            var count = _site.Mails.CountTo("nora@example.test");
            fields["Input.Username"] = "newcomer2";
            var again = await IdentityFactory.PostFormAsync(_site.Browser(), "/Account/Register", fields);
            Assert.Contains("open the link we sent", await again.Content.ReadAsStringAsync());
            await Task.Delay(200);
            Assert.Equal(count, _site.Mails.CountTo("nora@example.test"));
        }
        finally
        {
            await _site.Api().PutAsJsonAsync("/api/configure", new { values = new { allowRegistration = false } });
        }
    }
}
