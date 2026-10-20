using System.Net;
using System.Text.RegularExpressions;
using MatIdentity.Core.Data;
using MatIdentity.Core.Entities;
using MatIdentity.Core.Users;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace MatIdentity.Tests;

/// <summary>
/// The links in mails: "Forgot your password?" (the same answer for every name, a link that works once and is stored as a hash only), the invitation of a new
/// person, and confirming an e-mail address (then <c>email_verified</c> is true).
/// </summary>
[Collection(TestCollection.Name)]
public sealed partial class AccountMailTests
{
    private readonly IdentityFactory _site;

    public AccountMailTests(IdentityFactory site)
    {
        _site = site;
    }

    [Fact]
    public async Task A_forgotten_password_is_set_again_with_a_link_that_works_once()
    {
        var person = await CreatePersonAsync("forgetful", "forgetful@example.test");
        var browser = _site.Browser();
        Assert.Contains("Forgot your password?", await browser.GetStringAsync("/Account/Login"));

        var asked = await IdentityFactory.PostFormAsync(browser, "/Account/Forgot", new() { ["Login"] = "forgetful@example.test" });
        Assert.Contains("the link is on its way", await asked.Content.ReadAsStringAsync());
        var mail = await _site.Mails.WaitForAsync("forgetful@example.test", "set a new password");
        var key = KeyOf(mail.Text, "Reset");

        // Only the hash of the key is stored.
        using (var scope = _site.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<MatIdentityDbContext>();
            var stored = await db.AccountTokens.Where(t => t.UserId == person.Id).Select(t => t.TokenHash).ToListAsync();
            Assert.Contains(AccountTokenService.Hash(key), stored);
            Assert.DoesNotContain(key, stored);
        }

        var page = "/Account/Reset?token=" + key;
        Assert.Contains("Set a new password", await browser.GetStringAsync(page));
        var set = await IdentityFactory.PostFormAsync(browser, page, new() { ["Token"] = key, ["Input.Password"] = "New-Pass-2024", ["Input.ConfirmPassword"] = "New-Pass-2024" });
        Assert.Equal(HttpStatusCode.Redirect, set.StatusCode);
        Assert.Equal("/Account/Login?passwordSet=true", set.Headers.Location!.OriginalString, ignoreCase: true);

        Assert.Equal("/", await IdentityFactory.SignInAsync(_site.Browser(), "/Account/Login", "forgetful", "New-Pass-2024"));
        Assert.Contains("This link does not work", await _site.Browser().GetStringAsync(page));

        // The link went to the address: it is confirmed now.
        Assert.True((await ReadPersonAsync(person.Id)).EmailVerified);
    }

    [Fact]
    public async Task An_unknown_name_gets_the_same_answer_and_no_mail()
    {
        var before = _site.Mails.Sent.Count;
        var asked = await IdentityFactory.PostFormAsync(_site.Browser(), "/Account/Forgot", new() { ["Login"] = "nobody-here" });
        Assert.Contains("the link is on its way", await asked.Content.ReadAsStringAsync());
        await Task.Delay(200);
        Assert.Equal(before, _site.Mails.Sent.Count);
    }

    [Fact]
    public async Task An_invited_person_chooses_the_password_and_the_address_counts_as_confirmed()
    {
        var admin = await _site.AdminAsync();
        var created = await IdentityFactory.PostFormAsync(admin, "/Users/Edit", new()
        {
            ["Input.Username"] = "invited",
            ["Input.DisplayName"] = "Ida Invited",
            ["Input.Email"] = "ida@example.test",
            ["Input.Role"] = "User",
            ["Input.IsActive"] = "true",
            ["Input.Invite"] = "true",
        });
        Assert.Equal(HttpStatusCode.Redirect, created.StatusCode);
        Assert.Equal("/Users", created.Headers.Location!.OriginalString);

        var mail = await _site.Mails.WaitForAsync("ida@example.test", "your account");
        Assert.Contains("Ida Invited", mail.Text);
        Assert.Contains("Invited", await admin.GetStringAsync("/Users"));

        var key = KeyOf(mail.Text, "Reset");
        var browser = _site.Browser();
        Assert.Contains("Welcome, Ida Invited", await browser.GetStringAsync("/Account/Reset?token=" + key));
        var set = await IdentityFactory.PostFormAsync(browser, "/Account/Reset?token=" + key, new() { ["Token"] = key, ["Input.Password"] = "Ida-Pass-2024", ["Input.ConfirmPassword"] = "Ida-Pass-2024" });
        Assert.Equal(HttpStatusCode.Redirect, set.StatusCode);
        Assert.Equal("/", await IdentityFactory.SignInAsync(_site.Browser(), "/Account/Login", "invited", "Ida-Pass-2024"));
    }

    [Fact]
    public async Task A_person_confirms_the_address_and_a_new_address_is_unconfirmed_again()
    {
        var person = await CreatePersonAsync("confirming", "confirming@example.test");
        var browser = _site.Browser();
        await IdentityFactory.SignInAsync(browser, "/Account/Login", "confirming", "Person-Pass-1");
        Assert.Contains("Not confirmed", await browser.GetStringAsync("/Account/Profile"));

        var sent = await IdentityFactory.PostFormAsync(browser, "/Account/Profile", [], "/Account/Profile?handler=SendVerification");
        Assert.Equal(HttpStatusCode.Redirect, sent.StatusCode);
        var mail = await _site.Mails.WaitForAsync("confirming@example.test", "confirm your e-mail address");
        Assert.Contains("Address confirmed", await _site.Browser().GetStringAsync("/Account/Verify?token=" + KeyOf(mail.Text, "Verify")));
        Assert.True((await ReadPersonAsync(person.Id)).EmailVerified);

        using (var scope = _site.Services.CreateScope())
        {
            var users = scope.ServiceProvider.GetRequiredService<UserService>();
            await users.UpdateAsync(person.Id, person.DisplayName, "other@example.test", person.Role, true, null);
        }

        Assert.False((await ReadPersonAsync(person.Id)).EmailVerified);
    }

    private async Task<User> CreatePersonAsync(string username, string email)
    {
        using var scope = _site.Services.CreateScope();
        return await scope.ServiceProvider.GetRequiredService<UserService>().CreateAsync(username, username, email, "Person-Pass-1", UserRole.User);
    }

    private async Task<User> ReadPersonAsync(long id)
    {
        using var scope = _site.Services.CreateScope();
        return (await scope.ServiceProvider.GetRequiredService<UserService>().GetAsync(id))!;
    }

    /// <summary>The key of the link to <c>/Account/{page}</c> in a mail.</summary>
    private static string KeyOf(string text, string page)
    {
        var match = Regex.Match(text, $@"/Account/{page}\?token=([A-Za-z0-9_-]+)");
        Assert.True(match.Success, text);
        return match.Groups[1].Value;
    }
}
