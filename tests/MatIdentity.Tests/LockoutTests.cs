using System.Net;
using MatIdentity.Core.Activity;
using MatIdentity.Core.Auth;
using MatIdentity.Core.Entities;
using MatIdentity.Core.Users;
using Microsoft.Extensions.DependencyInjection;

namespace MatIdentity.Tests;

/// <summary>Brute force against one account: ten wrong passwords in a row lock its password sign-in, without telling the one who tries.</summary>
[Collection(TestCollection.Name)]
public sealed class LockoutTests
{
    private readonly IdentityFactory _site;

    public LockoutTests(IdentityFactory site)
    {
        _site = site;
    }

    [Fact]
    public async Task Ten_wrong_passwords_lock_the_account_and_the_right_one_then_gets_the_same_answer()
    {
        long id;
        using (var scope = _site.Services.CreateScope())
        {
            id = (await scope.ServiceProvider.GetRequiredService<UserService>().CreateAsync("guessed", "Guessed", null, "Right-Pass-1", UserRole.User)).Id;
        }

        var browser = _site.Browser();
        for (var i = 0; i < AuthService.MaxFailedAttempts; i++)
        {
            var wrong = await IdentityFactory.PostFormAsync(browser, "/Account/Login", new() { ["Input.Username"] = "guessed", ["Input.Password"] = "wrong-" + i });
            Assert.Equal(HttpStatusCode.OK, wrong.StatusCode);
        }

        var right = await IdentityFactory.PostFormAsync(browser, "/Account/Login", new() { ["Input.Username"] = "guessed", ["Input.Password"] = "Right-Pass-1" });
        Assert.Equal(HttpStatusCode.OK, right.StatusCode);
        Assert.Contains("Incorrect username or password.", await right.Content.ReadAsStringAsync());

        using (var scope = _site.Services.CreateScope())
        {
            var entries = await scope.ServiceProvider.GetRequiredService<ActivityService>().GetRecentAsync(30);
            Assert.Contains(entries, e => e.Kind == ActivityKind.AccountLocked && e.Username == "guessed");
            await scope.ServiceProvider.GetRequiredService<AuthService>().ClearFailuresAsync(id);
        }

        // Unlocked by an administrator: the right password works again.
        Assert.Equal("/", await IdentityFactory.SignInAsync(_site.Browser(), "/Account/Login", "guessed", "Right-Pass-1"));
    }
}
