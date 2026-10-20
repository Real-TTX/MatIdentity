using System.Net;
using System.Net.Http.Json;
using MatIdentity.Core.Activity;
using MatIdentity.Core.Entities;
using Microsoft.Extensions.DependencyInjection;

namespace MatIdentity.Tests;

/// <summary>What administrators change is in the activity list: people, groups, settings (by the page and by the API), never a value of a secret.</summary>
[Collection(TestCollection.Name)]
public sealed class AuditTests
{
    private readonly IdentityFactory _site;

    public AuditTests(IdentityFactory site)
    {
        _site = site;
    }

    [Fact]
    public async Task Changes_of_administrators_are_in_the_activity_list()
    {
        var admin = await _site.AdminAsync();
        var person = await IdentityFactory.PostFormAsync(admin, "/Users/Edit", new()
        {
            ["Input.Username"] = "audited",
            ["Input.DisplayName"] = "Audited",
            ["Input.Role"] = "User",
            ["Input.IsActive"] = "true",
            ["Input.Invite"] = "false",
            ["Input.Password"] = "Audit-Pass-1",
            ["Input.ConfirmPassword"] = "Audit-Pass-1",
        });
        Assert.Equal(HttpStatusCode.Redirect, person.StatusCode);

        var group = await IdentityFactory.PostFormAsync(admin, "/Groups/Edit", new() { ["Input.Name"] = "Audit group" });
        Assert.Equal(HttpStatusCode.Redirect, group.StatusCode);

        var api = await _site.Api().PutAsJsonAsync("/api/configure", new { values = new { sessionLifetimeDays = 21 } });
        Assert.Equal(HttpStatusCode.OK, api.StatusCode);

        using var scope = _site.Services.CreateScope();
        var entries = await scope.ServiceProvider.GetRequiredService<ActivityService>().GetRecentAsync(50);
        Assert.Contains(entries, e => e.Kind == ActivityKind.PersonCreated && e.Detail == "audited" && e.Username == "admin@example.com");
        Assert.Contains(entries, e => e.Kind == ActivityKind.GroupSaved && e.Detail!.StartsWith("Audit group", StringComparison.Ordinal));
        Assert.Contains(entries, e => e.Kind == ActivityKind.SettingsChanged && e.Detail == "Through the API: sessionLifetimeDays");
        Assert.DoesNotContain(entries, e => e.Detail?.Contains("Audit-Pass-1", StringComparison.Ordinal) == true);
    }

    [Fact]
    public async Task An_administrator_sees_where_a_person_is_signed_in_and_signs_them_out_everywhere()
    {
        long id;
        using (var scope = _site.Services.CreateScope())
        {
            id = (await scope.ServiceProvider.GetRequiredService<MatIdentity.Core.Users.UserService>().CreateAsync("roaming", "Roaming", null, "Roam-Pass-1", UserRole.User)).Id;
        }

        var person = _site.Browser();
        await IdentityFactory.SignInAsync(person, "/Account/Login", "roaming", "Roam-Pass-1");
        Assert.Equal(HttpStatusCode.OK, (await person.GetAsync("/Account/Profile")).StatusCode);

        var admin = await _site.AdminAsync();
        Assert.DoesNotContain("Not signed in anywhere", await admin.GetStringAsync($"/Users/Edit?id={id}"));
        var signedOut = await IdentityFactory.PostFormAsync(admin, $"/Users/Edit?id={id}", new() { ["id"] = id.ToString() }, $"/Users/Edit?id={id}&handler=SignOut");
        Assert.Equal(HttpStatusCode.Redirect, signedOut.StatusCode);

        Assert.Equal(HttpStatusCode.Redirect, (await person.GetAsync("/Account/Profile")).StatusCode);
        Assert.Contains("Not signed in anywhere", await admin.GetStringAsync($"/Users/Edit?id={id}"));
    }
}
