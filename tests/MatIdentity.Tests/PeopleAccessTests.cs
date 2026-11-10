using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Web;
using MatIdentity.Core.Access;
using MatIdentity.Core.Entities;
using MatIdentity.Core.Users;
using MatIdentity.Web.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace MatIdentity.Tests;

/// <summary>
/// The people of the apps (MatDesign docs/PLATFORM.md "People, permissions and quotas"): permissions and quotas of an app, given by grants, in the tokens; a change
/// tells the app at once; SCIM with the key (everything) and with the key of people.scim (the people of one app, read only); the actions on a person.
/// </summary>
[Collection(TestCollection.Name)]
public sealed class PeopleAccessTests
{
    private const string Password = "Person-Pass-1";

    private readonly IdentityFactory _site;

    public PeopleAccessTests(IdentityFactory site)
    {
        _site = site;
    }

    // ---- grants and claims -----------------------------------------------------------------------------------------------------------

    [Fact]
    public async Task Permissions_add_up_and_quotas_take_the_own_value_else_the_largest_of_the_groups()
    {
        var (clientId, secret, redirect) = await RegisterAppAsync("matpeople-a");
        var person = await CreatePersonAsync("people-anna");
        using (var scope = _site.Services.CreateScope())
        {
            var groups = scope.ServiceProvider.GetRequiredService<GroupService>();
            var permissions = scope.ServiceProvider.GetRequiredService<PermissionService>();
            var small = await groups.SaveAsync(null, "Small " + clientId, null, [person.Id]);
            var big = await groups.SaveAsync(null, "Big " + clientId, null, [person.Id]);
            await permissions.SaveGrantAsync(clientId, null, small.Id, "member", Values(["export"], new() { ["storage"] = 10, ["ai-tokens"] = 100 }));
            await permissions.SaveGrantAsync(clientId, null, big.Id, "member", Values([], new() { ["storage"] = 50, ["ai-tokens"] = null }));
        }

        var browser = _site.Browser();
        await IdentityFactory.SignInAsync(browser, "/Account/Login", "people-anna", Password);
        var tokens = await CodeFlowAsync(browser, clientId, secret, redirect);
        var id = Jwt(tokens.GetProperty("id_token").GetString()!);
        Assert.Equal("member", id.GetProperty("role").GetString());
        // "share-public" comes with the role admin only; "export" from the small group.
        Assert.Equal("export", Single(id.GetProperty("entitlements")));
        Assert.Equal(50, id.GetProperty("mat_quotas").GetProperty("storage").GetInt64());
        Assert.Equal(JsonValueKind.Null, id.GetProperty("mat_quotas").GetProperty("ai-tokens").ValueKind);
        Assert.False(id.GetProperty("mat_quotas").TryGetProperty("files", out _));

        var access = Jwt(tokens.GetProperty("access_token").GetString()!);
        Assert.Equal("export", Single(access.GetProperty("entitlements")));
        Assert.Equal(50, access.GetProperty("mat_quotas").GetProperty("storage").GetInt64());

        // The person's own grant wins for the quota, and its permissions add to the groups'; the admin role brings share-public.
        using (var scope = _site.Services.CreateScope())
        {
            await scope.ServiceProvider.GetRequiredService<PermissionService>().SaveGrantAsync(clientId, person.Id, null, "admin", Values(["drives-create"], new() { ["storage"] = 5 }));
        }

        var again = Jwt((await CodeFlowAsync(browser, clientId, secret, redirect)).GetProperty("id_token").GetString()!);
        Assert.Equal("admin", again.GetProperty("role").GetString());
        Assert.Equal(["share-public", "export", "drives-create"], again.GetProperty("entitlements").EnumerateArray().Select(e => e.GetString()));
        Assert.Equal(5, again.GetProperty("mat_quotas").GetProperty("storage").GetInt64());

        // The user info says the same.
        var userInfo = new HttpRequestMessage(HttpMethod.Get, "/connect/userinfo");
        userInfo.Headers.Authorization = new AuthenticationHeaderValue("Bearer", tokens.GetProperty("access_token").GetString());
        var info = JsonDocument.Parse(await (await _site.CreateClient().SendAsync(userInfo)).Content.ReadAsStringAsync()).RootElement;
        Assert.Equal(50, info.GetProperty("mat_quotas").GetProperty("storage").GetInt64());
    }

    [Fact]
    public async Task An_app_that_decides_its_roles_gets_no_permissions_and_no_quotas()
    {
        var (clientId, secret, redirect) = await RegisterAppAsync("matpeople-b", roleMode: "app");
        var person = await CreatePersonAsync("people-ben");
        using (var scope = _site.Services.CreateScope())
        {
            await scope.ServiceProvider.GetRequiredService<PermissionService>().SaveGrantAsync(clientId, person.Id, null, null, Values(["export"], new() { ["storage"] = 1 }));
        }

        var browser = _site.Browser();
        await IdentityFactory.SignInAsync(browser, "/Account/Login", "people-ben", Password);
        var id = Jwt((await CodeFlowAsync(browser, clientId, secret, redirect)).GetProperty("id_token").GetString()!);
        Assert.False(id.TryGetProperty("role", out _));
        Assert.False(id.TryGetProperty("entitlements", out _));
        Assert.False(id.TryGetProperty("mat_quotas", out _));
    }

    [Fact]
    public async Task The_client_api_keeps_the_permissions_and_quotas_and_refuses_bad_ones()
    {
        await RegisterAppAsync("matpeople-c");
        var client = JsonDocument.Parse(await _site.Api().GetStringAsync("/api/v1/clients/matpeople-c")).RootElement;
        Assert.Equal("matidentity", client.GetProperty("roleMode").GetString());
        Assert.Equal("share-public", client.GetProperty("permissions")[0].GetProperty("key").GetString());
        Assert.Equal("admin", client.GetProperty("permissions")[0].GetProperty("roles")[0].GetString());
        Assert.Equal("month", client.GetProperty("quotas")[1].GetProperty("period").GetString());

        var bad = await _site.Api().PutAsJsonAsync("/api/v1/clients/matpeople-c", new { quotas = new[] { new { key = "storage", label = "Storage", unit = "gigabytes" } } });
        Assert.Equal(HttpStatusCode.BadRequest, bad.StatusCode);
        Assert.Contains("gigabytes", await bad.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task A_binding_reads_the_permissions_and_quotas_of_the_apps_api()
    {
        _site.AppDefinitions["http://mattiverse-matbox-web:4900/api"] = """
            { "contract": 2, "app": { "id": "matbox", "name": "MatBox" },
              "roles": [ { "key": "admin", "label": "Administrator" }, { "key": "user", "label": "User" } ],
              "permissions": [ { "key": "share-public", "label": "Share publicly", "roles": ["admin", "nobody"] } ],
              "quotas": [ { "key": "storage", "label": "Storage", "unit": "bytes", "min": 0 } ] }
            """;
        var response = await _site.Api().PutAsJsonAsync("/api/bindings/identity.oidc/matbox", new
        {
            version = 1,
            managedBy = "mattiverse",
            consumer = new { name = "MatBox", url = "https://box.example.test", internalUrl = "http://mattiverse-matbox-web:4900" },
            provider = new { url = "https://id.example.test" },
            @params = new Dictionary<string, string>(),
            renew = false,
        });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        using var scope = _site.Services.CreateScope();
        var permissions = scope.ServiceProvider.GetRequiredService<PermissionService>();
        var permission = Assert.Single(await permissions.PermissionsAsync("matbox"));
        // A role the app does not have is left out.
        Assert.Equal(["admin"], permission.Roles);
        Assert.Equal("bytes", Assert.Single(await permissions.QuotasAsync("matbox")).Unit);
        await _site.Api().DeleteAsync("/api/bindings/identity.oidc/matbox?managedBy=mattiverse");
    }

    // ---- a change tells the app --------------------------------------------------------------------------------------------------------

    [Fact]
    public async Task A_change_of_a_grant_signs_the_person_out_of_that_app_and_ends_their_renewal()
    {
        var (clientId, secret, redirect) = await RegisterAppAsync("matpeople-d", backchannel: "http://matpeople-d.internal/signout-backchannel");
        var (otherId, _, _) = await RegisterAppAsync("matpeople-d2", backchannel: "http://matpeople-d2.internal/signout-backchannel");
        var person = await CreatePersonAsync("people-dora");
        using (var scope = _site.Services.CreateScope())
        {
            await scope.ServiceProvider.GetRequiredService<PermissionService>().SaveGrantAsync(clientId, person.Id, null, "member", Values([], new() { ["storage"] = 10 }));
        }

        var browser = _site.Browser();
        await IdentityFactory.SignInAsync(browser, "/Account/Login", "people-dora", Password);
        var tokens = await CodeFlowAsync(browser, clientId, secret, redirect);
        _site.Backchannel.Clear();

        // The same values again: nothing changes, nobody is told.
        using (var scope = _site.Services.CreateScope())
        {
            await scope.ServiceProvider.GetRequiredService<PermissionService>().SaveGrantAsync(clientId, person.Id, null, "member", Values([], new() { ["storage"] = 10 }));
        }

        await Task.Delay(300);
        Assert.Empty(_site.Backchannel);

        // Another quota: the app hears it (the subject alone), the other app does not, and the refresh token is gone.
        using (var scope = _site.Services.CreateScope())
        {
            await scope.ServiceProvider.GetRequiredService<PermissionService>().SaveGrantAsync(clientId, person.Id, null, "member", Values([], new() { ["storage"] = 20 }));
        }

        var notice = await NextBackchannelAsync();
        Assert.Equal("http://matpeople-d.internal/signout-backchannel", notice.Address.ToString());
        var logout = Jwt(notice.Form["logout_token"]);
        Assert.Equal(person.Subject, logout.GetProperty("sub").GetString());
        Assert.False(logout.TryGetProperty("sid", out _));
        Assert.DoesNotContain(_site.Backchannel, b => b.Address.Host == "matpeople-d2.internal");
        Assert.NotEqual(otherId, clientId);

        var refreshed = await RefreshAsync(clientId, secret, tokens.GetProperty("refresh_token").GetString()!);
        Assert.Equal(HttpStatusCode.BadRequest, refreshed.StatusCode);

        // A new sign-in carries the new value.
        var id = Jwt((await CodeFlowAsync(browser, clientId, secret, redirect)).GetProperty("id_token").GetString()!);
        Assert.Equal(20, id.GetProperty("mat_quotas").GetProperty("storage").GetInt64());
    }

    [Fact]
    public async Task Joining_a_group_tells_the_apps_of_the_group_and_taking_an_app_away_too()
    {
        var (clientId, _, _) = await RegisterAppAsync("matpeople-e", backchannel: "http://matpeople-e.internal/signout-backchannel");
        var person = await CreatePersonAsync("people-emil");
        long groupId;
        using (var scope = _site.Services.CreateScope())
        {
            var group = await scope.ServiceProvider.GetRequiredService<GroupService>().SaveAsync(null, "Team " + clientId, null, []);
            groupId = group.Id;
            await scope.ServiceProvider.GetRequiredService<PermissionService>().SaveGrantAsync(clientId, null, group.Id, "member", null);
        }

        _site.Backchannel.Clear();
        using (var scope = _site.Services.CreateScope())
        {
            await scope.ServiceProvider.GetRequiredService<GroupService>().SaveAsync(groupId, "Team " + clientId, null, [person.Id]);
        }

        Assert.Equal(person.Subject, Jwt((await NextBackchannelAsync()).Form["logout_token"]).GetProperty("sub").GetString());

        _site.Backchannel.Clear();
        using (var scope = _site.Services.CreateScope())
        {
            var permissions = scope.ServiceProvider.GetRequiredService<PermissionService>();
            var grant = (await permissions.GrantsAsync(clientId)).Single();
            await permissions.RevokeAsync(grant.Id);
        }

        Assert.Equal(person.Subject, Jwt((await NextBackchannelAsync()).Form["logout_token"]).GetProperty("sub").GetString());
    }

    // ---- SCIM ------------------------------------------------------------------------------------------------------------------------

    [Fact]
    public async Task Scim_needs_a_key_and_describes_itself()
    {
        Assert.Equal(HttpStatusCode.Unauthorized, (await _site.CreateClient().GetAsync("/scim/v2/Users")).StatusCode);

        var config = await ScimAsync(HttpMethod.Get, "/scim/v2/ServiceProviderConfig");
        Assert.True(config.GetProperty("patch").GetProperty("supported").GetBoolean());
        Assert.False(config.GetProperty("bulk").GetProperty("supported").GetBoolean());

        // The key as a bearer token works too (what SCIM clients send).
        var bearer = _site.CreateClient();
        bearer.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", IdentityFactory.ApiKey);
        var types = await bearer.GetAsync("/scim/v2/ResourceTypes");
        Assert.Equal(HttpStatusCode.OK, types.StatusCode);
        Assert.Equal("application/scim+json", types.Content.Headers.ContentType!.MediaType);
    }

    [Fact]
    public async Task Scim_makes_changes_and_removes_a_person_with_their_grants()
    {
        await RegisterAppAsync("matpeople-f");
        var created = await ScimAsync(HttpMethod.Post, "/scim/v2/Users", new JsonObjectBuilder
        {
            ["schemas"] = new[] { ScimEndpoints.UserSchema, ScimEndpoints.UserAccessSchema },
            ["userName"] = "scim-frieda",
            ["name"] = new Dictionary<string, string> { ["givenName"] = "Frieda", ["familyName"] = "Fink" },
            ["emails"] = new[] { new Dictionary<string, object> { ["value"] = "frieda@example.test", ["primary"] = true } },
            ["externalId"] = "entra-42",
            ["password"] = "Kiwi-Garden-77",
            [ScimEndpoints.UserAccessSchema] = new Dictionary<string, object>
            {
                ["grants"] = new[] { new Dictionary<string, object?> { ["app"] = "matpeople-f", ["role"] = "member", ["permissions"] = new[] { "export" }, ["quotas"] = new Dictionary<string, long> { ["storage"] = 99 } } },
            },
        }.Build(), HttpStatusCode.Created);
        var subject = created.GetProperty("id").GetString()!;
        Assert.Equal("Frieda Fink", created.GetProperty("displayName").GetString());
        Assert.Equal("entra-42", created.GetProperty("externalId").GetString());
        var access = created.GetProperty(ScimEndpoints.UserAccessSchema).GetProperty("access").EnumerateArray().Single(a => a.GetProperty("app").GetString() == "matpeople-f");
        Assert.Equal("member", access.GetProperty("role").GetString());
        Assert.Equal(99, access.GetProperty("quotas").GetProperty("storage").GetInt64());
        Assert.Equal("person", access.GetProperty("via")[0].GetString());
        Assert.Contains(created.GetProperty("entitlements").EnumerateArray(), e => e.GetProperty("value").GetString() == "export" && e.GetProperty("type").GetString() == "matpeople-f");
        Assert.False(created.TryGetProperty("password", out _));

        // A name that is taken, a filter, a patch (Entra style: "Replace" and "False" as text).
        Assert.Equal(HttpStatusCode.Conflict, (await SendAsync(HttpMethod.Post, "/scim/v2/Users", new { userName = "scim-frieda" })).StatusCode);
        var found = await ScimAsync(HttpMethod.Get, "/scim/v2/Users?filter=" + Uri.EscapeDataString("externalId eq \"entra-42\""));
        Assert.Equal(1, found.GetProperty("totalResults").GetInt32());
        Assert.Equal(HttpStatusCode.BadRequest, (await SendAsync(HttpMethod.Get, "/scim/v2/Users?filter=" + Uri.EscapeDataString("userName sw \"scim\""))).StatusCode);

        var patched = await ScimAsync(HttpMethod.Patch, "/scim/v2/Users/" + subject, new
        {
            schemas = new[] { "urn:ietf:params:scim:api:messages:2.0:PatchOp" },
            Operations = new object[]
            {
                new { op = "Replace", path = "active", value = "False" },
                new { op = "replace", path = "emails[type eq \"work\"].value", value = "frieda.fink@example.test" },
                new { op = "replace", path = ScimEndpoints.UserAccessSchema + ":grants", value = Array.Empty<object>() },
            },
        });
        Assert.False(patched.GetProperty("active").GetBoolean());
        Assert.Equal("frieda.fink@example.test", patched.GetProperty("emails")[0].GetProperty("value").GetString());
        Assert.Empty(patched.GetProperty(ScimEndpoints.UserAccessSchema).GetProperty("grants").EnumerateArray());
        // Disabled: no access anywhere.
        Assert.Empty(patched.GetProperty(ScimEndpoints.UserAccessSchema).GetProperty("access").EnumerateArray());

        Assert.Equal(HttpStatusCode.NoContent, (await SendAsync(HttpMethod.Delete, "/scim/v2/Users/" + subject)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await SendAsync(HttpMethod.Get, "/scim/v2/Users/" + subject)).StatusCode);
    }

    [Fact]
    public async Task Scim_groups_have_members_and_grants()
    {
        await RegisterAppAsync("matpeople-g");
        var greta = await CreatePersonAsync("people-greta");
        var hugo = await CreatePersonAsync("people-hugo");
        var group = await ScimAsync(HttpMethod.Post, "/scim/v2/Groups", new JsonObjectBuilder
        {
            ["displayName"] = "SCIM team",
            ["members"] = new[] { new { value = greta.Subject }, new { value = hugo.Subject } },
            [ScimEndpoints.GroupAccessSchema] = new Dictionary<string, object> { ["grants"] = new[] { new { app = "matpeople-g", role = "member" } } },
        }.Build(), HttpStatusCode.Created);
        var groupId = group.GetProperty("id").GetString()!;
        Assert.Equal(2, group.GetProperty("members").GetArrayLength());

        var person = await ScimAsync(HttpMethod.Get, "/scim/v2/Users/" + greta.Subject);
        var access = person.GetProperty(ScimEndpoints.UserAccessSchema).GetProperty("access").EnumerateArray().Single(a => a.GetProperty("app").GetString() == "matpeople-g");
        Assert.Equal("group:SCIM team", access.GetProperty("via")[0].GetString());

        var patched = await ScimAsync(HttpMethod.Patch, "/scim/v2/Groups/" + groupId, new
        {
            Operations = new object[] { new { op = "remove", path = $"members[value eq \"{hugo.Subject}\"]" } },
        });
        Assert.Equal(greta.Subject, Assert.Single(patched.GetProperty("members").EnumerateArray()).GetProperty("value").GetString());

        Assert.Equal(HttpStatusCode.BadRequest, (await SendAsync(HttpMethod.Post, "/scim/v2/Groups", new { displayName = "Ghosts", members = new[] { new { value = "nobody" } } })).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await SendAsync(HttpMethod.Delete, "/scim/v2/Groups/" + groupId)).StatusCode);
    }

    [Fact]
    public async Task The_key_of_people_scim_reads_only_the_people_of_its_app()
    {
        await RegisterAppAsync("matpeople-h");
        var ida = await CreatePersonAsync("people-ida");
        var jan = await CreatePersonAsync("people-jan");
        using (var scope = _site.Services.CreateScope())
        {
            await scope.ServiceProvider.GetRequiredService<PermissionService>().SaveGrantAsync("matpeople-h", ida.Id, null, "member", Values(["export"], new()));
        }

        var bound = await _site.Api().PutAsJsonAsync("/api/bindings/people.scim/matpeople-h", new
        {
            version = 1,
            managedBy = "mattiverse",
            consumer = new { name = "MatPeople H", internalUrl = "http://matpeople-h:4000" },
            provider = new { url = "https://id.example.test", internalUrl = "http://matidentity:2300" },
            @params = new Dictionary<string, string>(),
            renew = false,
        });
        var text = await bound.Content.ReadAsStringAsync();
        Assert.True(bound.IsSuccessStatusCode, text);
        var key = JsonDocument.Parse(text).RootElement.GetProperty("variables").GetProperty("MAT_PEOPLE_SCIM_KEY").GetString()!;

        var app = _site.CreateClient();
        app.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", key);
        var list = JsonDocument.Parse(await app.GetStringAsync("/scim/v2/Users?count=500")).RootElement;
        var subjects = list.GetProperty("Resources").EnumerateArray().Select(r => r.GetProperty("id").GetString()).ToList();
        Assert.Contains(ida.Subject, subjects);
        Assert.DoesNotContain(jan.Subject, subjects);

        var person = JsonDocument.Parse(await app.GetStringAsync("/scim/v2/Users/" + ida.Subject)).RootElement;
        var extension = person.GetProperty(ScimEndpoints.UserAccessSchema);
        Assert.Equal("matpeople-h", Assert.Single(extension.GetProperty("access").EnumerateArray()).GetProperty("app").GetString());
        Assert.False(extension.TryGetProperty("grants", out _));
        Assert.False(extension.TryGetProperty("administrator", out _));
        Assert.Equal(HttpStatusCode.NotFound, (await app.GetAsync("/scim/v2/Users/" + jan.Subject)).StatusCode);

        var write = await app.PostAsync("/scim/v2/Users", new StringContent("""{"userName":"intruder"}""", Encoding.UTF8, "application/scim+json"));
        Assert.Equal(HttpStatusCode.Forbidden, write.StatusCode);
        await _site.Api().DeleteAsync("/api/bindings/people.scim/matpeople-h?managedBy=mattiverse");
    }

    [Fact]
    public async Task The_last_administrator_stays_and_the_actions_on_a_person_answer()
    {
        using (var scope = _site.Services.CreateScope())
        {
            var users = scope.ServiceProvider.GetRequiredService<UserService>();
            var admin = (await users.GetByUsernameAsync(DevAccount.Username))!;
            if (await users.CountActiveAdminsAsync() == 1)
            {
                var refused = await SendAsync(HttpMethod.Patch, "/scim/v2/Users/" + admin.Subject, new { Operations = new object[] { new { op = "replace", path = "active", value = false } } });
                Assert.Equal(HttpStatusCode.BadRequest, refused.StatusCode);
                Assert.Contains("mutability", await refused.Content.ReadAsStringAsync());
            }
        }

        var person = await CreatePersonAsync("people-karl");
        var signOut = await _site.Api().PostAsync($"/api/v1/people/{person.Subject}/actions/signOut", null);
        Assert.Equal(HttpStatusCode.OK, signOut.StatusCode);
        Assert.True(JsonDocument.Parse(await signOut.Content.ReadAsStringAsync()).RootElement.GetProperty("ok").GetBoolean());
        Assert.Equal(HttpStatusCode.Conflict, (await _site.Api().PostAsync($"/api/v1/people/{person.Subject}/actions/invite", null)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await _site.Api().PostAsync($"/api/v1/people/{person.Subject}/actions/explode", null)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await _site.Api().PostAsync("/api/v1/people/nobody/actions/signOut", null)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await _site.CreateClient().PostAsync($"/api/v1/people/{person.Subject}/actions/signOut", null)).StatusCode);
    }

    [Fact]
    public async Task Signed_out_everywhere_ends_the_renewal_of_every_app()
    {
        // OpenIddict keeps the type of a token as its URN: the revoker once looked for "refresh_token" and revoked nothing.
        var (clientId, secret, redirect) = await RegisterAppAsync("matpeople-l");
        var person = await CreatePersonAsync("people-lena");
        using (var scope = _site.Services.CreateScope())
        {
            await scope.ServiceProvider.GetRequiredService<PermissionService>().SaveGrantAsync(clientId, person.Id, null, "member", null);
        }

        var browser = _site.Browser();
        await IdentityFactory.SignInAsync(browser, "/Account/Login", "people-lena", Password);
        var tokens = await CodeFlowAsync(browser, clientId, secret, redirect);
        Assert.Equal(HttpStatusCode.OK, (await _site.Api().PostAsync($"/api/v1/people/{person.Subject}/actions/signOut", null)).StatusCode);

        var refreshed = await RefreshAsync(clientId, secret, tokens.GetProperty("refresh_token").GetString()!);
        Assert.Equal(HttpStatusCode.BadRequest, refreshed.StatusCode);
    }

    [Fact]
    public async Task The_page_of_a_grant_sets_role_permissions_and_quotas()
    {
        await RegisterAppAsync("matpeople-m");
        var person = await CreatePersonAsync("people-mia");
        long grantId;
        using (var scope = _site.Services.CreateScope())
        {
            var permissions = scope.ServiceProvider.GetRequiredService<PermissionService>();
            await permissions.GrantAsync("matpeople-m", person.Id, null, null);
            grantId = (await permissions.GrantsAsync("matpeople-m")).Single().Id;
        }

        var admin = await _site.AdminAsync();
        var page = $"/Apps/Grant?id=matpeople-m&grant={grantId}";
        var html = await admin.GetStringAsync(page);
        Assert.Contains("Storage (GB)", html);
        Assert.Contains("AI tokens (tokens per month)", html);

        // A quota that is no number: the page again, with the message, nothing saved.
        var wrong = await IdentityFactory.PostFormAsync(admin, page, new Dictionary<string, string> { ["Role"] = "member", ["Quota[storage]"] = "lots" });
        Assert.Equal(HttpStatusCode.OK, wrong.StatusCode);
        Assert.Contains("a number of GB", await wrong.Content.ReadAsStringAsync());

        var saved = await IdentityFactory.PostFormAsync(admin, page, new Dictionary<string, string>
        {
            ["Role"] = "member",
            ["Permissions"] = "export",
            ["Quota[storage]"] = "2,5",
            ["Unlimited"] = "ai-tokens",
        });
        Assert.Equal(HttpStatusCode.Redirect, saved.StatusCode);

        using (var scope = _site.Services.CreateScope())
        {
            var grant = (await scope.ServiceProvider.GetRequiredService<PermissionService>().GrantsAsync("matpeople-m")).Single();
            var values = GrantValues.Of(grant);
            Assert.Equal("member", grant.RoleKey);
            Assert.Equal(["export"], values.Permissions);
            Assert.Equal((long)(2.5 * 1024 * 1024 * 1024), values.Quotas["storage"]);
            Assert.Null(values.Quotas["ai-tokens"]);
        }

        // The Access page names it in a few words.
        Assert.Contains("Storage 2.5 GB", await admin.GetStringAsync("/Apps/Access?id=matpeople-m"));
    }

    [Fact]
    public void Grants_are_held_to_the_permissions_and_limits_of_the_app()
    {
        PermissionInfo[] permissions = [new("export", "Export")];
        QuotaInfo[] quotas = [new("storage", "Storage", "bytes", Min: 1, Max: 100)];
        Assert.Empty(PermissionService.ValidateGrant(Values(["export"], new() { ["storage"] = 100 }), permissions, quotas));
        Assert.Empty(PermissionService.ValidateGrant(Values([], new() { ["storage"] = null }), permissions, quotas));
        Assert.Contains("permissions", PermissionService.ValidateGrant(Values(["nuke"], new()), permissions, quotas).Keys);
        Assert.Contains("quotas.storage", PermissionService.ValidateGrant(Values([], new() { ["storage"] = 101 }), permissions, quotas).Keys);
        Assert.Contains("quotas.files", PermissionService.ValidateGrant(Values([], new() { ["files"] = 1 }), permissions, quotas).Keys);

        Assert.NotEmpty(PermissionService.ValidateCatalog([new("Bad Key", "x")], null));
        Assert.NotEmpty(PermissionService.ValidateCatalog(null, [new("files", "Files", "count", "week")]));
        Assert.NotEmpty(PermissionService.ValidateCatalog(null, [new("files", "Files", "count", Min: 5, Max: 1)]));
        Assert.Empty(PermissionService.ValidateCatalog([new("export", "Export", Roles: ["admin"])], [new("files", "Files", "count", "month", 0, 10)]));
    }

    // ---- helpers ---------------------------------------------------------------------------------------------------------------------

    private static GrantValues Values(IReadOnlyList<string> permissions, Dictionary<string, long?> quotas) => new(permissions, quotas);

    private async Task<User> CreatePersonAsync(string username)
    {
        using var scope = _site.Services.CreateScope();
        return await scope.ServiceProvider.GetRequiredService<UserService>().CreateAsync(username, username, null, Password, UserRole.User);
    }

    /// <summary>An app with the roles admin and member, the permissions share-public (admin) and export, the quotas storage and ai-tokens (month).</summary>
    private async Task<(string ClientId, string Secret, string Redirect)> RegisterAppAsync(string id, string roleMode = "matidentity", string? backchannel = null)
    {
        var redirect = $"https://{id}.test/signin-oidc";
        var response = await _site.Api().PutAsJsonAsync($"/api/v1/clients/{id}", new
        {
            displayName = id,
            redirectUris = new[] { redirect },
            roleMode,
            roles = new[] { new { key = "admin", label = "Administrator" }, new { key = "member", label = "Member" } },
            permissions = new object[]
            {
                new { key = "share-public", label = "Share publicly", roles = new[] { "admin" } },
                new { key = "export", label = "Export" },
                new { key = "drives-create", label = "Create drives" },
            },
            quotas = new object[] { new { key = "storage", label = "Storage", unit = "bytes", min = 0 }, new { key = "ai-tokens", label = "AI tokens", unit = "tokens", period = "month" } },
            backchannelLogoutUri = backchannel,
        });
        var text = await response.Content.ReadAsStringAsync();
        Assert.True(response.IsSuccessStatusCode, text);
        return (id, JsonDocument.Parse(text).RootElement.GetProperty("clientSecret").GetString()!, redirect);
    }

    private async Task<(Uri Address, Dictionary<string, string> Form)> NextBackchannelAsync()
    {
        for (var i = 0; i < 100; i++)
        {
            if (_site.Backchannel.TryDequeue(out var notice))
            {
                return notice;
            }

            await Task.Delay(50);
        }

        throw new TimeoutException("No back-channel logout was sent.");
    }

    private async Task<JsonElement> ScimAsync(HttpMethod method, string path, object? body = null, HttpStatusCode expected = HttpStatusCode.OK)
    {
        var response = await SendAsync(method, path, body);
        var text = await response.Content.ReadAsStringAsync();
        Assert.True(response.StatusCode == expected, $"{(int)response.StatusCode}: {text}");
        return JsonDocument.Parse(text).RootElement.Clone();
    }

    private Task<HttpResponseMessage> SendAsync(HttpMethod method, string path, object? body = null)
    {
        var request = new HttpRequestMessage(method, path);
        if (body is not null)
        {
            request.Content = new StringContent(body is string s ? s : JsonSerializer.Serialize(body), Encoding.UTF8, "application/scim+json");
        }

        return _site.Api().SendAsync(request);
    }

    private Task<HttpResponseMessage> RefreshAsync(string clientId, string secret, string refreshToken)
        => _site.CreateClient().PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token",
            ["refresh_token"] = refreshToken,
            ["client_id"] = clientId,
            ["client_secret"] = secret,
        }));

    private async Task<JsonElement> CodeFlowAsync(HttpClient browser, string clientId, string secret, string redirect)
    {
        var verifier = Base64Url(RandomNumberGenerator.GetBytes(32));
        var challenge = Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));
        var response = await browser.GetAsync($"/connect/authorize?client_id={clientId}&response_type=code&scope={Uri.EscapeDataString("openid profile roles offline_access")}" +
            $"&redirect_uri={Uri.EscapeDataString(redirect)}&code_challenge={challenge}&code_challenge_method=S256");
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.StartsWith(redirect, response.Headers.Location!.OriginalString);
        var code = HttpUtility.ParseQueryString(response.Headers.Location!.Query)["code"]!;
        var token = await _site.CreateClient().PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = redirect,
            ["client_id"] = clientId,
            ["client_secret"] = secret,
            ["code_verifier"] = verifier,
        }));
        var text = await token.Content.ReadAsStringAsync();
        Assert.True(token.IsSuccessStatusCode, text);
        return JsonDocument.Parse(text).RootElement.Clone();
    }

    /// <summary>One value, written as a string or as an array of one.</summary>
    private static string? Single(JsonElement value) => value.ValueKind == JsonValueKind.Array ? Assert.Single(value.EnumerateArray()).GetString() : value.GetString();

    private static JsonElement Jwt(string jwt)
    {
        var part = jwt.Split('.')[1].Replace('-', '+').Replace('_', '/');
        part = part.PadRight(part.Length + ((4 - (part.Length % 4)) % 4), '=');
        return JsonDocument.Parse(Convert.FromBase64String(part)).RootElement.Clone();
    }

    private static string Base64Url(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    /// <summary>A JSON object with keys that are not C# names (the URNs of SCIM).</summary>
    private sealed class JsonObjectBuilder : Dictionary<string, object?>
    {
        public string Build() => JsonSerializer.Serialize(this);
    }
}
