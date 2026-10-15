using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Web;
using MatIdentity.Core.Access;
using MatIdentity.Core.Entities;
using MatIdentity.Core.Users;
using Microsoft.Extensions.DependencyInjection;

namespace MatIdentity.Tests;

/// <summary>
/// Who may sign in where, with which role, against the site in memory: a person without a grant is turned away, a group gives access and a role,
/// an app that decides its roles itself gets no role, and a machine only gets tokens for the apps it may call.
/// </summary>
[Collection(TestCollection.Name)]
public sealed class PermissionTests
{
    private readonly IdentityFactory _site;

    public PermissionTests(IdentityFactory site)
    {
        _site = site;
    }

    [Fact]
    public async Task A_person_without_a_grant_is_turned_away_and_a_group_lets_them_in_with_its_role()
    {
        var (clientId, secret, redirect) = await RegisterAppAsync("matperm-a", roles: [new("owner", "Owner"), new("editor", "Editor"), new("viewer", "Viewer")]);
        var person = await CreatePersonAsync("perm-anna");

        // No grant: MatIdentity says no on its own page, the app never gets a code.
        var browser = _site.Browser();
        await IdentityFactory.SignInAsync(browser, "/Account/Login", "perm-anna", "Person-Pass-1");
        var (_, challenge) = Pkce();
        var denied = await browser.GetAsync(Authorize(clientId, redirect, challenge));
        Assert.Equal(HttpStatusCode.Redirect, denied.StatusCode);
        Assert.StartsWith("/Account/NoAccess", denied.Headers.Location!.OriginalString);

        // In a group that has the app as editor: in, with the role editor.
        using (var scope = _site.Services.CreateScope())
        {
            var group = await scope.ServiceProvider.GetRequiredService<GroupService>().SaveAsync(null, "Editors " + clientId, null, [person.Id]);
            await scope.ServiceProvider.GetRequiredService<PermissionService>().GrantAsync(clientId, null, group.Id, "editor");
        }

        var claims = await SignInToAppAsync(browser, clientId, secret, redirect);
        Assert.Equal("editor", claims.GetProperty("role").GetString());

        // A grant of the person's own wins over the group.
        using (var scope = _site.Services.CreateScope())
        {
            await scope.ServiceProvider.GetRequiredService<PermissionService>().GrantAsync(clientId, person.Id, null, "viewer");
        }

        Assert.Equal("viewer", (await SignInToAppAsync(browser, clientId, secret, redirect)).GetProperty("role").GetString());
    }

    [Fact]
    public async Task An_app_that_decides_its_roles_itself_gets_no_role_and_an_open_app_lets_everyone_in()
    {
        var (clientId, secret, redirect) = await RegisterAppAsync("matperm-b", roleMode: "app", openToEveryone: true);
        await CreatePersonAsync("perm-ben");
        var browser = _site.Browser();
        await IdentityFactory.SignInAsync(browser, "/Account/Login", "perm-ben", "Person-Pass-1");

        var claims = await SignInToAppAsync(browser, clientId, secret, redirect);
        Assert.False(claims.TryGetProperty("role", out _));
        Assert.Equal("perm-ben", claims.GetProperty("preferred_username").GetString());
    }

    [Fact]
    public async Task Taking_the_app_away_ends_the_next_renewal()
    {
        var (clientId, secret, redirect) = await RegisterAppAsync("matperm-c");
        var person = await CreatePersonAsync("perm-cleo");
        using (var scope = _site.Services.CreateScope())
        {
            await scope.ServiceProvider.GetRequiredService<PermissionService>().GrantAsync(clientId, person.Id, null, null);
        }

        var browser = _site.Browser();
        await IdentityFactory.SignInAsync(browser, "/Account/Login", "perm-cleo", "Person-Pass-1");
        var tokens = await CodeFlowAsync(browser, clientId, secret, redirect);
        Assert.Equal("user", Jwt(tokens.GetProperty("id_token").GetString()!).GetProperty("role").GetString());

        using (var scope = _site.Services.CreateScope())
        {
            var permissions = scope.ServiceProvider.GetRequiredService<PermissionService>();
            var grant = (await permissions.GrantsAsync(clientId)).Single();
            await permissions.RevokeAsync(grant.Id);
        }

        var refreshed = await _site.CreateClient().PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token",
            ["refresh_token"] = tokens.GetProperty("refresh_token").GetString()!,
            ["client_id"] = clientId,
            ["client_secret"] = secret,
        }));
        Assert.Equal(HttpStatusCode.BadRequest, refreshed.StatusCode);
        Assert.Contains("invalid_grant", await refreshed.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task A_machine_gets_tokens_only_for_the_apps_it_may_call()
    {
        await RegisterAppAsync("matperm-target");
        await RegisterAppAsync("matperm-other");
        var put = await _site.Api().PutAsJsonAsync("/api/v1/clients/matperm-caller", new { displayName = "Caller", allowSignIn = false, allowMachine = true });
        var secret = JsonDocument.Parse(await put.Content.ReadAsStringAsync()).RootElement.GetProperty("clientSecret").GetString()!;

        // Only matperm-target, given on the page of the caller (the same calls as the page).
        using (var scope = _site.Services.CreateScope())
        {
            await scope.ServiceProvider.GetRequiredService<PermissionService>().SetCallTargetsAsync("matperm-caller", ["matperm-target"]);
            await scope.ServiceProvider.GetRequiredService<MatIdentity.Core.Clients.ClientService>().SyncCallScopesAsync("matperm-caller");
        }

        Assert.Equal(HttpStatusCode.OK, (await MachineTokenAsync("matperm-caller", secret, "app:matperm-target")).StatusCode);
        var other = await MachineTokenAsync("matperm-caller", secret, "app:matperm-other");
        Assert.Equal(HttpStatusCode.BadRequest, other.StatusCode);
        // OpenIddict answers invalid_request: "This client application is not allowed to use the specified scope".
        Assert.Contains("scope", await other.Content.ReadAsStringAsync());
        Assert.DoesNotContain("access_token", await other.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task The_client_api_takes_roles_and_refuses_bad_ones()
    {
        var api = _site.Api();
        var good = await api.PutAsJsonAsync("/api/v1/clients/matperm-roles", new
        {
            displayName = "Roles",
            redirectUris = new[] { "https://roles.test/signin-oidc" },
            roleMode = "matidentity",
            roles = new[] { new { key = "admin", label = "Administrator" }, new { key = "member", label = "Member" } },
        });
        Assert.Equal(HttpStatusCode.OK, good.StatusCode);
        using (var doc = JsonDocument.Parse(await good.Content.ReadAsStringAsync()))
        {
            Assert.Equal("member", doc.RootElement.GetProperty("roles")[1].GetProperty("key").GetString());
        }

        var bad = await api.PutAsJsonAsync("/api/v1/clients/matperm-roles", new { roles = new[] { new { key = "Not A Key", label = "x" } } });
        Assert.Equal(HttpStatusCode.BadRequest, bad.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await api.PutAsJsonAsync("/api/v1/clients/matperm-roles", new { roleMode = "nobody" })).StatusCode);
    }

    [Fact]
    public void Roles_are_checked()
    {
        Assert.Empty(PermissionService.ValidateRoles([new("admin", "Administrator"), new("user", "User")]));
        Assert.NotEmpty(PermissionService.ValidateRoles([]));
        Assert.NotEmpty(PermissionService.ValidateRoles([new("admin", "A"), new("admin", "B")]));
        Assert.NotEmpty(PermissionService.ValidateRoles([new("Admin Role", "A")]));
    }

    [Fact]
    public void Roles_are_read_from_lines()
        => Assert.Equal(
            [new RoleInfo("admin", "Administrator"), new RoleInfo("editor", "Can edit everything"), new RoleInfo("viewer", "viewer")],
            MatIdentity.Web.Pages.Apps.AccessModel.ParseRoles("admin Administrator\r\neditor\tCan edit everything\n\nviewer"));

    private async Task<User> CreatePersonAsync(string username)
    {
        using var scope = _site.Services.CreateScope();
        return await scope.ServiceProvider.GetRequiredService<UserService>().CreateAsync(username, username, null, "Person-Pass-1", UserRole.User);
    }

    private async Task<(string ClientId, string Secret, string Redirect)> RegisterAppAsync(string id, IReadOnlyList<RoleInfo>? roles = null, string roleMode = "matidentity", bool openToEveryone = false)
    {
        var redirect = $"https://{id}.test/signin-oidc";
        var response = await _site.Api().PutAsJsonAsync($"/api/v1/clients/{id}", new
        {
            displayName = id,
            redirectUris = new[] { redirect },
            roleMode,
            openToEveryone,
            roles = roles?.Select(r => new { key = r.Key, label = r.Label }).ToArray(),
        });
        var text = await response.Content.ReadAsStringAsync();
        Assert.True(response.IsSuccessStatusCode, text);
        return (id, JsonDocument.Parse(text).RootElement.GetProperty("clientSecret").GetString()!, redirect);
    }

    private async Task<JsonElement> SignInToAppAsync(HttpClient browser, string clientId, string secret, string redirect)
        => Jwt((await CodeFlowAsync(browser, clientId, secret, redirect)).GetProperty("id_token").GetString()!);

    private async Task<JsonElement> CodeFlowAsync(HttpClient browser, string clientId, string secret, string redirect)
    {
        var (verifier, challenge) = Pkce();
        var response = await browser.GetAsync(Authorize(clientId, redirect, challenge));
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

    private Task<HttpResponseMessage> MachineTokenAsync(string clientId, string secret, string scope)
        => _site.CreateClient().PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = clientId,
            ["client_secret"] = secret,
            ["scope"] = scope,
        }));

    private static string Authorize(string clientId, string redirect, string challenge)
        => $"/connect/authorize?client_id={clientId}&response_type=code&scope={Uri.EscapeDataString("openid profile roles offline_access")}" +
           $"&redirect_uri={Uri.EscapeDataString(redirect)}&code_challenge={challenge}&code_challenge_method=S256";

    private static (string Verifier, string Challenge) Pkce()
    {
        var verifier = Base64Url(RandomNumberGenerator.GetBytes(32));
        return (verifier, Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(verifier))));
    }

    private static JsonElement Jwt(string jwt)
    {
        var part = jwt.Split('.')[1].Replace('-', '+').Replace('_', '/');
        part = part.PadRight(part.Length + ((4 - (part.Length % 4)) % 4), '=');
        return JsonDocument.Parse(Convert.FromBase64String(part)).RootElement.Clone();
    }

    private static string Base64Url(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
