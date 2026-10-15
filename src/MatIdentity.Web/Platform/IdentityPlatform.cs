using System.Text.Json;
using MatIdentity.Core;
using MatIdentity.Core.Activity;
using MatIdentity.Core.Auth;
using MatIdentity.Core.Clients;
using MatIdentity.Core.Configuration;
using MatIdentity.Core.Data;
using MatIdentity.Core.Entities;
using MatIdentity.Core.Users;
using MatIdentity.Web.Support;
using Microsoft.EntityFrameworkCore;

namespace MatIdentity.Web.Platform;

/// <summary>
/// MatIdentity as an app of the platform contract: how Mattiverse shows it (tiles, settings, buttons), what its values are and what the
/// buttons do. The settings are the same as on the Settings page, checked by the same <see cref="SystemConfigService"/>.
/// </summary>
public sealed class IdentityPlatform : IMatPlatformApp
{
    private static readonly ActivityKind[] SignIns = [ActivityKind.SignIn];
    private static readonly ActivityKind[] Failures = [ActivityKind.SignInFailed];

    private readonly MatIdentityDbContext _db;
    private readonly UserService _users;
    private readonly ClientService _clients;
    private readonly SessionService _sessions;
    private readonly ActivityService _activity;
    private readonly SystemConfigService _config;
    private readonly ApiAccess _access;
    private readonly TokenRevoker _revoker;

    public IdentityPlatform(MatIdentityDbContext db, UserService users, ClientService clients, SessionService sessions, ActivityService activity, SystemConfigService config, ApiAccess access, TokenRevoker revoker)
    {
        _revoker = revoker;
        _db = db;
        _users = users;
        _clients = clients;
        _sessions = sessions;
        _activity = activity;
        _config = config;
        _access = access;
    }

    public MatApiDefinition Definition(HttpContext http) => new()
    {
        App = new MatAppInfo(Ui.App.Id, Ui.App.Name, Ui.App.Tagline, AppVersion.Current, "/img/logo.svg", Ui.App.Accent),
        // MatIdentity is the identity: its own address is the authority.
        Auth = new MatAuthInfo(_access.KeyEnabled, $"{http.Request.Scheme}://{http.Request.Host}{http.Request.PathBase}"),
        Pages =
        [
            new MatPage("overview", "Overview", "dashboard",
            [
                new MatSection("tiles", ["users", "apps", "sessions", "signInsToday", "failedToday", "lastSignIn"]),
                new MatSection("actions", ["openAdmin", "openApps", "signOutEveryone"]),
            ]),
            new MatPage("settings", "Settings", "settings",
            [
                new MatSection("form", ["instanceName", "issuer"], Label: "General"),
                new MatSection("form", ["sessionLifetimeDays", "accessTokenMinutes"], Label: "Sign-in"),
            ]),
        ],
        State =
        [
            new MatStateItem("users", "People", "number") { Icon = "users" },
            new MatStateItem("apps", "Apps", "number") { Icon = "apps" },
            new MatStateItem("sessions", "Signed in now", "number") { Icon = "key" },
            new MatStateItem("signInsToday", "Sign-ins in 24 h", "number") { Icon = "login" },
            new MatStateItem("failedToday", "Failed sign-ins in 24 h", "number") { Icon = "alert", WarnAbove = 10, ErrorAbove = 50 },
            new MatStateItem("lastSignIn", "Last sign-in", "time"),
        ],
        Configure =
        [
            new MatField("instanceName", "Name", "text") { Required = true, Max = 80, Hint = "Shown on the sign-in page and in the menu." },
            new MatField("issuer", "Public address", "url")
            {
                Placeholder = "https://id.example.com",
                Hint = "The address the apps reach MatIdentity at. Empty: the address of each request.",
                Restart = true,
            },
            new MatField("sessionLifetimeDays", "Stay signed in (days)", "number")
            {
                Required = true, Min = SystemConfigService.MinSessionDays, Max = SystemConfigService.MaxSessionDays,
                Hint = "Without activity a person has to sign in again after this many days.",
            },
            new MatField("accessTokenMinutes", "Access token (minutes)", "number")
            {
                Required = true, Min = SystemConfigService.MinTokenMinutes, Max = SystemConfigService.MaxTokenMinutes,
                Hint = "Short is safer; the apps renew it on their own.", Restart = true,
            },
        ],
        Actions =
        [
            new MatAction("openAdmin", "Open MatIdentity", "external", "link") { Url = "/" },
            new MatAction("openApps", "Manage apps", "apps", "link") { Url = "/Apps" },
            new MatAction("signOutEveryone", "Sign everyone out", "logout", "post")
            {
                Confirm = "Sign everyone out? Every person has to sign in again, in every app.",
                Danger = true,
            },
        ],
        Provides = [new MatCapability("identity.oidc", 1)],
        Endpoints = ["/api/health", "/api/state", "/api/configure", "/api/actions", "/api/v1/clients"],
    };

    public async Task<MatHealth> HealthAsync(CancellationToken ct)
    {
        var checks = new List<MatHealthCheck>();
        try
        {
            await _db.Database.ExecuteSqlRawAsync("SELECT 1", ct);
            checks.Add(new MatHealthCheck("database", "ok"));
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            checks.Add(new MatHealthCheck("database", "down", "The database cannot be read."));
        }

        if (await _users.CountActiveAdminsAsync(ct) == 0 && await _users.CountAsync(ct) > 0)
        {
            checks.Add(new MatHealthCheck("administrators", "degraded", "No active administrator."));
        }

        var status = checks.Any(c => c.Status == "down") ? "down" : checks.Any(c => c.Status == "degraded") ? "degraded" : "ok";
        return new MatHealth(status, Ui.App.Id, AppVersion.Current, DateTimeOffset.Now, checks);
    }

    public async Task<IReadOnlyDictionary<string, MatStateValue>> StateAsync(CancellationToken ct)
    {
        var day = DateTime.UtcNow.AddDays(-1);
        var failed = await _activity.CountSinceAsync(day, Failures, ct);
        var last = await _activity.LastAsync(ActivityKind.SignIn, ct);
        return new Dictionary<string, MatStateValue>
        {
            ["users"] = new(await _users.CountAsync(ct)),
            ["apps"] = new(await _clients.CountAsync(ct)),
            ["sessions"] = new(await _sessions.CountActiveAsync(ct)),
            ["signInsToday"] = new(await _activity.CountSinceAsync(day, SignIns, ct)),
            ["failedToday"] = new(failed, failed > 50 ? "error" : failed > 10 ? "warn" : null),
            ["lastSignIn"] = new(last is null ? null : new DateTimeOffset(DateTime.SpecifyKind(last.Value, DateTimeKind.Utc))),
        };
    }

    public async Task<IReadOnlyDictionary<string, object?>> ConfigurationAsync(CancellationToken ct)
    {
        var config = await _config.GetAsync(ct);
        return new Dictionary<string, object?>
        {
            ["instanceName"] = config.InstanceName,
            ["issuer"] = config.Issuer,
            ["sessionLifetimeDays"] = config.SessionLifetimeDays,
            ["accessTokenMinutes"] = config.AccessTokenMinutes,
        };
    }

    public async Task<IReadOnlyDictionary<string, string>> ConfigureAsync(IReadOnlyDictionary<string, JsonElement> values, string caller, CancellationToken ct)
    {
        var config = await _config.GetAsync(ct);
        var errors = new Dictionary<string, string>();
        foreach (var (key, value) in values)
        {
            switch (key)
            {
                case "instanceName" when value.ValueKind == JsonValueKind.String:
                    config.InstanceName = value.GetString()!;
                    break;
                case "issuer" when value.ValueKind is JsonValueKind.String or JsonValueKind.Null:
                    config.Issuer = value.ValueKind == JsonValueKind.Null ? null : value.GetString();
                    break;
                case "sessionLifetimeDays" when value.TryGetInt32Strict(out var days):
                    config.SessionLifetimeDays = days;
                    break;
                case "accessTokenMinutes" when value.TryGetInt32Strict(out var minutes):
                    config.AccessTokenMinutes = minutes;
                    break;
                case "instanceName" or "issuer":
                    errors[key] = "Enter a text.";
                    break;
                case "sessionLifetimeDays" or "accessTokenMinutes":
                    errors[key] = "Enter a whole number.";
                    break;
                default:
                    errors[key] = "There is no such setting.";
                    break;
            }
        }

        if (errors.Count > 0)
        {
            return errors;
        }

        return await _config.SaveAsync(config, ct);
    }

    public async Task<(bool Ok, string Message)?> RunActionAsync(string id, string caller, CancellationToken ct)
    {
        switch (id)
        {
            case "signOutEveryone":
                var (sessions, tokens) = await SignOutEveryoneAsync(_sessions, _revoker, ct);
                await _activity.WriteAsync(ActivityKind.SignOut, username: caller, detail: $"Everyone signed out ({sessions} sessions, {tokens} app sign-ins)", ct: ct);
                return (true, $"{sessions} sessions and {tokens} app sign-ins ended.");
            default:
                return null;
        }
    }

    /// <summary>Ends every session here and every refresh token of the apps: everyone has to sign in again, everywhere. Also used by the Settings page.</summary>
    public static async Task<(int Sessions, int Tokens)> SignOutEveryoneAsync(SessionService sessions, TokenRevoker revoker, CancellationToken ct)
        => (await sessions.InvalidateEveryoneAsync(ct), await revoker.RevokeAllAsync(ct));
}

internal static class JsonElementExtensions
{
    /// <summary>A whole number sent as a JSON number (not a string, not a fraction).</summary>
    public static bool TryGetInt32Strict(this JsonElement value, out int number)
    {
        number = 0;
        return value.ValueKind == JsonValueKind.Number && value.TryGetInt32(out number);
    }
}
