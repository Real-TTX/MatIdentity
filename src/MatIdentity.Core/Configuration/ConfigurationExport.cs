using System.Text.Json;
using System.Text.Json.Serialization;
using MatIdentity.Core.Access;
using MatIdentity.Core.Clients;
using MatIdentity.Core.Entities;
using MatIdentity.Core.Users;

namespace MatIdentity.Core.Configuration;

/// <summary>
/// The configuration as one JSON document, for a look at it, a comparison, or setting up another MatIdentity by hand: the settings, the apps with their rules,
/// roles and grants, the groups and the people. Never a secret: no password or hash, no app secret, no SMTP password, no authenticator key, no passkey, no token
/// key. It is not a backup: that is the data volume (it holds the keys that sign the tokens).
/// </summary>
public sealed class ConfigurationExport
{
    public const string Format = "matidentity-configuration";

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    private readonly SystemConfigService _config;
    private readonly ClientService _clients;
    private readonly PermissionService _permissions;
    private readonly GroupService _groups;
    private readonly UserService _users;
    private readonly TimeProvider _time;

    public ConfigurationExport(SystemConfigService config, ClientService clients, PermissionService permissions, GroupService groups, UserService users, TimeProvider time)
    {
        _config = config;
        _clients = clients;
        _permissions = permissions;
        _groups = groups;
        _users = users;
        _time = time;
    }

    public async Task<byte[]> CreateAsync(CancellationToken ct = default)
    {
        var config = await _config.GetAsync(ct);
        var people = await _users.GetAllAsync(ct);
        var usernames = people.ToDictionary(p => p.Id, p => p.Username);

        var groups = new List<object>();
        var groupNames = new Dictionary<long, string>();
        foreach (var (group, _) in await _groups.GetAllAsync(ct))
        {
            groupNames[group.Id] = group.Name;
            var members = (await _groups.MemberIdsAsync(group.Id, ct)).Where(usernames.ContainsKey).Select(id => usernames[id]).Order(StringComparer.OrdinalIgnoreCase).ToList();
            groups.Add(new { group.Name, group.Description, Members = members });
        }

        var apps = new List<object>();
        foreach (var client in await _clients.GetAllAsync(ct))
        {
            var policy = await _permissions.PolicyAsync(client.ClientId, ct);
            var grants = (await _permissions.GrantsAsync(client.ClientId, ct)).Select(g => new
            {
                Person = g.UserId is { } u && usernames.TryGetValue(u, out var name) ? name : null,
                Group = g.GroupId is { } id && groupNames.TryGetValue(id, out var groupName) ? groupName : null,
                Role = g.RoleKey,
            });
            apps.Add(new
            {
                client.ClientId,
                client.DisplayName,
                client.HomeUrl,
                client.AllowSignIn,
                client.AllowMachine,
                client.IsPublic,
                client.RedirectUris,
                client.PostLogoutRedirectUris,
                client.BackchannelLogoutUri,
                client.ManagedBy,
                RoleMode = policy.RoleMode == RoleMode.App ? "app" : "matidentity",
                policy.OpenToEveryone,
                policy.CallsAllApps,
                CallTargets = await _permissions.CallTargetsAsync(client.ClientId, ct),
                Roles = await _permissions.RolesAsync(client.ClientId, ct),
                Grants = grants,
            });
        }

        var document = new
        {
            Format,
            Version = 1,
            Exported = _time.GetUtcNow(),
            MatIdentity = AppVersion.Current,
            Settings = new
            {
                config.InstanceName,
                config.Issuer,
                config.SessionLifetimeDays,
                config.AccessTokenMinutes,
                Smtp = config.SmtpHost is null ? null : new { Host = config.SmtpHost, Port = config.SmtpPort, Tls = config.SmtpTls, From = config.SmtpFrom, Username = config.SmtpUsername },
            },
            Apps = apps,
            Groups = groups,
            People = people.Select(p => new
            {
                p.Username,
                p.DisplayName,
                p.Email,
                p.EmailVerified,
                Role = p.Role == UserRole.Admin ? "admin" : "user",
                p.IsActive,
                SecondStep = p.TotpEnabled ? "authenticator app" : null,
            }),
        };

        return JsonSerializer.SerializeToUtf8Bytes(document, Json);
    }
}
