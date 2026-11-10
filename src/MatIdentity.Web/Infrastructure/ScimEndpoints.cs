using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using MatIdentity.Core.Access;
using MatIdentity.Core.Activity;
using MatIdentity.Core.Auth;
using MatIdentity.Core.Clients;
using MatIdentity.Core.Configuration;
using MatIdentity.Core.Entities;
using MatIdentity.Core.Users;
using MatIdentity.Web.Platform;
using MatPlatform;
using Group = MatIdentity.Core.Entities.Group;

namespace MatIdentity.Web.Infrastructure;

/// <summary>Who calls SCIM: with the key everything (<paramref name="Full"/>), with the key of a binding of <c>people.scim</c> only the people of <paramref name="ClientId"/>, read only.</summary>
public sealed record ScimCaller(bool Full, string? ClientId, string Name);

/// <summary>
/// SCIM 2.0 (RFC 7643, RFC 7644) at <c>/scim/v2</c>: the people and groups of MatIdentity and what they are given in the apps (MatDesign docs/PLATFORM.md "SCIM at
/// MatIdentity"). A broker (Mattiverse) or a company's directory administers them with MatIdentity's <c>MAT_API_KEY</c> (as <c>X-Api-Key</c> or bearer); an app reads its
/// own people with the key of its binding of <c>people.scim</c>. Users are known by their subject, groups by their id; the extension
/// <see cref="UserAccessSchema"/> carries the grants (written) and what a person ends up with in each app (read only).
/// </summary>
public static partial class ScimEndpoints
{
    public const string UserSchema = "urn:ietf:params:scim:schemas:core:2.0:User";
    public const string GroupSchema = "urn:ietf:params:scim:schemas:core:2.0:Group";
    public const string UserAccessSchema = "urn:mat:scim:schemas:extension:access:1.0:User";
    public const string GroupAccessSchema = "urn:mat:scim:schemas:extension:access:1.0:Group";
    public const string ListSchema = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
    public const string ErrorSchema = "urn:ietf:params:scim:api:messages:2.0:Error";
    public const string ContentType = "application/scim+json";

    /// <summary>The person who acted, named by a broker (their subject): written to the activity list.</summary>
    public const string ActorHeader = "X-Mat-Actor";

    public const int MaxCount = 500;

    private const string CallerKey = "matidentity:scim-caller";

    public static void MapScimEndpoints(this WebApplication app)
    {
        var scim = app.MapGroup("/scim/v2").AllowAnonymous().DisableAntiforgery().AddEndpointFilter(RequireAsync);

        scim.MapGet("/ServiceProviderConfig", () => Json(ServiceProviderConfig()));
        scim.MapGet("/ResourceTypes", () => Json(List([ResourceType("User", "/Users", UserSchema, UserAccessSchema), ResourceType("Group", "/Groups", GroupSchema, GroupAccessSchema)], 1, 2)));
        scim.MapGet("/Schemas", () => Json(List([.. Schemas()], 1, 4)));

        scim.MapGet("/Users", ListUsersAsync);
        scim.MapGet("/Users/{id}", GetUserAsync);
        scim.MapPost("/Users", CreateUserAsync);
        scim.MapPut("/Users/{id}", ReplaceUserAsync);
        scim.MapPatch("/Users/{id}", PatchUserAsync);
        scim.MapDelete("/Users/{id}", DeleteUserAsync);

        scim.MapGet("/Groups", ListGroupsAsync);
        scim.MapGet("/Groups/{id}", GetGroupAsync);
        scim.MapPost("/Groups", CreateGroupAsync);
        scim.MapPut("/Groups/{id}", ReplaceGroupAsync);
        scim.MapPatch("/Groups/{id}", PatchGroupAsync);
        scim.MapDelete("/Groups/{id}", DeleteGroupAsync);
    }

    // ---- access ----------------------------------------------------------------------------------------------------------------------

    private static async ValueTask<object?> RequireAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        var http = context.HttpContext;
        var caller = await CallerAsync(http);
        if (caller is null)
        {
            http.Response.Headers.WWWAuthenticate = "Bearer";
            return Error(StatusCodes.Status401Unauthorized, "MatIdentity's key (X-Api-Key or bearer) or the key of a binding of people.scim is required.");
        }

        if (!caller.Full && !HttpMethods.IsGet(http.Request.Method))
        {
            return Error(StatusCodes.Status403Forbidden, "The key of people.scim only reads.");
        }

        http.Items[CallerKey] = caller;
        return await next(context);
    }

    private static async Task<ScimCaller?> CallerAsync(HttpContext http)
    {
        var access = http.RequestServices.GetRequiredService<ApiAccess>();
        var header = http.Request.Headers.Authorization.ToString();
        var bearer = header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase) ? header[7..].Trim() : null;
        string? name = null;
        if (access.IsKey(bearer) || (bearer is null && await access.AuthenticateAsync(http) is not null)
            || (bearer is not null && await ApiAccess.TokenAsync(http) is not null))
        {
            name = "scim";
            if (http.Request.Headers[ActorHeader].ToString() is { Length: > 0 } actor
                && await http.RequestServices.GetRequiredService<UserService>().GetBySubjectAsync(actor.Trim(), http.RequestAborted) is { } person)
            {
                name = person.Username;
            }

            return new ScimCaller(true, null, name);
        }

        // The key of a binding of people.scim: the consumer reads its own people.
        if (bearer is not null && await http.RequestServices.GetRequiredService<MatBindingStore>().AuthenticateAsync(MatPeople.Capability, bearer, http.RequestAborted) is { } binding)
        {
            return new ScimCaller(false, IdentityBindings.ClientIdOf(binding.Consumer), "scim:" + binding.Consumer);
        }

        return null;
    }

    private static ScimCaller Caller(HttpContext http) => (ScimCaller)http.Items[CallerKey]!;

    // ---- users -----------------------------------------------------------------------------------------------------------------------

    private static async Task<IResult> ListUsersAsync(HttpContext http, UserService users, GroupService groups, PermissionService permissions)
    {
        var ct = http.RequestAborted;
        var caller = Caller(http);
        if (FilterOf(http) is { Error: { } bad })
        {
            return Error(StatusCodes.Status400BadRequest, bad, "invalidFilter");
        }

        var filter = FilterOf(http);
        var all = await VisibleUsersAsync(caller, users, permissions, ct);
        var matching = all.Where(u => filter.Attribute is null || MatchesUser(u, filter.Attribute, filter.Value!)).OrderBy(u => u.Username, StringComparer.OrdinalIgnoreCase).ToList();
        var (start, count) = Paging(http);
        var page = matching.Skip(start - 1).Take(count).ToList();
        var resources = new List<JsonNode>();
        foreach (var user in page)
        {
            resources.Add(await UserResourceAsync(http, user, caller, groups, permissions, ct));
        }

        return Json(List(resources, start, matching.Count));
    }

    private static async Task<IResult> GetUserAsync(string id, HttpContext http, UserService users, GroupService groups, PermissionService permissions)
    {
        var caller = Caller(http);
        var user = await FindUserAsync(id, caller, users, permissions, http.RequestAborted);
        return user is null ? NotFound("User", id) : Json(await UserResourceAsync(http, user, caller, groups, permissions, http.RequestAborted));
    }

    private static async Task<IResult> CreateUserAsync(HttpContext http, UserService users, GroupService groups, PermissionService permissions, ScimPeople people)
    {
        var ct = http.RequestAborted;
        if (await ReadAsync(http) is not { } body)
        {
            return Error(StatusCodes.Status400BadRequest, "The body is not a JSON object.", "invalidSyntax");
        }

        var input = UserInput.From(body);
        if (input.UserName is null)
        {
            return Error(StatusCodes.Status400BadRequest, "userName is required.", "invalidValue");
        }

        if (await users.UsernameExistsAsync(input.UserName, null, ct))
        {
            return Error(StatusCodes.Status409Conflict, $"The user name \"{input.UserName}\" is taken.", "uniqueness");
        }

        if (input.Email is { } email && await users.EmailExistsAsync(email, null, ct))
        {
            return Error(StatusCodes.Status409Conflict, $"The e-mail address \"{email}\" is taken.", "uniqueness");
        }

        if (await people.CheckPasswordAsync(input.Password, input.UserName, input.Email, ct) is { } weak)
        {
            return Error(StatusCodes.Status400BadRequest, weak, "invalidValue");
        }

        if (input.Grants is { } grants && await permissions.CheckGrantsAsync(grants, ct) is { Count: > 0 } errors)
        {
            return Error(StatusCodes.Status400BadRequest, errors.First().Key + ": " + errors.First().Value, "invalidValue");
        }

        var user = await people.CreateAsync(http, input, Caller(http).Name, ct);
        http.Response.Headers.Location = await LocationAsync(http, "Users", user.Subject);
        return Json(await UserResourceAsync(http, user, Caller(http), groups, permissions, ct), StatusCodes.Status201Created);
    }

    private static async Task<IResult> ReplaceUserAsync(string id, HttpContext http, UserService users, GroupService groups, PermissionService permissions, ScimPeople people)
    {
        var ct = http.RequestAborted;
        if (await users.GetBySubjectAsync(id, ct) is not { } user)
        {
            return NotFound("User", id);
        }

        if (await ReadAsync(http) is not { } body)
        {
            return Error(StatusCodes.Status400BadRequest, "The body is not a JSON object.", "invalidSyntax");
        }

        var input = UserInput.From(body);
        if (input.UserName is null)
        {
            return Error(StatusCodes.Status400BadRequest, "userName is required.", "invalidValue");
        }

        return await SaveUserAsync(http, user, input, users, groups, permissions, people);
    }

    private static async Task<IResult> PatchUserAsync(string id, HttpContext http, UserService users, GroupService groups, PermissionService permissions, ScimPeople people)
    {
        var ct = http.RequestAborted;
        if (await users.GetBySubjectAsync(id, ct) is not { } user)
        {
            return NotFound("User", id);
        }

        if (await ReadAsync(http) is not { } body || body["Operations"] is not JsonArray operations)
        {
            return Error(StatusCodes.Status400BadRequest, "A PatchOp with Operations is required.", "invalidSyntax");
        }

        // The writable state as a resource, the operations applied to it, then saved like a PUT.
        var current = await UserResourceAsync(http, user, Caller(http), groups, permissions, ct, writableOnly: true);
        if (ApplyPatch(current, operations, UserAccessSchema) is { } problem)
        {
            return Error(StatusCodes.Status400BadRequest, problem, "invalidPath");
        }

        return await SaveUserAsync(http, user, UserInput.From(current), users, groups, permissions, people);
    }

    private static async Task<IResult> SaveUserAsync(HttpContext http, User user, UserInput input, UserService users, GroupService groups, PermissionService permissions, ScimPeople people)
    {
        var ct = http.RequestAborted;
        if (input.UserName is { } name && !string.Equals(name, user.Username, StringComparison.Ordinal) && await users.UsernameExistsAsync(name, user.Id, ct))
        {
            return Error(StatusCodes.Status409Conflict, $"The user name \"{name}\" is taken.", "uniqueness");
        }

        if (input.Email is { } email && await users.EmailExistsAsync(email, user.Id, ct))
        {
            return Error(StatusCodes.Status409Conflict, $"The e-mail address \"{email}\" is taken.", "uniqueness");
        }

        if (await people.CheckPasswordAsync(input.Password, input.UserName ?? user.Username, input.Email, ct) is { } weak)
        {
            return Error(StatusCodes.Status400BadRequest, weak, "invalidValue");
        }

        if (input.Grants is { } grants && await permissions.CheckGrantsAsync(grants, ct) is { Count: > 0 } errors)
        {
            return Error(StatusCodes.Status400BadRequest, errors.First().Key + ": " + errors.First().Value, "invalidValue");
        }

        if (await people.LastAdministratorAsync(user, input.Active ?? user.IsActive, input.Administrator ?? user.Role == UserRole.Admin, ct))
        {
            return Error(StatusCodes.Status400BadRequest, "The last active administrator stays an active administrator.", "mutability");
        }

        await people.UpdateAsync(user, input, Caller(http).Name, ct);
        var saved = await users.GetAsync(user.Id, ct);
        return Json(await UserResourceAsync(http, saved!, Caller(http), groups, permissions, ct));
    }

    private static async Task<IResult> DeleteUserAsync(string id, HttpContext http, UserService users, ScimPeople people)
    {
        var ct = http.RequestAborted;
        if (await users.GetBySubjectAsync(id, ct) is not { } user)
        {
            return NotFound("User", id);
        }

        if (await people.LastAdministratorAsync(user, active: false, administrator: false, ct))
        {
            return Error(StatusCodes.Status400BadRequest, "The last active administrator cannot be deleted.", "mutability");
        }

        await people.DeleteAsync(user, Caller(http).Name, ct);
        return Results.NoContent();
    }

    // ---- groups ----------------------------------------------------------------------------------------------------------------------

    private static async Task<IResult> ListGroupsAsync(HttpContext http, UserService users, GroupService groups, PermissionService permissions)
    {
        var ct = http.RequestAborted;
        var caller = Caller(http);
        var filter = FilterOf(http);
        if (filter.Error is { } bad)
        {
            return Error(StatusCodes.Status400BadRequest, bad, "invalidFilter");
        }

        var visible = (await VisibleUsersAsync(caller, users, permissions, ct)).ToDictionary(u => u.Id);
        var all = await groups.ListAsync(ct);
        var withMembers = new List<(Group Group, List<long> Members)>();
        foreach (var group in all.Where(g => filter.Attribute is null || MatchesGroup(g, filter.Attribute, filter.Value!)))
        {
            var members = (await groups.MemberIdsAsync(group.Id, ct)).Where(visible.ContainsKey).ToList();
            // An app sees a group only through its own people.
            if (caller.Full || members.Count > 0)
            {
                withMembers.Add((group, members));
            }
        }

        var (start, count) = Paging(http);
        var excludeMembers = http.Request.Query["excludedAttributes"].ToString().Contains("members", StringComparison.OrdinalIgnoreCase);
        var resources = new List<JsonNode>();
        foreach (var (group, members) in withMembers.Skip(start - 1).Take(count))
        {
            resources.Add(await GroupResourceAsync(http, group, excludeMembers ? [] : [.. members.Select(m => visible[m])], caller, permissions, ct));
        }

        return Json(List(resources, start, withMembers.Count));
    }

    private static async Task<IResult> GetGroupAsync(string id, HttpContext http, UserService users, GroupService groups, PermissionService permissions)
    {
        var ct = http.RequestAborted;
        var caller = Caller(http);
        if (!long.TryParse(id, NumberStyles.None, CultureInfo.InvariantCulture, out var groupId) || await groups.GetAsync(groupId, ct) is not { } group)
        {
            return NotFound("Group", id);
        }

        var visible = (await VisibleUsersAsync(caller, users, permissions, ct)).ToDictionary(u => u.Id);
        var members = (await groups.MemberIdsAsync(group.Id, ct)).Where(visible.ContainsKey).Select(m => visible[m]).ToList();
        if (!caller.Full && members.Count == 0)
        {
            return NotFound("Group", id);
        }

        return Json(await GroupResourceAsync(http, group, members, caller, permissions, ct));
    }

    private static async Task<IResult> CreateGroupAsync(HttpContext http, UserService users, GroupService groups, PermissionService permissions, ActivityService activity)
    {
        var ct = http.RequestAborted;
        if (await ReadAsync(http) is not { } body)
        {
            return Error(StatusCodes.Status400BadRequest, "The body is not a JSON object.", "invalidSyntax");
        }

        var input = GroupInput.From(body);
        if (input.Name is null || input.Name.Length > 100)
        {
            return Error(StatusCodes.Status400BadRequest, "displayName is required (up to 100 characters).", "invalidValue");
        }

        if (await groups.NameExistsAsync(input.Name, null, ct))
        {
            return Error(StatusCodes.Status409Conflict, $"The group \"{input.Name}\" exists.", "uniqueness");
        }

        if (await MemberIdsAsync(input.Members ?? [], users, ct) is not { } memberIds)
        {
            return Error(StatusCodes.Status400BadRequest, "A member is not a known user.", "invalidValue");
        }

        if (input.Grants is { } grants && await permissions.CheckGrantsAsync(grants, ct) is { Count: > 0 } errors)
        {
            return Error(StatusCodes.Status400BadRequest, errors.First().Key + ": " + errors.First().Value, "invalidValue");
        }

        var group = await groups.SaveAsync(null, input.Name, null, memberIds, ct);
        await groups.SetExternalIdAsync(group.Id, input.ExternalId, ct);
        if (input.Grants is { } given)
        {
            await permissions.ReplaceGrantsAsync(null, group.Id, given, ct);
        }

        await activity.WriteAsync(ActivityKind.GroupSaved, username: Caller(http).Name, ipAddress: http.Connection.RemoteIpAddress?.ToString(), detail: group.Name + " (SCIM)", ct: ct);
        http.Response.Headers.Location = await LocationAsync(http, "Groups", group.Id.ToString(CultureInfo.InvariantCulture));
        var members = await MembersAsync(group.Id, groups, users, ct);
        return Json(await GroupResourceAsync(http, (await groups.GetAsync(group.Id, ct))!, members, Caller(http), permissions, ct), StatusCodes.Status201Created);
    }

    private static async Task<IResult> ReplaceGroupAsync(string id, HttpContext http, UserService users, GroupService groups, PermissionService permissions, ActivityService activity)
    {
        if (!long.TryParse(id, NumberStyles.None, CultureInfo.InvariantCulture, out var groupId) || await groups.GetAsync(groupId, http.RequestAborted) is not { } group)
        {
            return NotFound("Group", id);
        }

        if (await ReadAsync(http) is not { } body)
        {
            return Error(StatusCodes.Status400BadRequest, "The body is not a JSON object.", "invalidSyntax");
        }

        return await SaveGroupAsync(http, group, GroupInput.From(body), users, groups, permissions, activity);
    }

    private static async Task<IResult> PatchGroupAsync(string id, HttpContext http, UserService users, GroupService groups, PermissionService permissions, ActivityService activity)
    {
        var ct = http.RequestAborted;
        if (!long.TryParse(id, NumberStyles.None, CultureInfo.InvariantCulture, out var groupId) || await groups.GetAsync(groupId, ct) is not { } group)
        {
            return NotFound("Group", id);
        }

        if (await ReadAsync(http) is not { } body || body["Operations"] is not JsonArray operations)
        {
            return Error(StatusCodes.Status400BadRequest, "A PatchOp with Operations is required.", "invalidSyntax");
        }

        var current = await GroupResourceAsync(http, group, await MembersAsync(group.Id, groups, users, ct), Caller(http), permissions, ct);
        if (ApplyPatch(current, operations, GroupAccessSchema) is { } problem)
        {
            return Error(StatusCodes.Status400BadRequest, problem, "invalidPath");
        }

        return await SaveGroupAsync(http, group, GroupInput.From(current), users, groups, permissions, activity);
    }

    private static async Task<IResult> SaveGroupAsync(HttpContext http, Group group, GroupInput input, UserService users, GroupService groups, PermissionService permissions, ActivityService activity)
    {
        var ct = http.RequestAborted;
        var name = input.Name ?? group.Name;
        if (name.Length > 100)
        {
            return Error(StatusCodes.Status400BadRequest, "displayName has up to 100 characters.", "invalidValue");
        }

        if (!string.Equals(name, group.Name, StringComparison.Ordinal) && await groups.NameExistsAsync(name, group.Id, ct))
        {
            return Error(StatusCodes.Status409Conflict, $"The group \"{name}\" exists.", "uniqueness");
        }

        var memberIds = input.Members is null ? await groups.MemberIdsAsync(group.Id, ct) : await MemberIdsAsync(input.Members, users, ct);
        if (memberIds is null)
        {
            return Error(StatusCodes.Status400BadRequest, "A member is not a known user.", "invalidValue");
        }

        if (input.Grants is { } grants && await permissions.CheckGrantsAsync(grants, ct) is { Count: > 0 } errors)
        {
            return Error(StatusCodes.Status400BadRequest, errors.First().Key + ": " + errors.First().Value, "invalidValue");
        }

        await groups.SaveAsync(group.Id, name, group.Description, memberIds, ct);
        await groups.SetExternalIdAsync(group.Id, input.ExternalId, ct);
        if (input.Grants is { } given)
        {
            await permissions.ReplaceGrantsAsync(null, group.Id, given, ct);
        }

        await activity.WriteAsync(ActivityKind.GroupSaved, username: Caller(http).Name, ipAddress: http.Connection.RemoteIpAddress?.ToString(), detail: name + " (SCIM)", ct: ct);
        var saved = (await groups.GetAsync(group.Id, ct))!;
        return Json(await GroupResourceAsync(http, saved, await MembersAsync(group.Id, groups, users, ct), Caller(http), permissions, ct));
    }

    private static async Task<IResult> DeleteGroupAsync(string id, HttpContext http, GroupService groups, ActivityService activity)
    {
        var ct = http.RequestAborted;
        if (!long.TryParse(id, NumberStyles.None, CultureInfo.InvariantCulture, out var groupId) || await groups.GetAsync(groupId, ct) is not { } group)
        {
            return NotFound("Group", id);
        }

        await groups.DeleteAsync(group.Id, ct);
        await activity.WriteAsync(ActivityKind.GroupDeleted, username: Caller(http).Name, ipAddress: http.Connection.RemoteIpAddress?.ToString(), detail: group.Name + " (SCIM)", ct: ct);
        return Results.NoContent();
    }

    // ---- resources -------------------------------------------------------------------------------------------------------------------

    /// <summary>The people the caller may see: everyone with the key, else the people who may use the caller's app.</summary>
    private static async Task<List<User>> VisibleUsersAsync(ScimCaller caller, UserService users, PermissionService permissions, CancellationToken ct)
    {
        var all = await users.GetAllAsync(ct);
        if (caller.Full)
        {
            return all;
        }

        var decisions = await permissions.AccessToAsync(caller.ClientId!, all, ct);
        return [.. all.Where(u => decisions[u.Id].Allowed)];
    }

    private static async Task<User?> FindUserAsync(string id, ScimCaller caller, UserService users, PermissionService permissions, CancellationToken ct)
    {
        var user = await users.GetBySubjectAsync(id, ct);
        if (user is null || caller.Full)
        {
            return user;
        }

        return (await permissions.DecideAsync(user, caller.ClientId!, ct)).Allowed ? user : null;
    }

    private static async Task<JsonObject> UserResourceAsync(HttpContext http, User user, ScimCaller caller, GroupService groups, PermissionService permissions, CancellationToken ct, bool writableOnly = false)
    {
        var resource = new JsonObject
        {
            ["schemas"] = new JsonArray(UserSchema, UserAccessSchema),
            ["id"] = user.Subject,
            ["userName"] = user.Username,
            ["displayName"] = user.DisplayName,
            ["name"] = new JsonObject { ["formatted"] = user.DisplayName },
            ["active"] = user.IsActive,
        };
        if (user.ExternalId is { } externalId && caller.Full)
        {
            resource["externalId"] = externalId;
        }

        if (!string.IsNullOrEmpty(user.Email))
        {
            resource["emails"] = new JsonArray(new JsonObject { ["value"] = user.Email, ["type"] = "work", ["primary"] = true });
        }

        var clients = caller.Full ? await permissions.ClientIdsAsync(ct) : [caller.ClientId!];
        var access = await permissions.AccessOfAsync(user, clients, ct);
        var extension = new JsonObject();
        if (caller.Full)
        {
            extension["administrator"] = user.Role == UserRole.Admin;
            extension["grants"] = Grants(await permissions.GrantsOfAsync(user.Id, null, ct));
        }

        if (!writableOnly)
        {
            var groupIds = (await groups.GroupIdsOfAsync(user.Id, ct)).ToHashSet();
            resource["groups"] = new JsonArray([.. (await groups.ListAsync(ct)).Where(g => groupIds.Contains(g.Id)).Select(g => (JsonNode)new JsonObject
            {
                ["value"] = g.Id.ToString(CultureInfo.InvariantCulture),
                ["display"] = g.Name,
                ["type"] = "direct",
            })]);
            resource["roles"] = new JsonArray([.. access.Where(a => a.Decision.Role is not null).Select(a => (JsonNode)new JsonObject { ["value"] = a.Decision.Role, ["type"] = a.ClientId })]);
            resource["entitlements"] = new JsonArray([.. access.SelectMany(a => a.Decision.Permissions.Select(p => (JsonNode)new JsonObject { ["value"] = p, ["type"] = a.ClientId }))]);
            extension["access"] = new JsonArray([.. access.Select(a => (JsonNode)AccessEntry(a.ClientId, a.Decision))]);
            resource["meta"] = await MetaAsync(http, "User", "Users", user.Subject, user.CreateDate, user.UpdateDate);
        }

        resource[UserAccessSchema] = extension;
        return resource;
    }

    private static async Task<JsonObject> GroupResourceAsync(HttpContext http, Group group, IReadOnlyList<User> members, ScimCaller caller, PermissionService permissions, CancellationToken ct)
    {
        var id = group.Id.ToString(CultureInfo.InvariantCulture);
        var resource = new JsonObject
        {
            ["schemas"] = new JsonArray(GroupSchema, GroupAccessSchema),
            ["id"] = id,
            ["displayName"] = group.Name,
            ["members"] = new JsonArray([.. members.Select(m => (JsonNode)new JsonObject { ["value"] = m.Subject, ["display"] = m.DisplayName, ["type"] = "User" })]),
            ["meta"] = await MetaAsync(http, "Group", "Groups", id, group.CreateDate, group.UpdateDate),
        };
        if (caller.Full)
        {
            if (group.ExternalId is { } externalId)
            {
                resource["externalId"] = externalId;
            }

            resource[GroupAccessSchema] = new JsonObject { ["grants"] = Grants(await permissions.GrantsOfAsync(null, group.Id, ct)) };
        }

        return resource;
    }

    private static JsonArray Grants(IEnumerable<AppGrant> grants)
        => new([.. grants.OrderBy(g => g.ClientId, StringComparer.Ordinal).Select(g =>
        {
            var values = GrantValues.Of(g);
            var entry = new JsonObject { ["app"] = g.ClientId, ["role"] = g.RoleKey, ["permissions"] = new JsonArray([.. values.Permissions.Select(p => (JsonNode)p)]) };
            entry["quotas"] = Quotas(values.Quotas);
            return (JsonNode)entry;
        })]);

    private static JsonObject AccessEntry(string clientId, AccessDecision decision) => new()
    {
        ["app"] = clientId,
        ["role"] = decision.Role,
        ["permissions"] = new JsonArray([.. decision.Permissions.Select(p => (JsonNode)p)]),
        ["quotas"] = Quotas(decision.Quotas),
        ["via"] = new JsonArray([.. decision.Via.Select(v => (JsonNode)v)]),
    };

    private static JsonObject Quotas(IReadOnlyDictionary<string, long?> quotas)
    {
        var result = new JsonObject();
        foreach (var (key, value) in quotas.OrderBy(q => q.Key, StringComparer.Ordinal))
        {
            result[key] = value is { } number ? JsonValue.Create(number) : null;
        }

        return result;
    }

    private static async Task<JsonObject> MetaAsync(HttpContext http, string type, string path, string id, DateTime created, DateTime modified) => new()
    {
        ["resourceType"] = type,
        ["created"] = Utc(created),
        ["lastModified"] = Utc(modified == default ? created : modified),
        ["location"] = await LocationAsync(http, path, id),
    };

    private static string Utc(DateTime time) => DateTime.SpecifyKind(time, DateTimeKind.Utc).ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture);

    private static async Task<string> LocationAsync(HttpContext http, string path, string id)
    {
        var config = http.RequestServices.GetRequiredService<SystemConfigService>();
        var configuration = http.RequestServices.GetRequiredService<IConfiguration>();
        return (await Support.Authority.GetAsync(http, config, configuration)).TrimEnd('/') + "/scim/v2/" + path + "/" + Uri.EscapeDataString(id);
    }

    private static async Task<List<User>> MembersAsync(long groupId, GroupService groups, UserService users, CancellationToken ct)
    {
        var ids = (await groups.MemberIdsAsync(groupId, ct)).ToHashSet();
        return [.. (await users.GetAllAsync(ct)).Where(u => ids.Contains(u.Id)).OrderBy(u => u.Username, StringComparer.OrdinalIgnoreCase)];
    }

    /// <summary>The ids of the people named by their subjects; null when one is not known.</summary>
    private static async Task<List<long>?> MemberIdsAsync(IReadOnlyList<string> subjects, UserService users, CancellationToken ct)
    {
        var ids = new List<long>();
        foreach (var subject in subjects.Distinct(StringComparer.Ordinal))
        {
            if (await users.GetBySubjectAsync(subject, ct) is not { } user)
            {
                return null;
            }

            ids.Add(user.Id);
        }

        return ids;
    }

    // ---- filters, paging, patches ------------------------------------------------------------------------------------------------------

    private sealed record ScimFilter(string? Attribute, string? Value, string? Error);

    /// <summary><c>attribute eq "value"</c>, the only filter there is; an attribute in small letters.</summary>
    private static ScimFilter FilterOf(HttpContext http)
    {
        var text = http.Request.Query["filter"].ToString();
        if (string.IsNullOrWhiteSpace(text))
        {
            return new ScimFilter(null, null, null);
        }

        var match = FilterRegex().Match(text);
        return match.Success
            ? new ScimFilter(match.Groups["attr"].Value.ToLowerInvariant(), match.Groups["value"].Value.Replace("\\\"", "\"", StringComparison.Ordinal).Replace("\\\\", "\\", StringComparison.Ordinal), null)
            : new ScimFilter(null, null, "Only filters of the form attribute eq \"value\" are supported.");
    }

    private static bool MatchesUser(User user, string attribute, string value) => attribute switch
    {
        "username" => string.Equals(user.Username, value, StringComparison.OrdinalIgnoreCase),
        "emails.value" or "emails" or "email" => string.Equals(user.Email, value, StringComparison.OrdinalIgnoreCase),
        "externalid" => string.Equals(user.ExternalId, value, StringComparison.Ordinal),
        "id" => string.Equals(user.Subject, value, StringComparison.Ordinal),
        "displayname" => string.Equals(user.DisplayName, value, StringComparison.OrdinalIgnoreCase),
        _ => false,
    };

    private static bool MatchesGroup(Group group, string attribute, string value) => attribute switch
    {
        "displayname" => string.Equals(group.Name, value, StringComparison.OrdinalIgnoreCase),
        "externalid" => string.Equals(group.ExternalId, value, StringComparison.Ordinal),
        "id" => string.Equals(group.Id.ToString(CultureInfo.InvariantCulture), value, StringComparison.Ordinal),
        _ => false,
    };

    private static (int Start, int Count) Paging(HttpContext http)
    {
        var start = int.TryParse(http.Request.Query["startIndex"], NumberStyles.Integer, CultureInfo.InvariantCulture, out var s) && s > 1 ? s : 1;
        var count = int.TryParse(http.Request.Query["count"], NumberStyles.Integer, CultureInfo.InvariantCulture, out var c) ? Math.Clamp(c, 0, MaxCount) : 100;
        return (start, count);
    }

    /// <summary>
    /// Applies the operations of a PatchOp to <paramref name="resource"/> (what can be written of it): <c>add</c>, <c>replace</c> and <c>remove</c> on a top attribute,
    /// <c>name.formatted</c>, the e-mail (<c>emails</c>, <c>emails[...].value</c>), the members (<c>members</c>, <c>members[value eq "..."]</c>) and the attributes of
    /// the extension (<c>urn:...:grants</c>). An operation without a path merges its object. Returns a problem for a person, or null.
    /// </summary>
    internal static string? ApplyPatch(JsonObject resource, JsonArray operations, string extension)
    {
        foreach (var operation in operations.OfType<JsonObject>())
        {
            var op = (Text(operation, "op") ?? string.Empty).ToLowerInvariant();
            var path = Text(operation, "path");
            var value = operation["value"]?.DeepClone();
            if (op is not ("add" or "replace" or "remove"))
            {
                return $"The operation \"{op}\" is not add, replace or remove.";
            }

            if (path is null)
            {
                if (op == "remove" || value is not JsonObject merge)
                {
                    return "An operation without a path needs an object as its value.";
                }

                foreach (var (key, item) in merge.ToList())
                {
                    if (SetPath(resource, key, item?.DeepClone(), op, extension) is { } problem)
                    {
                        return problem;
                    }
                }

                continue;
            }

            if (SetPath(resource, path, op == "remove" ? null : value, op, extension) is { } failed)
            {
                return failed;
            }
        }

        return null;
    }

    private static string? SetPath(JsonObject resource, string path, JsonNode? value, string op, string extension)
    {
        var lower = path.ToLowerInvariant();
        // The attributes of the extension: "urn:...:User:grants", or the extension as an object.
        if (lower.StartsWith(extension.ToLowerInvariant(), StringComparison.Ordinal))
        {
            var rest = path[extension.Length..].TrimStart(':');
            var target = resource[extension] as JsonObject ?? new JsonObject();
            resource[extension] = target;
            if (rest.Length == 0)
            {
                if (value is JsonObject all)
                {
                    foreach (var (key, item) in all.ToList())
                    {
                        target[key] = item?.DeepClone();
                    }
                }

                return null;
            }

            target[rest] = op == "remove" && rest.Equals("grants", StringComparison.OrdinalIgnoreCase) ? new JsonArray() : value;
            return null;
        }

        var member = MemberPathRegex().Match(path);
        if (member.Success && resource["members"] is JsonArray current)
        {
            var subject = member.Groups["value"].Value;
            foreach (var item in current.OfType<JsonObject>().Where(m => Text(m, "value") == subject).ToList())
            {
                current.Remove(item);
            }

            return op == "remove" ? null : "Only remove works on one member.";
        }

        switch (lower)
        {
            case "members":
                var members = resource["members"] as JsonArray ?? new JsonArray();
                resource["members"] = members;
                if (op == "replace")
                {
                    members.Clear();
                }

                var given = value switch
                {
                    JsonArray array => array.OfType<JsonObject>().Select(m => Text(m, "value")).OfType<string>().ToList(),
                    JsonObject single => [.. new[] { Text(single, "value") }.OfType<string>()],
                    _ => [],
                };
                if (op == "remove")
                {
                    if (value is null)
                    {
                        members.Clear();
                    }
                    else
                    {
                        foreach (var item in members.OfType<JsonObject>().Where(m => given.Contains(Text(m, "value") ?? string.Empty)).ToList())
                        {
                            members.Remove(item);
                        }
                    }
                }
                else
                {
                    foreach (var subject in given.Where(s => members.OfType<JsonObject>().All(m => Text(m, "value") != s)))
                    {
                        members.Add(new JsonObject { ["value"] = subject });
                    }
                }

                return null;

            case "emails" or "email":
                resource["emails"] = op == "remove" ? null : value is JsonArray ? value : new JsonArray(new JsonObject { ["value"] = value?.DeepClone(), ["primary"] = true });
                return null;

            case "name.formatted":
                resource["displayName"] = value;
                return null;

            case "name":
                if (value is JsonObject name && (Text(name, "formatted") ?? JoinName(name)) is { } formatted)
                {
                    resource["displayName"] = formatted;
                }

                return null;

            case "username" or "displayname" or "active" or "externalid" or "password":
                var key = lower switch { "username" => "userName", "displayname" => "displayName", "externalid" => "externalId", _ => lower };
                resource[key] = value;
                return null;

            default:
                if (lower.StartsWith("emails[", StringComparison.Ordinal) && lower.EndsWith("].value", StringComparison.Ordinal))
                {
                    resource["emails"] = op == "remove" || value is null ? null : new JsonArray(new JsonObject { ["value"] = value.DeepClone(), ["primary"] = true });
                    return null;
                }

                if (lower.StartsWith("name.", StringComparison.Ordinal))
                {
                    // givenName and familyName: MatIdentity keeps one name, the display name.
                    return null;
                }

                return $"The path \"{path}\" cannot be changed here.";
        }
    }

    private static string? JoinName(JsonObject name)
    {
        var joined = string.Join(' ', new[] { Text(name, "givenName"), Text(name, "familyName") }.Where(p => !string.IsNullOrWhiteSpace(p)));
        return joined.Length == 0 ? null : joined;
    }

    // ---- reading ---------------------------------------------------------------------------------------------------------------------

    /// <summary>The body as a JSON object (attribute names as they came; SCIM compares them without case: <see cref="Get"/>).</summary>
    private static async Task<JsonObject?> ReadAsync(HttpContext http)
    {
        try
        {
            return await JsonNode.ParseAsync(http.Request.Body, cancellationToken: http.RequestAborted) as JsonObject;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>An attribute by its name, without regard to case (RFC 7643 2.1).</summary>
    internal static JsonNode? Get(JsonObject? node, string name)
        => node?.FirstOrDefault(p => string.Equals(p.Key, name, StringComparison.OrdinalIgnoreCase)).Value;

    internal static string? Text(JsonObject? node, string name)
        => Get(node, name) is JsonValue value && value.TryGetValue<string>(out var text) && !string.IsNullOrWhiteSpace(text) ? text.Trim() : null;

    /// <summary>A boolean, also as the text "True"/"False" (some clients send it so).</summary>
    internal static bool? Bool(JsonNode? node)
        => node is JsonValue value
            ? value.TryGetValue<bool>(out var flag) ? flag : value.TryGetValue<string>(out var text) && bool.TryParse(text, out var parsed) ? parsed : null
            : null;

    /// <summary>The grants of the extension: <c>[{"app", "role", "permissions", "quotas"}]</c>; null when the extension does not name them.</summary>
    internal static IReadOnlyList<(string ClientId, string? Role, GrantValues Values)>? GrantsOf(JsonObject body, string extension)
    {
        if (Get(Get(body, extension) as JsonObject, "grants") is not JsonArray array)
        {
            return null;
        }

        var grants = new List<(string, string?, GrantValues)>();
        foreach (var entry in array.OfType<JsonObject>())
        {
            if (Text(entry, "app") is not { } app)
            {
                continue;
            }

            var permissions = Get(entry, "permissions") is JsonArray list
                ? list.OfType<JsonValue>().Select(v => v.TryGetValue<string>(out var p) ? p.Trim() : null).OfType<string>().Distinct(StringComparer.Ordinal).ToList()
                : [];
            var quotas = new Dictionary<string, long?>(StringComparer.Ordinal);
            if (Get(entry, "quotas") is JsonObject given)
            {
                foreach (var (key, value) in given)
                {
                    quotas[key] = value is JsonValue number && number.TryGetValue<long>(out var n) ? n
                        : value is JsonValue text && text.TryGetValue<string>(out var s) && long.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed) ? parsed
                        : null;
                }
            }

            grants.Add((app, Text(entry, "role"), new GrantValues(permissions, quotas)));
        }

        return grants;
    }

    // ---- answers ---------------------------------------------------------------------------------------------------------------------

    private static IResult Json(JsonNode node, int status = StatusCodes.Status200OK)
        => Results.Text(node.ToJsonString(), ContentType, System.Text.Encoding.UTF8, status);

    private static JsonObject List(IReadOnlyList<JsonNode> resources, int start, int total) => new()
    {
        ["schemas"] = new JsonArray(ListSchema),
        ["totalResults"] = total,
        ["startIndex"] = start,
        ["itemsPerPage"] = resources.Count,
        ["Resources"] = new JsonArray([.. resources]),
    };

    private static IResult Error(int status, string detail, string? scimType = null)
    {
        var error = new JsonObject { ["schemas"] = new JsonArray(ErrorSchema), ["status"] = status.ToString(CultureInfo.InvariantCulture), ["detail"] = detail };
        if (scimType is not null)
        {
            error["scimType"] = scimType;
        }

        return Json(error, status);
    }

    private static IResult NotFound(string type, string id) => Error(StatusCodes.Status404NotFound, $"There is no {type} \"{id}\".");

    private static JsonObject ServiceProviderConfig() => new()
    {
        ["schemas"] = new JsonArray("urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"),
        ["documentationUri"] = "https://github.com/Real-TTX/MatDesign/blob/main/docs/PLATFORM.md",
        ["patch"] = new JsonObject { ["supported"] = true },
        ["bulk"] = new JsonObject { ["supported"] = false, ["maxOperations"] = 0, ["maxPayloadSize"] = 0 },
        ["filter"] = new JsonObject { ["supported"] = true, ["maxResults"] = MaxCount },
        ["changePassword"] = new JsonObject { ["supported"] = true },
        ["sort"] = new JsonObject { ["supported"] = false },
        ["etag"] = new JsonObject { ["supported"] = false },
        ["authenticationSchemes"] = new JsonArray(new JsonObject
        {
            ["type"] = "oauthbearertoken",
            ["name"] = "Bearer",
            ["description"] = "MatIdentity's MAT_API_KEY (everything), or the key of a binding of people.scim (the people of one app, read only).",
        }),
    };

    private static JsonObject ResourceType(string name, string endpoint, string schema, string extension) => new()
    {
        ["schemas"] = new JsonArray("urn:ietf:params:scim:schemas:core:2.0:ResourceType"),
        ["id"] = name,
        ["name"] = name,
        ["endpoint"] = endpoint,
        ["schema"] = schema,
        ["schemaExtensions"] = new JsonArray(new JsonObject { ["schema"] = extension, ["required"] = false }),
    };

    private static IEnumerable<JsonNode> Schemas()
    {
        static JsonObject Attribute(string name, string type, bool multi = false, string mutability = "readWrite") => new()
        {
            ["name"] = name, ["type"] = type, ["multiValued"] = multi, ["required"] = name is "userName" or "displayName" && type == "string",
            ["mutability"] = mutability, ["returned"] = name == "password" ? "never" : "default",
        };

        static JsonObject Schema(string id, string name, params JsonObject[] attributes) => new()
        {
            ["schemas"] = new JsonArray("urn:ietf:params:scim:schemas:core:2.0:Schema"),
            ["id"] = id,
            ["name"] = name,
            ["attributes"] = new JsonArray([.. attributes]),
        };

        yield return Schema(UserSchema, "User", Attribute("userName", "string"), Attribute("displayName", "string"), Attribute("name", "complex"), Attribute("emails", "complex", true),
            Attribute("active", "boolean"), Attribute("password", "string", mutability: "writeOnly"), Attribute("externalId", "string"), Attribute("groups", "complex", true, "readOnly"),
            Attribute("roles", "complex", true, "readOnly"), Attribute("entitlements", "complex", true, "readOnly"));
        yield return Schema(GroupSchema, "Group", Attribute("displayName", "string"), Attribute("members", "complex", true), Attribute("externalId", "string"));
        yield return Schema(UserAccessSchema, "Access", Attribute("administrator", "boolean"), Attribute("grants", "complex", true), Attribute("access", "complex", true, "readOnly"));
        yield return Schema(GroupAccessSchema, "Access", Attribute("grants", "complex", true));
    }

    [GeneratedRegex(@"^\s*(?<attr>[A-Za-z][A-Za-z0-9_.]*)\s+eq\s+""(?<value>(?:[^""\\]|\\.)*)""\s*$", RegexOptions.IgnoreCase)]
    private static partial Regex FilterRegex();

    [GeneratedRegex(@"^members\[\s*value\s+eq\s+""(?<value>[^""]*)""\s*\]$", RegexOptions.IgnoreCase)]
    private static partial Regex MemberPathRegex();
}

/// <summary>What a SCIM client sends for a person (the attributes MatIdentity keeps).</summary>
public sealed record UserInput
{
    public string? UserName { get; init; }

    public string? DisplayName { get; init; }

    /// <summary>The primary (or first) e-mail; null removes it.</summary>
    public string? Email { get; init; }

    public bool? Active { get; init; }

    public string? Password { get; init; }

    public string? ExternalId { get; init; }

    public bool? Administrator { get; init; }

    /// <summary>The grants given to the person directly; null keeps them.</summary>
    public IReadOnlyList<(string ClientId, string? Role, GrantValues Values)>? Grants { get; init; }

    public static UserInput From(JsonObject body)
    {
        string? email = null;
        if (ScimEndpoints.Get(body, "emails") is JsonArray emails)
        {
            var all = emails.OfType<JsonObject>().ToList();
            email = ScimEndpoints.Text(all.FirstOrDefault(e => ScimEndpoints.Bool(ScimEndpoints.Get(e, "primary")) == true) ?? all.FirstOrDefault(), "value");
        }

        var name = ScimEndpoints.Get(body, "name") as JsonObject;
        var extension = ScimEndpoints.Get(body, ScimEndpoints.UserAccessSchema) as JsonObject;
        var joined = string.Join(' ', new[] { ScimEndpoints.Text(name, "givenName"), ScimEndpoints.Text(name, "familyName") }.OfType<string>());
        return new UserInput
        {
            UserName = ScimEndpoints.Text(body, "userName"),
            DisplayName = ScimEndpoints.Text(body, "displayName") ?? ScimEndpoints.Text(name, "formatted") ?? (joined.Length > 0 ? joined : null),
            Email = email,
            Active = ScimEndpoints.Bool(ScimEndpoints.Get(body, "active")),
            Password = ScimEndpoints.Get(body, "password") is JsonValue p && p.TryGetValue<string>(out var password) && password.Length > 0 ? password : null,
            ExternalId = ScimEndpoints.Text(body, "externalId"),
            Administrator = ScimEndpoints.Bool(ScimEndpoints.Get(extension, "administrator")),
            Grants = ScimEndpoints.GrantsOf(body, ScimEndpoints.UserAccessSchema),
        };
    }
}

/// <summary>What a SCIM client sends for a group.</summary>
public sealed record GroupInput
{
    public string? Name { get; init; }

    public string? ExternalId { get; init; }

    /// <summary>The subjects of the members; null keeps them.</summary>
    public IReadOnlyList<string>? Members { get; init; }

    public IReadOnlyList<(string ClientId, string? Role, GrantValues Values)>? Grants { get; init; }

    public static GroupInput From(JsonObject body) => new()
    {
        Name = ScimEndpoints.Text(body, "displayName"),
        ExternalId = ScimEndpoints.Text(body, "externalId"),
        Members = ScimEndpoints.Get(body, "members") is JsonArray members
            ? [.. members.OfType<JsonObject>().Select(m => ScimEndpoints.Text(m, "value")).OfType<string>()]
            : null,
        Grants = ScimEndpoints.GrantsOf(body, ScimEndpoints.GroupAccessSchema),
    };
}
