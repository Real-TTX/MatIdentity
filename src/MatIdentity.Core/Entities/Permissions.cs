namespace MatIdentity.Core.Entities;

/// <summary>Who decides what a person may do inside an app.</summary>
public enum RoleMode
{
    /// <summary>MatIdentity: an administrator gives each person or group a role of the app here, and the token carries it (claim <c>role</c>).</summary>
    MatIdentity = 0,

    /// <summary>The app: MatIdentity only says who the person is and that they may come in; the app gives the rights itself (no claim <c>role</c>).</summary>
    App = 1
}

/// <summary>A group of people (Family, Guests, Work): access and roles in the apps can be given to a group instead of each person.</summary>
public class Group : AuditableEntity
{
    public string Name { get; set; } = string.Empty;

    public string? Description { get; set; }

    /// <summary>The id a SCIM client keeps for the group (<c>externalId</c>).</summary>
    public string? ExternalId { get; set; }

    public ICollection<GroupMember> Members { get; set; } = new List<GroupMember>();
}

/// <summary>A person in a group.</summary>
public class GroupMember : AuditableEntity
{
    public long GroupId { get; set; }

    public Group? Group { get; set; }

    public long UserId { get; set; }

    public User? User { get; set; }
}

/// <summary>
/// The rules of one app (by its client id): who decides the roles, whether everyone may sign in, and whether it may call every other app.
/// An app without a row has the defaults: roles by MatIdentity, only the people and groups it is given to (and administrators), calls no app.
/// </summary>
public class AppPolicy : AuditableEntity
{
    public string ClientId { get; set; } = string.Empty;

    public RoleMode RoleMode { get; set; } = RoleMode.MatIdentity;

    /// <summary>Every active person may sign in (with the default role), not only those it is given to.</summary>
    public bool OpenToEveryone { get; set; }

    /// <summary>The app may get a token for every app, also for those added later (Mattiverse). Else only for the apps in <see cref="AppCallGrant"/>.</summary>
    public bool CallsAllApps { get; set; }
}

/// <summary>A role of an app, as the app announces it in its MatApiDefinition or as an administrator writes it down. The order matters: the first is the most powerful.</summary>
public class AppRole : AuditableEntity
{
    public string ClientId { get; set; } = string.Empty;

    /// <summary>The value of the claim <c>role</c> (<c>admin</c>, <c>editor</c>).</summary>
    public string Key { get; set; } = string.Empty;

    public string Label { get; set; } = string.Empty;

    public int SortOrder { get; set; }
}

/// <summary>A person or a group may sign in to an app, with a role of the app (null: the default role, or none when the app decides).</summary>
public class AppGrant : AuditableEntity
{
    public string ClientId { get; set; } = string.Empty;

    /// <summary>Exactly one of <see cref="UserId"/> and <see cref="GroupId"/> is set.</summary>
    public long? UserId { get; set; }

    public User? User { get; set; }

    public long? GroupId { get; set; }

    public Group? Group { get; set; }

    public string? RoleKey { get; set; }

    /// <summary>The permissions of the app given with this grant (keys of <see cref="AppPermission"/>, separated by spaces); null or empty: none on top of the role.</summary>
    public string? Permissions { get; set; }

    /// <summary>The quotas set with this grant, a JSON object (<c>{"storage": 53687091200, "ai-tokens": null}</c>; null = no limit); null: none.</summary>
    public string? Quotas { get; set; }
}

/// <summary>A permission of an app (a right on top of a role), as the app announces it in its MatApiDefinition (<c>permissions</c>).</summary>
public class AppPermission : AuditableEntity
{
    public string ClientId { get; set; } = string.Empty;

    /// <summary>A value of the claim <c>entitlements</c>.</summary>
    public string Key { get; set; } = string.Empty;

    public string Label { get; set; } = string.Empty;

    public string? Hint { get; set; }

    /// <summary>The roles that have it without anyone giving it, separated by spaces.</summary>
    public string? Roles { get; set; }

    public int SortOrder { get; set; }
}

/// <summary>A quota of an app (a number per person), as the app announces it in its MatApiDefinition (<c>quotas</c>).</summary>
public class AppQuota : AuditableEntity
{
    public string ClientId { get; set; } = string.Empty;

    /// <summary>A key of the claim <c>mat_quotas</c>.</summary>
    public string Key { get; set; } = string.Empty;

    public string Label { get; set; } = string.Empty;

    /// <summary><c>bytes</c>, <c>count</c>, <c>tokens</c>, <c>minutes</c> or <c>requests</c>.</summary>
    public string Unit { get; set; } = string.Empty;

    /// <summary><c>day</c> or <c>month</c>; null: it does not renew.</summary>
    public string? Period { get; set; }

    public long? Min { get; set; }

    public long? Max { get; set; }

    public string? Hint { get; set; }

    public int SortOrder { get; set; }
}

/// <summary>An app may get a token to call another app's API (client credentials, scope <c>app:&lt;target&gt;</c>).</summary>
public class AppCallGrant : AuditableEntity
{
    public string CallerClientId { get; set; } = string.Empty;

    public string TargetClientId { get; set; } = string.Empty;
}
