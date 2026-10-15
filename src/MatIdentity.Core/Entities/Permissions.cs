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
}

/// <summary>An app may get a token to call another app's API (client credentials, scope <c>app:&lt;target&gt;</c>).</summary>
public class AppCallGrant : AuditableEntity
{
    public string CallerClientId { get; set; } = string.Empty;

    public string TargetClientId { get; set; } = string.Empty;
}
