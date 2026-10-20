namespace MatIdentity.Core.Entities;

/// <summary>
/// What a person may do in MatIdentity. The role also travels to the apps as the claim <c>role</c> (<c>admin</c> or <c>user</c>),
/// so an app can make an administrator of MatIdentity an administrator of itself (docs/PLATFORM.md).
/// </summary>
public enum UserRole
{
    User = 1,
    Admin = 2
}

/// <summary>Soft-delete / audit state for every persisted record.</summary>
public enum UpdateState
{
    Deleted = 0,
    Created = 1,
    Updated = 2
}

/// <summary>What happened, for the activity list (sign-ins, tokens, sign-outs, changes to clients).</summary>
public enum ActivityKind
{
    SignIn = 0,
    SignInFailed = 1,
    SignOut = 2,

    /// <summary>An app received a token for a person (authorization code or refresh token).</summary>
    AppSignIn = 3,

    /// <summary>A machine (Mattiverse, another app) received a token with client credentials.</summary>
    MachineToken = 4,

    ClientCreated = 5,
    ClientChanged = 6,
    ClientDeleted = 7,
    ClientSecretRenewed = 8,

    /// <summary>A person tried to sign in to an app that was not given to them.</summary>
    AccessDenied = 9,

    /// <summary>A link to set a new password was sent ("Forgot your password?").</summary>
    PasswordResetSent = 10,

    /// <summary>A person set their password with a link (a reset or an invitation).</summary>
    PasswordSetByLink = 11,

    /// <summary>An administrator sent an invitation.</summary>
    InvitationSent = 12,

    /// <summary>A person confirmed their e-mail address.</summary>
    EmailVerified = 13
}
