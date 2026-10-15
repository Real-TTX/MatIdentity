namespace MatIdentity.Core.Configuration;

/// <summary>
/// What an administrator sets at runtime (<c>config/system.json</c>): the few settings that are also offered to Mattiverse through
/// <c>/api/configure</c> (docs/PLATFORM.md).
/// </summary>
public sealed class SystemConfig
{
    public const string FileName = "system";

    /// <summary>The name in the menu, the title of the pages and of the sign-in card.</summary>
    public string InstanceName { get; set; } = "MatIdentity";

    /// <summary>The public address (the <c>iss</c> of the tokens). Empty: <see cref="MatIdentityOptions.Issuer"/>, else the address of the request.</summary>
    public string? Issuer { get; set; }

    /// <summary>How long a sign-in at MatIdentity lasts without activity, in days (the single sign-on session).</summary>
    public int SessionLifetimeDays { get; set; } = 14;

    /// <summary>How long an access token is valid, in minutes. Short, because an app renews it with the refresh token.</summary>
    public int AccessTokenMinutes { get; set; } = 30;
}
