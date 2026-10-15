namespace MatIdentity.Web.Infrastructure;

/// <summary>Names for the authentication scheme and the custom claims MatIdentity stores in the cookie.</summary>
public static class AuthConstants
{
    public const string CookieScheme = "MatIdentity";

    public const string SessionTokenClaim = "matidentity:session-token";
    public const string DisplayNameClaim = "matidentity:display-name";
    public const string MustChangePasswordClaim = "matidentity:must-change-password";
    public const string ThemeClaim = "matidentity:theme";
}
