using System.Security.Claims;
using MatIdentity.Core.Entities;

namespace MatIdentity.Web.Infrastructure;

/// <summary>Convenience accessors for the MatIdentity claims stored on the authenticated principal.</summary>
public static class ClaimsPrincipalExtensions
{
    public static long? GetUserId(this ClaimsPrincipal principal)
    {
        var value = principal.FindFirstValue(ClaimTypes.NameIdentifier);
        return long.TryParse(value, out var id) ? id : null;
    }

    public static string GetDisplayName(this ClaimsPrincipal principal)
        => principal.FindFirstValue(AuthConstants.DisplayNameClaim)
           ?? principal.Identity?.Name
           ?? "Unknown";

    public static string? GetUsername(this ClaimsPrincipal principal)
        => principal.Identity?.Name;

    public static string? GetSessionToken(this ClaimsPrincipal principal)
        => principal.FindFirstValue(AuthConstants.SessionTokenClaim);

    public static bool MustChangePassword(this ClaimsPrincipal principal)
        => string.Equals(principal.FindFirstValue(AuthConstants.MustChangePasswordClaim), "true", StringComparison.OrdinalIgnoreCase);

    public static UserRole GetRole(this ClaimsPrincipal principal)
        => Enum.TryParse<UserRole>(principal.FindFirstValue(ClaimTypes.Role), out var role) ? role : UserRole.User;

    public static string GetTheme(this ClaimsPrincipal principal)
        => principal.FindFirstValue(AuthConstants.ThemeClaim) ?? "system";

    public static bool IsAdmin(this ClaimsPrincipal principal)
        => principal.IsInRole(nameof(UserRole.Admin));
}
