using System.Security.Cryptography;
using System.Text;
using MatIdentity.Core.Clients;
using MatIdentity.Core.Configuration;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using OpenIddict.Validation.AspNetCore;

namespace MatIdentity.Web.Infrastructure;

/// <summary>
/// Who may call the protected part of <c>/api</c> (docs/PLATFORM.md, "Access"): a caller with the key <c>MAT_API_KEY</c> in the header
/// <c>X-Api-Key</c> (compared in constant time; no key configured = the key is off), or a caller with a token of MatIdentity whose audience
/// is <c>matidentity</c> (an app or Mattiverse with client credentials and the scope <c>app:matidentity</c>).
/// </summary>
public sealed class ApiAccess
{
    public const string HeaderName = "X-Api-Key";

    private readonly byte[]? _key;

    public ApiAccess(IOptions<MatIdentityOptions> options)
    {
        var key = options.Value.ApiKey;
        _key = string.IsNullOrWhiteSpace(key) ? null : Encoding.UTF8.GetBytes(key.Trim());
    }

    public bool KeyEnabled => _key is not null;

    /// <summary>The name of the caller for the activity list and the audit columns, or null when it may not call.</summary>
    public async Task<string?> AuthenticateAsync(HttpContext http)
    {
        if (_key is not null && http.Request.Headers.TryGetValue(HeaderName, out var sent) && sent.Count == 1)
        {
            var given = Encoding.UTF8.GetBytes(sent.ToString());
            if (CryptographicOperations.FixedTimeEquals(given, _key))
            {
                return "api-key";
            }
        }

        if (http.Request.Headers.Authorization.ToString().StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            var result = await http.AuthenticateAsync(OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme);
            if (result.Succeeded && result.Principal.HasAudience(ClientRules.SelfId))
            {
                return result.Principal.GetClaim(OpenIddictConstants.Claims.Subject) ?? "token";
            }
        }

        return null;
    }

    /// <summary>An endpoint filter: <c>401</c> unless <see cref="AuthenticateAsync"/> knows the caller; the name lands in <c>HttpContext.Items</c>.</summary>
    public static async ValueTask<object?> RequireAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        var http = context.HttpContext;
        var caller = await http.RequestServices.GetRequiredService<ApiAccess>().AuthenticateAsync(http);
        if (caller is null)
        {
            http.Response.Headers.WWWAuthenticate = "Bearer";
            return Results.Json(new { errors = new Dictionary<string, string> { [string.Empty] = "A valid X-Api-Key or bearer token is required." } }, statusCode: StatusCodes.Status401Unauthorized);
        }

        http.Items[CallerKey] = caller;
        return await next(context);
    }

    public const string CallerKey = "matidentity:api-caller";
}
