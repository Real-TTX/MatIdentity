using System.Collections.Immutable;
using System.Security.Claims;
using MatIdentity.Core.Activity;
using MatIdentity.Core.Auth;
using MatIdentity.Core.Entities;
using MatIdentity.Core.Users;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace MatIdentity.Web.Infrastructure;

/// <summary>
/// The parts of OpenID Connect that need a decision of MatIdentity (OpenIddict checks the protocol, these handlers say who is signed in and
/// what goes into the tokens): <c>/connect/authorize</c> (single sign-on: a person with a session here goes straight back to the app),
/// <c>/connect/token</c> (codes, refresh tokens, machine tokens), <c>/connect/userinfo</c> and <c>/connect/logout</c>.
/// </summary>
public static class OidcEndpoints
{
    public static void MapOidcEndpoints(this WebApplication app)
    {
        app.MapMethods("/connect/authorize", [HttpMethods.Get, HttpMethods.Post], AuthorizeAsync).AllowAnonymous().DisableAntiforgery();
        app.MapPost("/connect/token", TokenAsync).AllowAnonymous().DisableAntiforgery().RequireRateLimiting(RateLimits.Token);
        app.MapMethods("/connect/userinfo", [HttpMethods.Get, HttpMethods.Post], UserInfoAsync).AllowAnonymous().DisableAntiforgery();
        app.MapMethods("/connect/logout", [HttpMethods.Get, HttpMethods.Post], LogoutAsync).AllowAnonymous().DisableAntiforgery();
    }

    private static async Task<IResult> AuthorizeAsync(HttpContext http, UserService users, ActivityService activity)
    {
        var request = http.GetOpenIddictServerRequest() ?? throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");
        var cookie = await http.AuthenticateAsync(AuthConstants.CookieScheme);
        var forceLogin = request.HasPromptValue(PromptValues.Login);
        var user = cookie.Succeeded && cookie.Principal.GetUserId() is { } id ? await users.GetAsync(id, http.RequestAborted) : null;

        if (user is null || !user.IsActive || forceLogin)
        {
            if (request.HasPromptValue(PromptValues.None))
            {
                return Forbid(Errors.LoginRequired, "The user is not signed in.");
            }

            // Back here after the sign-in, without prompt=login (else the form would come again and again).
            var parameters = (http.Request.HasFormContentType ? http.Request.Form.ToList() : http.Request.Query.ToList())
                .Where(p => p.Key != Parameters.Prompt)
                .ToList();
            var returnUrl = http.Request.PathBase + http.Request.Path + QueryString.Create(parameters);
            return Results.Redirect("/Account/Login?returnUrl=" + Uri.EscapeDataString(returnUrl) + (forceLogin ? "&force=true" : string.Empty));
        }

        var identity = BuildIdentity(user, request.GetScopes());
        // The access token of a person is meant for the app that asked for it (its own API checks the audience).
        identity.SetResources(request.ClientId ?? string.Empty);
        identity.SetDestinations(Destinations);

        await activity.WriteAsync(ActivityKind.AppSignIn, user, clientId: request.ClientId, ipAddress: http.Connection.RemoteIpAddress?.ToString(), ct: http.RequestAborted);
        return Results.SignIn(new ClaimsPrincipal(identity), properties: null, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    private static async Task<IResult> TokenAsync(HttpContext http, UserService users, ActivityService activity, IOpenIddictApplicationManager applications, IOpenIddictScopeManager scopes)
    {
        var request = http.GetOpenIddictServerRequest() ?? throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        if (request.IsClientCredentialsGrantType())
        {
            // A machine (Mattiverse, an app calling another app): the token is the app's own, for the apps whose scopes it asked for.
            var app = await applications.FindByClientIdAsync(request.ClientId ?? string.Empty, http.RequestAborted);
            if (app is null)
            {
                return Forbid(Errors.InvalidClient, "The app is not known.");
            }

            var identity = new ClaimsIdentity(TokenValidationParameters.DefaultAuthenticationType, Claims.Name, Claims.Role);
            identity.SetClaim(Claims.Subject, request.ClientId);
            identity.SetClaim(Claims.Name, await applications.GetDisplayNameAsync(app, http.RequestAborted));
            identity.SetScopes(request.GetScopes());

            var resources = new List<string>();
            await foreach (var resource in scopes.ListResourcesAsync(identity.GetScopes(), http.RequestAborted))
            {
                resources.Add(resource);
            }

            identity.SetResources(resources);
            identity.SetDestinations(_ => [OpenIddictConstants.Destinations.AccessToken]);

            await activity.WriteAsync(ActivityKind.MachineToken, clientId: request.ClientId, ipAddress: http.Connection.RemoteIpAddress?.ToString(),
                detail: string.Join(' ', request.GetScopes()), ct: http.RequestAborted);
            return Results.SignIn(new ClaimsPrincipal(identity), properties: null, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        if (request.IsAuthorizationCodeGrantType() || request.IsRefreshTokenGrantType())
        {
            // The principal of the code or the refresh token; the person is read again, so a disabled account or a new role takes effect at once.
            var result = await http.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            var subject = result.Principal?.GetClaim(Claims.Subject);
            var user = subject is null ? null : await users.GetBySubjectAsync(subject, http.RequestAborted);
            if (result.Principal is null || user is null || !user.IsActive)
            {
                return Forbid(Errors.InvalidGrant, "The account no longer exists or is disabled.");
            }

            var identity = BuildIdentity(user, result.Principal.GetScopes());
            identity.SetResources(result.Principal.GetResources());
            identity.SetDestinations(Destinations);
            return Results.SignIn(new ClaimsPrincipal(identity), properties: null, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        return Forbid(Errors.UnsupportedGrantType, "This grant type is not supported.");
    }

    private static async Task<IResult> UserInfoAsync(HttpContext http, UserService users)
    {
        var result = await http.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        var subject = result.Principal?.GetClaim(Claims.Subject);
        var user = subject is null ? null : await users.GetBySubjectAsync(subject, http.RequestAborted);
        if (result.Principal is null || user is null || !user.IsActive)
        {
            return Results.Challenge(
                new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidToken,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The account no longer exists or is disabled.",
                }),
                [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme]);
        }

        var claims = new Dictionary<string, object>(StringComparer.Ordinal) { [Claims.Subject] = user.Subject };
        if (result.Principal.HasScope(Scopes.Profile))
        {
            claims[Claims.Name] = user.DisplayName;
            claims[Claims.PreferredUsername] = user.Username;
        }

        if (result.Principal.HasScope(Scopes.Email) && !string.IsNullOrEmpty(user.Email))
        {
            claims[Claims.Email] = user.Email;
            claims[Claims.EmailVerified] = false;
        }

        if (result.Principal.HasScope(Scopes.Roles))
        {
            claims[Claims.Role] = RoleClaim(user.Role);
        }

        return Results.Ok(claims);
    }

    private static async Task<IResult> LogoutAsync(HttpContext http, SessionService sessions, UserService users, ActivityService activity)
    {
        // Ends the single sign-on session here; OpenIddict then sends the person back to the app (post_logout_redirect_uri, when it is registered).
        var cookie = await http.AuthenticateAsync(AuthConstants.CookieScheme);
        if (cookie.Succeeded)
        {
            if (cookie.Principal.GetSessionToken() is { } token)
            {
                await sessions.InvalidateAsync(token, http.RequestAborted);
            }

            var user = cookie.Principal.GetUserId() is { } id ? await users.GetAsync(id, http.RequestAborted) : null;
            await activity.WriteAsync(ActivityKind.SignOut, user, clientId: http.GetOpenIddictServerRequest()?.ClientId,
                ipAddress: http.Connection.RemoteIpAddress?.ToString(), ct: http.RequestAborted);
            await http.SignOutAsync(AuthConstants.CookieScheme);
        }

        return Results.SignOut(new AuthenticationProperties { RedirectUri = "/Account/Login?signedOut=true" }, [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme]);
    }

    /// <summary>The claims of a person, by the scopes the app asked for (<c>sub</c> always).</summary>
    internal static ClaimsIdentity BuildIdentity(User user, ImmutableArray<string> scopes)
    {
        var identity = new ClaimsIdentity(TokenValidationParameters.DefaultAuthenticationType, Claims.Name, Claims.Role);
        identity.SetClaim(Claims.Subject, user.Subject)
            .SetClaim(Claims.Name, user.DisplayName)
            .SetClaim(Claims.PreferredUsername, user.Username)
            .SetClaim(Claims.Email, user.Email)
            .SetClaims(Claims.Role, [RoleClaim(user.Role)]);
        identity.SetScopes(scopes);
        return identity;
    }

    /// <summary>The value of the claim <c>role</c>: <c>admin</c> or <c>user</c> (docs/PLATFORM.md).</summary>
    internal static string RoleClaim(UserRole role) => role == UserRole.Admin ? "admin" : "user";

    /// <summary>Which token a claim goes into: only what the scopes allow, and the identity token gets the profile only when it was asked for.</summary>
    internal static IEnumerable<string> Destinations(Claim claim)
    {
        var principal = claim.Subject!;
        switch (claim.Type)
        {
            case Claims.Subject:
                yield return OpenIddictConstants.Destinations.AccessToken;
                yield return OpenIddictConstants.Destinations.IdentityToken;
                yield break;

            case Claims.Name or Claims.PreferredUsername when principal.HasScope(Scopes.Profile):
                yield return OpenIddictConstants.Destinations.AccessToken;
                yield return OpenIddictConstants.Destinations.IdentityToken;
                yield break;

            case Claims.Email when principal.HasScope(Scopes.Email):
                yield return OpenIddictConstants.Destinations.IdentityToken;
                yield break;

            case Claims.Role when principal.HasScope(Scopes.Roles):
                yield return OpenIddictConstants.Destinations.AccessToken;
                yield return OpenIddictConstants.Destinations.IdentityToken;
                yield break;

            // Never leave the server: the security stamp of OpenIddict and everything not asked for.
            default:
                yield break;
        }
    }

    private static IResult Forbid(string error, string description)
        => Results.Forbid(
            new AuthenticationProperties(new Dictionary<string, string?>
            {
                [OpenIddictServerAspNetCoreConstants.Properties.Error] = error,
                [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = description,
            }),
            [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme]);
}
