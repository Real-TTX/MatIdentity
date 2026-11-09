using System.Text.Encodings.Web;
using MatPlatform;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace MatIdentity.Web.Infrastructure;

/// <summary>
/// The scheme MatPlatform asks when a caller of the protected part of <c>/api</c> brings a token (<see cref="MatApiAccess.BearerScheme"/>). An app gets it from
/// <c>AddMatIdentitySignIn</c>; MatIdentity is the identity itself, so here it is a token MatIdentity issued for its own API, checked by its own validation: the same
/// check as <c>/api/v1</c> (<see cref="ApiAccess.TokenAsync"/>).
/// </summary>
public sealed class IdentityBearerHandler(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder)
    : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        => await ApiAccess.TokenAsync(Context) is { } principal
            ? AuthenticateResult.Success(new AuthenticationTicket(principal, Scheme.Name))
            : AuthenticateResult.NoResult();
}
