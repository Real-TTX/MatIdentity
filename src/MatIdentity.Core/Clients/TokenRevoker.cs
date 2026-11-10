using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace MatIdentity.Core.Clients;

/// <summary>
/// Ends what the apps hold for a person: their refresh tokens (and so the sign-in in every app, at the next renewal of the short access token).
/// Used when an account is disabled or deleted, when an administrator sets a new password, and by "Sign everyone out".
/// </summary>
public sealed class TokenRevoker
{
    private readonly IOpenIddictTokenManager _tokens;
    private readonly IOpenIddictApplicationManager? _applications;

    public TokenRevoker(IOpenIddictTokenManager tokens, IOpenIddictApplicationManager? applications = null)
    {
        _tokens = tokens;
        _applications = applications;
    }

    /// <summary>Revokes the valid refresh tokens of the person with the claim <c>sub</c> = <paramref name="subject"/>. Returns how many.</summary>
    public async Task<int> RevokeForSubjectAsync(string subject, CancellationToken ct = default)
    {
        var found = new List<object>();
        await foreach (var token in _tokens.FindBySubjectAsync(subject, ct))
        {
            found.Add(token);
        }

        return await RevokeRefreshTokensAsync(found, ct);
    }

    /// <summary>
    /// Revokes the valid refresh tokens of the person <paramref name="subject"/> in one app (its access, role, permissions or quotas there changed: the app has to
    /// sign the person in again to get the new values). Returns how many.
    /// </summary>
    public async Task<int> RevokeForSubjectAndClientAsync(string subject, string clientId, CancellationToken ct = default)
    {
        if (_applications is null || await _applications.FindByClientIdAsync(clientId, ct) is not { } app || await _applications.GetIdAsync(app, ct) is not { } appId)
        {
            return 0;
        }

        var found = new List<object>();
        await foreach (var token in _tokens.FindAsync(subject, appId, status: null, type: null, ct))
        {
            found.Add(token);
        }

        return await RevokeRefreshTokensAsync(found, ct);
    }

    /// <summary>Revokes every valid refresh token of every person (machine tokens are access tokens only and expire on their own). Returns how many.</summary>
    public async Task<int> RevokeAllAsync(CancellationToken ct = default)
    {
        var found = new List<object>();
        await foreach (var token in _tokens.ListAsync(count: null, offset: null, ct))
        {
            found.Add(token);
        }

        return await RevokeRefreshTokensAsync(found, ct);
    }

    private async Task<int> RevokeRefreshTokensAsync(IEnumerable<object> tokens, CancellationToken ct)
    {
        var count = 0;
        foreach (var token in tokens)
        {
            // OpenIddict 5 and later keep the type as its URN (urn:ietf:params:oauth:token-type:refresh_token); before, it was the hint "refresh_token".
            if (await _tokens.GetTypeAsync(token, ct) is TokenTypeIdentifiers.RefreshToken or TokenTypeHints.RefreshToken
                && await _tokens.HasStatusAsync(token, Statuses.Valid, ct)
                && await _tokens.TryRevokeAsync(token, ct))
            {
                count++;
            }
        }

        return count;
    }
}
