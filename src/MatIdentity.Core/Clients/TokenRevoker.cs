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

    public TokenRevoker(IOpenIddictTokenManager tokens)
    {
        _tokens = tokens;
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
            if (await _tokens.GetTypeAsync(token, ct) == TokenTypeHints.RefreshToken
                && await _tokens.HasStatusAsync(token, Statuses.Valid, ct)
                && await _tokens.TryRevokeAsync(token, ct))
            {
                count++;
            }
        }

        return count;
    }
}
