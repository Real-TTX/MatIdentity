using System.Text.RegularExpressions;
using MatIdentity.Core.Access;
using MatIdentity.Core.Entities;

namespace MatIdentity.Core.Clients;

/// <summary>
/// An app that signs people in through MatIdentity (an OpenID Connect client), as the pages and the API see it.
/// It is stored by OpenIddict (table <c>OidcApplication</c>); <see cref="ClientService"/> translates.
/// </summary>
public sealed record ClientInfo
{
    /// <summary>The id of the app in the family (<c>matsplit</c>): the client id, the audience of its tokens and the end of its scope <c>app:matsplit</c>.</summary>
    public required string ClientId { get; init; }

    public required string DisplayName { get; init; }

    /// <summary>The address of the app, for the list of apps and the link "Open".</summary>
    public string? HomeUrl { get; init; }

    /// <summary>People sign in to the app through MatIdentity (authorization code with PKCE, refresh tokens).</summary>
    public bool AllowSignIn { get; init; } = true;

    /// <summary>The app may get a token for itself (client credentials) to call the API of every other app (Mattiverse does).</summary>
    public bool AllowMachine { get; init; }

    /// <summary>A public client (a browser or phone app without a secret): sign-in only, PKCE enforced.</summary>
    public bool IsPublic { get; init; }

    public IReadOnlyList<string> RedirectUris { get; init; } = [];

    public IReadOnlyList<string> PostLogoutRedirectUris { get; init; } = [];

    /// <summary>
    /// Where MatIdentity tells the app that a person signed out (OpenID Connect Back-Channel Logout 1.0: a POST with a signed <c>logout_token</c>), so the app ends its
    /// own session too. Optional; MatIdentity has to reach it (inside Docker the internal address of the app is fine).
    /// </summary>
    public string? BackchannelLogoutUri { get; init; }

    /// <summary>
    /// Who created it: <c>mattiverse</c> when Mattiverse installed the app (docs/PLATFORM.md), <c>manual</c> when an administrator connected it in the Connections area
    /// (<see cref="ClientRules.ManagedByHand"/>), else null (an administrator under Apps).
    /// </summary>
    public string? ManagedBy { get; init; }
}

/// <summary>The result of a save: the client, and its secret when one was made now (shown once, never stored in plain text).</summary>
public sealed record ClientSaveResult(ClientInfo? Client, string? Secret, IReadOnlyDictionary<string, string> Errors)
{
    public bool Succeeded => Errors.Count == 0;
}

/// <summary>
/// An app as a caller registers it, by its id: the API <c>/api/v1/clients</c> (Mattiverse's own client) and the bindings of the capability <c>identity.oidc</c>
/// (<see cref="ClientService.UpsertAsync"/>). Every other value is optional; what is missing keeps its value, or the default for a new app.
/// </summary>
public sealed record ClientUpsert
{
    public required string ClientId { get; init; }

    public string? DisplayName { get; init; }

    /// <summary>"" removes it.</summary>
    public string? HomeUrl { get; init; }

    public IReadOnlyList<string>? RedirectUris { get; init; }

    public IReadOnlyList<string>? PostLogoutRedirectUris { get; init; }

    public bool? AllowSignIn { get; init; }

    public bool? AllowMachine { get; init; }

    public bool? IsPublic { get; init; }

    /// <summary>The mark of the caller (<c>mattiverse</c>, <c>manual</c>): a caller removes only what carries its own mark.</summary>
    public string? ManagedBy { get; init; }

    /// <summary>"" removes it.</summary>
    public string? BackchannelLogoutUri { get; init; }

    /// <summary>A new secret even when the app has one (the old one stops working at once).</summary>
    public bool RenewSecret { get; init; }

    public RoleMode? RoleMode { get; init; }

    /// <summary>The roles of the app, the most powerful first.</summary>
    public IReadOnlyList<RoleInfo>? Roles { get; init; }

    public bool? OpenToEveryone { get; init; }

    public bool? CallsAllApps { get; init; }

    /// <summary>The apps it may call by name (also MatIdentity's own API, which "every app" leaves out).</summary>
    public IReadOnlyList<string>? CallTargets { get; init; }
}

/// <summary>What <see cref="ClientService.UpsertAsync"/> did: the save (the app and its secret when one was made now, or the errors) and whether the app is new.</summary>
public sealed record ClientUpsertResult(ClientSaveResult Saved, bool Created);

/// <summary>What <see cref="ClientService.RemoveManagedAsync"/> did.</summary>
public enum ClientRemoval
{
    Removed,
    NotFound,

    /// <summary>The app carries another mark than the caller's: it was not removed.</summary>
    OtherMark,
}

/// <summary>The rules of a client, shared by the page and the API.</summary>
public static partial class ClientRules
{
    /// <summary>The scope prefix of an app: a token for <c>app:matsplit</c> has the audience <c>matsplit</c>.</summary>
    public const string AppScopePrefix = "app:";

    /// <summary>The id of MatIdentity itself as an app of the family (its own API is the audience <c>matidentity</c>).</summary>
    public const string SelfId = "matidentity";

    /// <summary>
    /// The mark of an app an administrator connected by hand in the Connections area (<c>managedBy: manual</c> of the platform contract, "Bindings"). The area knows only
    /// the name of the app, so it gets its id and secret first and its sign-in addresses afterwards, under Apps: until then it may be without one.
    /// </summary>
    public const string ManagedByHand = "manual";

    [GeneratedRegex("^[a-z0-9][a-z0-9_-]{1,62}$")]
    private static partial Regex ClientIdRegex();

    public static string AppScope(string clientId) => AppScopePrefix + clientId;

    public static bool IsValidClientId(string? value) => value is not null && ClientIdRegex().IsMatch(value);

    /// <summary>
    /// A redirect address is absolute, http or https, without a fragment. Plain http is only allowed for localhost-like hosts and private
    /// networks would be a guess, so it is allowed everywhere: MatIdentity runs at home behind a proxy, and many apps there are http.
    /// </summary>
    public static bool IsValidRedirectUri(string value)
        => Uri.TryCreate(value, UriKind.Absolute, out var uri)
           && (uri.Scheme == Uri.UriSchemeHttps || uri.Scheme == Uri.UriSchemeHttp)
           && string.IsNullOrEmpty(uri.Fragment);

    public static bool IsValidHomeUrl(string value) => IsValidRedirectUri(value);

    /// <summary>Splits a text field of addresses (one per line, or separated by spaces or commas) into a clean list without duplicates.</summary>
    public static IReadOnlyList<string> SplitUris(string? text)
        => (text ?? string.Empty)
            .Split(['\n', '\r', ' ', ',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Distinct(StringComparer.Ordinal)
            .ToList();

    /// <summary>Checks a client; the dictionary maps a field (camelCase) to a message. Empty = valid.</summary>
    public static Dictionary<string, string> Validate(ClientInfo client)
    {
        var errors = new Dictionary<string, string>();
        if (!IsValidClientId(client.ClientId))
        {
            errors["clientId"] = "Use 2 to 63 small letters, digits, - or _, starting with a letter or digit.";
        }
        else if (client.ClientId == SelfId)
        {
            errors["clientId"] = "This id is MatIdentity's own.";
        }

        if (string.IsNullOrWhiteSpace(client.DisplayName) || client.DisplayName.Trim().Length > 100)
        {
            errors["displayName"] = "Please enter a name of up to 100 characters.";
        }

        if (!client.AllowSignIn && !client.AllowMachine)
        {
            errors["allowSignIn"] = "Choose at least one: people sign in, or the app calls other apps.";
        }

        if (client.IsPublic && client.AllowMachine)
        {
            errors["allowMachine"] = "A public app has no secret, so it cannot get a token for itself.";
        }

        if (client.AllowSignIn && client.RedirectUris.Count == 0 && client.ManagedBy != ManagedByHand)
        {
            errors["redirectUris"] = "Add the address the app receives the sign-in at (like https://split.example.com/signin-oidc).";
        }

        if (client.RedirectUris.FirstOrDefault(u => !IsValidRedirectUri(u)) is { } badRedirect)
        {
            errors["redirectUris"] = $"\"{badRedirect}\" is not an absolute http or https address without #.";
        }

        if (client.PostLogoutRedirectUris.FirstOrDefault(u => !IsValidRedirectUri(u)) is { } badLogout)
        {
            errors["postLogoutRedirectUris"] = $"\"{badLogout}\" is not an absolute http or https address without #.";
        }

        if (!string.IsNullOrWhiteSpace(client.BackchannelLogoutUri) && !IsValidRedirectUri(client.BackchannelLogoutUri))
        {
            errors["backchannelLogoutUri"] = "Enter an absolute http or https address without #, like http://matsplit:8080/signout-backchannel.";
        }

        if (!string.IsNullOrWhiteSpace(client.HomeUrl) && !IsValidHomeUrl(client.HomeUrl))
        {
            errors["homeUrl"] = "Enter an absolute address like https://split.example.com.";
        }

        return errors;
    }
}
