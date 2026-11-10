using System.Text.Json;
using System.Text.RegularExpressions;
using MatIdentity.Core.Entities;

namespace MatIdentity.Core.Access;

/// <summary>What an app's rules say for one person.</summary>
/// <param name="Allowed">The person may sign in to the app.</param>
/// <param name="Role">The role of the app for the token (claim <c>role</c>); null when the app decides the roles itself.</param>
/// <param name="Reason">For a person: why (shown on the page that says no, and in the activity list).</param>
public sealed record AccessDecision(bool Allowed, string? Role, string Reason)
{
    /// <summary>The permissions of the app the person ends up with (claim <c>entitlements</c>): those of the role, of their own grant and of their groups' grants.</summary>
    public IReadOnlyList<string> Permissions { get; init; } = [];

    /// <summary>The quotas that are set for the person (claim <c>mat_quotas</c>; null = no limit); a quota that is not here is the app's own setting.</summary>
    public IReadOnlyDictionary<string, long?> Quotas { get; init; } = new Dictionary<string, long?>();

    /// <summary>Why the person may come in: <c>person</c>, <c>group:&lt;name&gt;</c>, <c>everyone</c>, <c>administrator</c>.</summary>
    public IReadOnlyList<string> Via { get; init; } = [];

    /// <summary>What an app sees of the decision, as one text: two decisions with the same signature give the app the same claims.</summary>
    public string Signature
        => Allowed
            ? $"{Role}|{string.Join(' ', Permissions)}|{string.Join(' ', Quotas.OrderBy(q => q.Key, StringComparer.Ordinal).Select(q => $"{q.Key}={q.Value?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "-"}"))}"
            : "-";
}

/// <summary>A role of an app as the pages and the API see it.</summary>
public sealed record RoleInfo(string Key, string Label);

/// <summary>A permission of an app (a right on top of a role): <paramref name="Roles"/> have it without anyone giving it.</summary>
public sealed record PermissionInfo(string Key, string Label, string? Hint = null, IReadOnlyList<string>? Roles = null);

/// <summary>A quota of an app (a number per person): <paramref name="Unit"/> <c>bytes</c>, <c>count</c>, <c>tokens</c>, <c>minutes</c>, <c>requests</c>; <paramref name="Period"/> <c>day</c>, <c>month</c> or none.</summary>
public sealed record QuotaInfo(string Key, string Label, string Unit, string? Period = null, long? Min = null, long? Max = null, string? Hint = null);

/// <summary>What a grant gives on top of its role: permissions and quotas (null = no limit).</summary>
public sealed record GrantValues(IReadOnlyList<string> Permissions, IReadOnlyDictionary<string, long?> Quotas)
{
    public static readonly GrantValues None = new([], new Dictionary<string, long?>());

    /// <summary>The values a grant keeps (what cannot be read counts as nothing).</summary>
    public static GrantValues Of(AppGrant grant)
    {
        ArgumentNullException.ThrowIfNull(grant);
        var permissions = (grant.Permissions ?? string.Empty).Split(' ', StringSplitOptions.RemoveEmptyEntries).Where(AccessKeys.IsKey).Distinct(StringComparer.Ordinal).ToList();
        var quotas = new Dictionary<string, long?>(StringComparer.Ordinal);
        if (!string.IsNullOrWhiteSpace(grant.Quotas))
        {
            try
            {
                using var document = JsonDocument.Parse(grant.Quotas);
                if (document.RootElement.ValueKind == JsonValueKind.Object)
                {
                    foreach (var entry in document.RootElement.EnumerateObject().Where(e => AccessKeys.IsKey(e.Name)))
                    {
                        if (entry.Value.ValueKind == JsonValueKind.Null)
                        {
                            quotas[entry.Name] = null;
                        }
                        else if (entry.Value.TryGetInt64(out var number) && number >= 0)
                        {
                            quotas[entry.Name] = number;
                        }
                    }
                }
            }
            catch (JsonException)
            {
                // A value that cannot be read gives nothing.
            }
        }

        return new GrantValues(permissions, quotas);
    }

    /// <summary>The permissions as a grant keeps them (null when there are none).</summary>
    public string? PermissionsText => Permissions.Count == 0 ? null : string.Join(' ', Permissions);

    /// <summary>The quotas as a grant keeps them (null when there are none).</summary>
    public string? QuotasJson => Quotas.Count == 0 ? null : JsonSerializer.Serialize(Quotas.OrderBy(q => q.Key, StringComparer.Ordinal).ToDictionary(q => q.Key, q => q.Value));
}

/// <summary>The keys of permissions and quotas, and their units: the same form as role keys.</summary>
public static partial class AccessKeys
{
    public static readonly IReadOnlySet<string> Units = new HashSet<string>(StringComparer.Ordinal) { "bytes", "count", "tokens", "minutes", "requests" };

    public static readonly IReadOnlySet<string> Periods = new HashSet<string>(StringComparer.Ordinal) { "day", "month" };

    public static bool IsKey(string? key) => key is not null && KeyRegex().IsMatch(key);

    [GeneratedRegex("^[a-z0-9][a-z0-9_-]{0,63}$")]
    private static partial Regex KeyRegex();
}

/// <summary>A person's access to an app changed (their access, role, permissions or quotas): the app has to hear of it.</summary>
public sealed record AccessChange(string Subject, string ClientId);

/// <summary>
/// Hears when the access of people to apps changes, so the apps take the new values at once (the web project sends a back-channel logout with the subject alone to the
/// app, which ends the person's sessions there; the next request signs them in again with the new claims).
/// </summary>
public interface IAccessChangeListener
{
    Task AccessChangedAsync(IReadOnlyList<AccessChange> changes, CancellationToken ct);
}

/// <summary>Nobody listens (Core alone, the tests of Core).</summary>
public sealed class NoAccessChangeListener : IAccessChangeListener
{
    public Task AccessChangedAsync(IReadOnlyList<AccessChange> changes, CancellationToken ct) => Task.CompletedTask;
}
