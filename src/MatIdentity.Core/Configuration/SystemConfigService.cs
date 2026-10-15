namespace MatIdentity.Core.Configuration;

/// <summary>Reads and changes <see cref="SystemConfig"/>; the values are checked here, so the page and <c>/api/configure</c> share the rules.</summary>
public sealed class SystemConfigService
{
    public const int MinSessionDays = 1;
    public const int MaxSessionDays = 365;
    public const int MinTokenMinutes = 5;
    public const int MaxTokenMinutes = 24 * 60;

    private readonly JsonConfigStore _store;

    public SystemConfigService(JsonConfigStore store)
    {
        _store = store;
    }

    public Task<SystemConfig> GetAsync(CancellationToken ct = default) => _store.GetAsync<SystemConfig>(SystemConfig.FileName, ct);

    /// <summary>Checks the values; the dictionary maps the name of a setting (camelCase, as in the API) to a message. Empty = valid.</summary>
    public static Dictionary<string, string> Validate(SystemConfig config)
    {
        var errors = new Dictionary<string, string>();
        if (string.IsNullOrWhiteSpace(config.InstanceName) || config.InstanceName.Trim().Length > 80)
        {
            errors["instanceName"] = "Please enter a name of up to 80 characters.";
        }

        if (!string.IsNullOrWhiteSpace(config.Issuer) && !IsValidIssuer(config.Issuer))
        {
            errors["issuer"] = "Enter an absolute address like https://id.example.com (no path, no query).";
        }

        if (config.SessionLifetimeDays is < MinSessionDays or > MaxSessionDays)
        {
            errors["sessionLifetimeDays"] = $"Choose between {MinSessionDays} and {MaxSessionDays} days.";
        }

        if (config.AccessTokenMinutes is < MinTokenMinutes or > MaxTokenMinutes)
        {
            errors["accessTokenMinutes"] = $"Choose between {MinTokenMinutes} and {MaxTokenMinutes} minutes.";
        }

        return errors;
    }

    /// <summary>Saves the values when they are valid; returns the errors otherwise (nothing is saved then).</summary>
    public async Task<Dictionary<string, string>> SaveAsync(SystemConfig config, CancellationToken ct = default)
    {
        config.InstanceName = config.InstanceName?.Trim() ?? string.Empty;
        config.Issuer = string.IsNullOrWhiteSpace(config.Issuer) ? null : config.Issuer.Trim().TrimEnd('/');
        var errors = Validate(config);
        if (errors.Count == 0)
        {
            await _store.SaveAsync(SystemConfig.FileName, config, ct);
        }

        return errors;
    }

    /// <summary>An issuer is an absolute http(s) address without query or fragment (OpenID Connect Discovery, section 3).</summary>
    public static bool IsValidIssuer(string value)
        => Uri.TryCreate(value.Trim(), UriKind.Absolute, out var uri)
           && (uri.Scheme == Uri.UriSchemeHttps || uri.Scheme == Uri.UriSchemeHttp)
           && string.IsNullOrEmpty(uri.Query)
           && string.IsNullOrEmpty(uri.Fragment);
}
