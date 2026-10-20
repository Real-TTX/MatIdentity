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

        if (!string.IsNullOrWhiteSpace(config.SmtpHost))
        {
            if (config.SmtpHost.Trim().Length > 253 || config.SmtpHost.Any(char.IsWhiteSpace))
            {
                errors["smtpHost"] = "Enter the name or address of the server, like smtp.example.com.";
            }

            if (config.SmtpPort is < 1 or > 65535)
            {
                errors["smtpPort"] = "Choose a port between 1 and 65535.";
            }

            if (string.IsNullOrWhiteSpace(config.SmtpFrom) || !IsMailAddress(config.SmtpFrom))
            {
                errors["smtpFrom"] = "Enter the sender address, like id@example.com.";
            }

            if (Mail.SmtpTarget.Parse(config.SmtpTls) is null)
            {
                errors["smtpTls"] = "Choose none, starttls or tls.";
            }
        }

        return errors;
    }

    /// <summary>The names of the settings that differ (for the activity list; values are not named, the SMTP password is only 'smtpPassword').</summary>
    public static List<string> Changes(SystemConfig before, SystemConfig after)
    {
        var a = System.Text.Json.JsonSerializer.SerializeToElement(before, JsonConfigStore.JsonOptions);
        var b = System.Text.Json.JsonSerializer.SerializeToElement(after, JsonConfigStore.JsonOptions);
        var names = a.EnumerateObject().Select(p => p.Name).Union(b.EnumerateObject().Select(p => p.Name));
        return names
            .Where(n => (a.TryGetProperty(n, out var x) ? x.GetRawText() : null) != (b.TryGetProperty(n, out var y) ? y.GetRawText() : null))
            .Select(n => n == "smtpPasswordProtected" ? "smtpPassword" : n)
            .ToList();
    }

    /// <summary>A plain address (<c>name@host</c>), as MimeKit reads it.</summary>
    public static bool IsMailAddress(string value)
        => MimeKit.MailboxAddress.TryParse(value.Trim(), out var address) && address.Address.Contains('@') && string.IsNullOrEmpty(address.Name);

    /// <summary>Saves the values when they are valid; returns the errors otherwise (nothing is saved then).</summary>
    public async Task<Dictionary<string, string>> SaveAsync(SystemConfig config, CancellationToken ct = default)
    {
        config.InstanceName = config.InstanceName?.Trim() ?? string.Empty;
        config.Issuer = string.IsNullOrWhiteSpace(config.Issuer) ? null : config.Issuer.Trim().TrimEnd('/');
        config.SmtpHost = string.IsNullOrWhiteSpace(config.SmtpHost) ? null : config.SmtpHost.Trim();
        config.SmtpUsername = string.IsNullOrWhiteSpace(config.SmtpUsername) ? null : config.SmtpUsername.Trim();
        config.SmtpFrom = string.IsNullOrWhiteSpace(config.SmtpFrom) ? null : config.SmtpFrom.Trim();
        config.SmtpTls = config.SmtpTls?.Trim().ToLowerInvariant() ?? "starttls";
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
