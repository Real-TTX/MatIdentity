namespace MatIdentity.Core.Configuration;

/// <summary>
/// Strongly-typed application options bound from configuration (section <c>MatIdentity</c>) and environment variables
/// (<c>MatIdentity__DataPath</c>, ...). Everything the app writes lives under <see cref="DataPath"/>, which is expected to be a mounted
/// Docker volume so data survives container restarts. What an administrator changes at runtime is in <see cref="SystemConfig"/> instead.
/// </summary>
public sealed class MatIdentityOptions
{
    public const string SectionName = "MatIdentity";

    /// <summary>Root data directory (database, config, keys). Container default: <c>/data</c>.</summary>
    public string DataPath { get; set; } = "/data";

    /// <summary>
    /// The public address of MatIdentity (<c>https://id.example.com</c>), the <c>iss</c> of every token. Empty: the address the request came in on
    /// (behind a reverse proxy that sends X-Forwarded-*), which is fine as long as everyone reaches MatIdentity under one address.
    /// The setting of the same name in the UI wins over this one.
    /// </summary>
    public string? Issuer { get; set; }

    /// <summary>The key for <c>/api/*</c> (header <c>X-Api-Key</c>); empty switches the key off. Read from <c>MAT_API_KEY</c> as well (docs/PLATFORM.md).</summary>
    public string? ApiKey { get; set; }

    public AdminSeedOptions Admin { get; set; } = new();
}

/// <summary>Credentials used to seed the first administrator on an empty database (headless setups).</summary>
public sealed class AdminSeedOptions
{
    /// <summary>When true, seed the admin from these settings on an empty DB (headless/automated
    /// deployments). When false (default), an empty DB shows the first-run setup instead.</summary>
    public bool Seed { get; set; }

    public string Username { get; set; } = "admin";

    public string DisplayName { get; set; } = "Administrator";

    /// <summary>Initial password. The seeded admin is forced to change it on first login.</summary>
    public string Password { get; set; } = "admin";
}
