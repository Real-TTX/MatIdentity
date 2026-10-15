namespace MatIdentity.Core.Configuration;

/// <summary>
/// Resolves the concrete file-system layout under <see cref="MatIdentityOptions.DataPath"/> and makes
/// sure the required directories exist. Registered as a singleton.
/// </summary>
public sealed class AppPaths
{
    public AppPaths(string dataPath)
    {
        DataPath = dataPath;
        ConfigPath = Path.Combine(dataPath, "config");
        KeysPath = Path.Combine(dataPath, "dataprotection-keys");
        TokenKeysPath = Path.Combine(dataPath, "token-keys");
        DatabasePath = Path.Combine(dataPath, "matidentity.db");
    }

    public string DataPath { get; }

    /// <summary>JSON configuration files (system.json).</summary>
    public string ConfigPath { get; }

    /// <summary>The keys of ASP.NET Core Data Protection (cookies, protected secrets).</summary>
    public string KeysPath { get; }

    /// <summary>The keys that sign and encrypt the tokens (<see cref="Security.TokenKeys"/>): losing them signs every app out.</summary>
    public string TokenKeysPath { get; }

    public string DatabasePath { get; }

    public string SqliteConnectionString => $"Data Source={DatabasePath}";

    /// <summary>Creates the data directories if they do not yet exist.</summary>
    public void EnsureCreated()
    {
        foreach (var path in new[] { DataPath, ConfigPath, KeysPath, TokenKeysPath })
        {
            Directory.CreateDirectory(path);
        }
    }
}
