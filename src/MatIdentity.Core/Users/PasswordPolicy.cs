namespace MatIdentity.Core.Users;

/// <summary>
/// The rules for a new password, everywhere one is chosen (setup, account, a link, an administrator): at least <see cref="Configuration.SystemConfig.PasswordMinLength"/>
/// characters (8 at the least), not the user name or the e-mail address, not one of the passwords every attacker tries first. No rules of composition (NIST SP 800-63B).
/// </summary>
public static class PasswordPolicy
{
    public const int Floor = 8;
    public const int Ceiling = 128;

    /// <summary>The ones tried first (lists of leaked passwords, at least 8 characters).</summary>
    private static readonly HashSet<string> Common = new(StringComparer.OrdinalIgnoreCase)
    {
        "password", "password1", "password123", "passwort", "passwort1", "12345678", "123456789", "1234567890", "qwertyui", "qwertyuiop", "qwertz123",
        "iloveyou", "sunshine", "princess", "football", "baseball", "welcome1", "welcome123", "admin123", "administrator", "letmein1", "abc12345",
        "11111111", "00000000", "87654321", "qwerty123", "1q2w3e4r", "1qaz2wsx", "zaq12wsx", "superman", "starwars", "dragon12", "monkey12", "changeme",
        "hallo123", "schatz123", "matidentity",
    };

    /// <summary>Null when <paramref name="password"/> may be used, else the reason for the person.</summary>
    public static string? Check(string? password, int minLength, params string?[] personal)
    {
        var min = Math.Clamp(minLength, Floor, Ceiling);
        if (string.IsNullOrEmpty(password) || password.Length < min)
        {
            return $"Use at least {min} characters.";
        }

        if (password.Length > Ceiling)
        {
            return $"Use at most {Ceiling} characters.";
        }

        if (Common.Contains(password))
        {
            return "This is one of the passwords tried first. Choose another one.";
        }

        foreach (var value in personal)
        {
            var name = value?.Trim();
            var local = name?.Split('@')[0];
            if ((!string.IsNullOrEmpty(name) && password.Contains(name, StringComparison.OrdinalIgnoreCase))
                || (local is { Length: >= 4 } && password.Contains(local, StringComparison.OrdinalIgnoreCase)))
            {
                return "The password must not contain the user name or the e-mail address.";
            }
        }

        return null;
    }
}
