using System.Security.Cryptography;
using System.Text;

namespace MatIdentity.Core.Security;

/// <summary>
/// Time-based one-time passwords (RFC 6238, the codes of an authenticator app): HMAC-SHA1, 30 seconds, 6 digits, which is what every app can read
/// from the QR code. A code is accepted in its own 30 seconds and the one before and after (a clock that is a little off), and never twice:
/// the caller keeps the last step that was used.
/// </summary>
public static class Totp
{
    public const int Digits = 6;
    public const int PeriodSeconds = 30;
    private const string Base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    /// <summary>A new secret: 20 random bytes (160 bits, as RFC 4226 recommends), Base32 as the apps want it.</summary>
    public static string NewSecret() => ToBase32(RandomNumberGenerator.GetBytes(20));

    /// <summary>The step of a moment: the number of 30-second periods since 1970.</summary>
    public static long StepOf(DateTimeOffset time) => time.ToUnixTimeSeconds() / PeriodSeconds;

    /// <summary>The code of a step.</summary>
    public static string Code(string base32Secret, long step)
    {
        var counter = new byte[8];
        for (var i = 7; i >= 0; i--)
        {
            counter[i] = (byte)(step & 0xff);
            step >>= 8;
        }

        var hash = HMACSHA1.HashData(FromBase32(base32Secret), counter);
        var offset = hash[^1] & 0x0f;
        var binary = ((hash[offset] & 0x7f) << 24) | (hash[offset + 1] << 16) | (hash[offset + 2] << 8) | hash[offset + 3];
        return (binary % 1_000_000).ToString("D6", System.Globalization.CultureInfo.InvariantCulture);
    }

    /// <summary>
    /// The step the code belongs to, when it is valid now (this step, the one before or after) and newer than <paramref name="lastUsedStep"/>; else null.
    /// Spaces in the code are ignored (apps show "123 456").
    /// </summary>
    public static long? Verify(string base32Secret, string? code, DateTimeOffset now, long lastUsedStep)
    {
        var digits = (code ?? string.Empty).Replace(" ", string.Empty, StringComparison.Ordinal);
        if (digits.Length != Digits || !digits.All(char.IsAsciiDigit))
        {
            return null;
        }

        var current = StepOf(now);
        foreach (var step in new[] { current, current - 1, current + 1 })
        {
            if (step > lastUsedStep && CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(Code(base32Secret, step)), Encoding.ASCII.GetBytes(digits)))
            {
                return step;
            }
        }

        return null;
    }

    /// <summary>The address an authenticator app reads from the QR code (the "Key Uri Format" of Google Authenticator, which all apps follow).</summary>
    public static string KeyUri(string issuer, string account, string base32Secret)
        => $"otpauth://totp/{Uri.EscapeDataString(issuer)}:{Uri.EscapeDataString(account)}?secret={base32Secret}&issuer={Uri.EscapeDataString(issuer)}&digits={Digits}&period={PeriodSeconds}";

    public static string ToBase32(byte[] data)
    {
        var result = new StringBuilder((data.Length + 4) / 5 * 8);
        int buffer = 0, bits = 0;
        foreach (var b in data)
        {
            buffer = (buffer << 8) | b;
            bits += 8;
            while (bits >= 5)
            {
                result.Append(Base32Alphabet[(buffer >> (bits - 5)) & 31]);
                bits -= 5;
            }
        }

        if (bits > 0)
        {
            result.Append(Base32Alphabet[(buffer << (5 - bits)) & 31]);
        }

        return result.ToString();
    }

    public static byte[] FromBase32(string text)
    {
        var clean = text.Trim().TrimEnd('=').Replace(" ", string.Empty, StringComparison.Ordinal).ToUpperInvariant();
        var bytes = new List<byte>(clean.Length * 5 / 8);
        int buffer = 0, bits = 0;
        foreach (var c in clean)
        {
            var value = Base32Alphabet.IndexOf(c, StringComparison.Ordinal);
            if (value < 0)
            {
                throw new FormatException($"'{c}' is not a Base32 character.");
            }

            buffer = (buffer << 5) | value;
            bits += 5;
            if (bits >= 8)
            {
                bytes.Add((byte)((buffer >> (bits - 8)) & 0xff));
                bits -= 8;
            }
        }

        return [.. bytes];
    }
}
