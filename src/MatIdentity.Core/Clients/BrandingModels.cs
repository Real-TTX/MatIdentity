using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace MatIdentity.Core.Clients;

/// <summary>
/// The look of the sign-in of an app as the pages and the mails see it: everything but the pictures themselves (<see cref="BrandingService.ImageAsync"/> has those).
/// </summary>
public sealed record BrandInfo
{
    public required string ClientId { get; init; }

    public required string Name { get; init; }

    /// <summary><c>#rrggbb</c>, or null.</summary>
    public string? Accent { get; init; }

    public bool HideIdentity { get; init; }

    public string? LogoContentType { get; init; }

    public string? LogoHash { get; init; }

    public string? BackgroundContentType { get; init; }

    public string? BackgroundHash { get; init; }

    public bool HasLogo => LogoHash is not null;

    public bool HasBackground => BackgroundHash is not null;

    /// <summary>The version of what the stylesheet of the brand says (the accent and the background): the <c>?v=</c> of its address.</summary>
    public string ThemeVersion => BrandingRules.Hash(Encoding.UTF8.GetBytes($"{Accent}|{BackgroundHash}"));
}

/// <summary>A picture of a brand as it is served.</summary>
public sealed record BrandImage(string ContentType, byte[] Data, string Hash);

/// <summary>Which picture of a brand.</summary>
public enum BrandImageKind
{
    Logo,
    Background,
}

/// <summary>A picture as a caller sends it: the content type and the bytes as Base64.</summary>
public sealed record BrandImageInput(string? ContentType, string? Data);

/// <summary>
/// The look of the sign-in as a caller sets it (<c>branding</c> of <c>PUT /api/v1/clients/{id}</c>). The name, the accent and <see cref="HideIdentity"/> are set as
/// a whole; a picture that is not given keeps the stored one, <see cref="RemoveLogo"/> / <see cref="RemoveBackground"/> remove it.
/// </summary>
public sealed record BrandingInput
{
    public string? Name { get; init; }

    public string? Accent { get; init; }

    public bool HideIdentity { get; init; }

    public BrandImageInput? Logo { get; init; }

    public bool RemoveLogo { get; init; }

    public BrandImageInput? Background { get; init; }

    public bool RemoveBackground { get; init; }
}

/// <summary>A checked <see cref="BrandingInput"/>: the errors (field, message), else the decoded pictures.</summary>
public sealed record BrandingCheck(Dictionary<string, string> Errors, byte[]? Logo, byte[]? Background)
{
    public bool Succeeded => Errors.Count == 0;
}

/// <summary>The rules of a brand, shared by the API and the tests: the limits, the content types, and that a picture is what it says it is.</summary>
public static partial class BrandingRules
{
    /// <summary>The largest logo: 256 KiB.</summary>
    public const int MaxLogoBytes = 256 * 1024;

    /// <summary>The largest background: 2 MiB.</summary>
    public const int MaxBackgroundBytes = 2 * 1024 * 1024;

    public const int MaxNameLength = 60;

    public const string Svg = "image/svg+xml";
    public const string Png = "image/png";
    public const string Jpeg = "image/jpeg";
    public const string Webp = "image/webp";

    public static readonly IReadOnlyList<string> LogoTypes = [Svg, Png];

    public static readonly IReadOnlyList<string> BackgroundTypes = [Jpeg, Png, Webp];

    [GeneratedRegex("^#[0-9a-fA-F]{6}$")]
    private static partial Regex AccentRegex();

    public static bool IsValidAccent(string? value) => value is not null && AccentRegex().IsMatch(value);

    /// <summary>The first 16 hex digits of the SHA-256 (lower case): an ETag and a version.</summary>
    public static string Hash(byte[] data) => Convert.ToHexStringLower(SHA256.HashData(data))[..16];

    /// <summary>Checks a brand and decodes its pictures. The fields of the errors are <c>branding.name</c>, <c>branding.accent</c>, <c>branding.logo</c> and <c>branding.background</c>.</summary>
    public static BrandingCheck Check(BrandingInput input)
    {
        ArgumentNullException.ThrowIfNull(input);
        var errors = new Dictionary<string, string>();
        var name = input.Name?.Trim();
        if (string.IsNullOrEmpty(name) || name.Length > MaxNameLength)
        {
            errors["branding.name"] = $"Give the name the sign-in shows, up to {MaxNameLength} characters.";
        }

        if (input.Accent is not null && !IsValidAccent(input.Accent))
        {
            errors["branding.accent"] = "Give the accent as #rrggbb, like #2563eb.";
        }

        var logo = input.Logo is null ? null : Picture(input.Logo, "branding.logo", "logo", LogoTypes, MaxLogoBytes, "256 KiB", errors);
        var background = input.Background is null ? null : Picture(input.Background, "branding.background", "background", BackgroundTypes, MaxBackgroundBytes, "2 MiB", errors);
        return new BrandingCheck(errors, logo, background);
    }

    /// <summary>The bytes of a picture, or null with an error: a known content type, Base64, not empty, within the limit, and the bytes are of that type.</summary>
    private static byte[]? Picture(BrandImageInput image, string field, string what, IReadOnlyList<string> types, int max, string maxText, Dictionary<string, string> errors)
    {
        if (image.ContentType is null || !types.Contains(image.ContentType))
        {
            errors[field] = $"The {what} must be {string.Join(" or ", types)}.";
            return null;
        }

        var data = image.Data?.Trim() ?? string.Empty;
        // Base64 grows by a third: anything longer than this cannot be within the limit (checked before decoding).
        if (data.Length > ((max + 2) / 3 * 4) + 4)
        {
            errors[field] = $"The {what} is larger than {maxText}.";
            return null;
        }

        var buffer = new byte[(data.Length * 3 / 4) + 3];
        if (data.Length == 0 || !Convert.TryFromBase64String(data, buffer, out var length) || length == 0)
        {
            errors[field] = $"The {what} must be its bytes as Base64.";
            return null;
        }

        if (length > max)
        {
            errors[field] = $"The {what} is larger than {maxText}.";
            return null;
        }

        var bytes = buffer[..length];
        if (!IsOfType(bytes, image.ContentType))
        {
            errors[field] = $"The {what} is not a picture of the type {image.ContentType}.";
            return null;
        }

        return bytes;
    }

    /// <summary>The first bytes say what a file is: the signature of PNG, JPEG and WebP; an SVG is XML text with an <c>&lt;svg</c> element.</summary>
    public static bool IsOfType(ReadOnlySpan<byte> data, string contentType) => contentType switch
    {
        Png => data.Length > 8 && data[..8].SequenceEqual((ReadOnlySpan<byte>)[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
        Jpeg => data.Length > 3 && data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF,
        Webp => data.Length > 12 && data[..4].SequenceEqual("RIFF"u8) && data[8..12].SequenceEqual("WEBP"u8),
        Svg => IsSvg(data),
        _ => false,
    };

    private static bool IsSvg(ReadOnlySpan<byte> data)
    {
        string text;
        try
        {
            text = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true).GetString(data).TrimStart('﻿').TrimStart();
        }
        catch (DecoderFallbackException)
        {
            return false;
        }

        return text.StartsWith('<') && text.Contains("<svg", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>The first letters of a name for the tile of a brand without a logo (MatOS: MO, "My Cloud": MC).</summary>
    public static string Letters(string name)
    {
        var words = name.Split([' ', '-', '_', '.'], StringSplitOptions.RemoveEmptyEntries);
        if (words.Length >= 2)
        {
            return string.Concat(words.Take(2).Select(w => char.ToUpperInvariant(w[0])));
        }

        var caps = name.Where(char.IsUpper).Take(2).ToArray();
        if (caps.Length == 2)
        {
            return new string(caps);
        }

        return name.Length == 0 ? "?" : char.ToUpperInvariant(name[0]).ToString();
    }
}
