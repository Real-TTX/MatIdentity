using System.Net;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Html;

namespace MatIdentity.Web.Support;

/// <summary>Small helpers for the markup of the toolkit: icons and the logo tile.</summary>
public static partial class Ui
{
    [GeneratedRegex("^[a-z0-9-]+$")]
    private static partial Regex NameRegex();

    /// <summary>An icon from the page's inline sprite. The name must exist in <c>matui-icons.svg</c> (a unit test checks the pages).</summary>
    public static IHtmlContent Icon(string name, string? extraClass = null)
    {
        if (!NameRegex().IsMatch(name))
        {
            throw new ArgumentException($"'{name}' is not an icon name.", nameof(name));
        }

        var cls = string.IsNullOrEmpty(extraClass) ? "mat-icon" : $"mat-icon {extraClass}";
        return new HtmlString($"<svg class=\"{cls}\" aria-hidden=\"true\" focusable=\"false\"><use href=\"#mat-i-{name}\"></use></svg>");
    }

    /// <summary>
    /// The logo of MatIdentity in the tile of the toolkit (<c>mat-logo</c>): a flat tile in the accent with one glyph (IDENT-03), the keyhole whose top is a head.
    /// The picture is the whole tile (with its own rounded corners), so the tile of the toolkit shows no colour behind it (<c>mi-logo</c>).
    /// </summary>
    public static IHtmlContent Logo(string size = "md")
        => new HtmlString($"<span class=\"mat-logo mat-logo--{size} mi-logo\" role=\"img\" aria-label=\"{App.Name}\"><img src=\"/img/logo.svg\" alt=\"\" width=\"128\" height=\"128\" /></span>");

    /// <summary>The first letters of a name, for an avatar.</summary>
    public static string Initials(string name)
        => string.Concat(name.Split([' ', '-', '_'], StringSplitOptions.RemoveEmptyEntries).Take(2).Select(p => char.ToUpperInvariant(p[0])));

    /// <summary>
    /// The two letters on the tile of an app: the capitals of its name (MatSplit: MS), else M and the letter after "Mat" (Matdo: MD), else the first two.
    /// </summary>
    public static string AppLetters(string name)
    {
        var caps = name.Where(char.IsUpper).Take(2).ToArray();
        if (caps.Length == 2)
        {
            return new string(caps);
        }

        if (name.Length > 3 && name.StartsWith("Mat", StringComparison.OrdinalIgnoreCase))
        {
            return "M" + char.ToUpperInvariant(name[3]);
        }

        return name.Length == 0 ? "?" : name[..Math.Min(2, name.Length)].ToUpperInvariant();
    }

    /// <summary>A stable hue number (0 to 11) for a name, so the same app always gets the same tint of the accent (<c>mi-hue-N</c>).</summary>
    public static int Hue(string name)
    {
        var hash = 17;
        foreach (var c in name)
        {
            hash = unchecked((hash * 31) + c);
        }

        return Math.Abs(hash % 12);
    }

    /// <summary>Text with the characters of HTML escaped, for the few places that build markup in C#.</summary>
    public static string Encode(string? text) => WebUtility.HtmlEncode(text ?? string.Empty);

    /// <summary>How the toolkit's registry knows MatIdentity (the accent itself comes from <c>data-app</c> in <c>matui.css</c>).</summary>
    public static class App
    {
        public const string Id = "matidentity";
        public const string Name = "MatIdentity";
        public const string Tagline = "Single sign-on for all Mat apps";

        /// <summary>The accent as the toolkit registry has it; it colours the bar of the browser. A unit test compares it with <c>matui.css</c>.</summary>
        public const string Accent = "#a21a50";
    }
}
