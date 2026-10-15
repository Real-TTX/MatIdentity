namespace MatIdentity.Web.Support;

/// <summary>Small formatting helpers for the pages: relative times and dates.</summary>
public static class Format
{
    /// <summary>"just now", "5 min ago", "3 h ago", "2 days ago", or a date for older values.</summary>
    public static string Ago(DateTime utc, DateTime? now = null)
    {
        var span = (now ?? DateTime.UtcNow) - utc;
        if (span < TimeSpan.Zero)
        {
            span = TimeSpan.Zero;
        }

        return span.TotalSeconds < 45 ? "just now"
            : span.TotalMinutes < 90 ? $"{Math.Max(1, (int)Math.Round(span.TotalMinutes))} min ago"
            : span.TotalHours < 36 ? $"{(int)Math.Round(span.TotalHours)} h ago"
            : span.TotalDays < 14 ? $"{(int)Math.Round(span.TotalDays)} days ago"
            : utc.ToLocalTime().ToString("yyyy-MM-dd");
    }

    public static string DateTimeLocal(DateTime utc) => utc.ToLocalTime().ToString("yyyy-MM-dd HH:mm");

    /// <summary>A short description of a browser from its user agent ("Edge on Windows"), for the list of sessions.</summary>
    public static string Browser(string? userAgent)
    {
        if (string.IsNullOrWhiteSpace(userAgent))
        {
            return "Unknown device";
        }

        var browser = userAgent.Contains("Edg/") ? "Edge"
            : userAgent.Contains("Firefox/") ? "Firefox"
            : userAgent.Contains("Chrome/") ? "Chrome"
            : userAgent.Contains("Safari/") ? "Safari"
            : "A browser";
        var system = userAgent.Contains("Windows") ? "Windows"
            : userAgent.Contains("Android") ? "Android"
            : userAgent.Contains("iPhone") || userAgent.Contains("iPad") ? "iOS"
            : userAgent.Contains("Mac OS") ? "macOS"
            : userAgent.Contains("Linux") ? "Linux"
            : null;
        return system is null ? browser : $"{browser} on {system}";
    }
}
