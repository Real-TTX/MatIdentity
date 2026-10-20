namespace MatIdentity.Web.Infrastructure;

/// <summary>
/// Whether an address the browser sent (a <c>returnUrl</c>) stays on MatIdentity: the rule of ASP.NET Core's <c>Url.IsLocalUrl</c>, for the places without a page
/// (the passkey endpoints). <c>//evil.example</c> and <c>/\evil.example</c> are other hosts to a browser, so they are not local.
/// </summary>
public static class LocalUrl
{
    public static bool IsLocal(string? url)
    {
        if (string.IsNullOrEmpty(url) || url[0] != '/')
        {
            return false;
        }

        if (url.Length > 1 && (url[1] == '/' || url[1] == '\\'))
        {
            return false;
        }

        return !url.Any(char.IsControl);
    }

    /// <summary><paramref name="url"/> when it is local, else <c>/</c>.</summary>
    public static string OrHome(string? url) => IsLocal(url) ? url! : "/";
}
