using MatIdentity.Core.Configuration;

namespace MatIdentity.Web.Support;

/// <summary>The address the apps reach MatIdentity at (<c>MATIDENTITY_AUTHORITY</c>): the setting, or the address of the request.</summary>
public static class Authority
{
    /// <summary>
    /// The public address when it is set (Settings or <c>MatIdentity__Issuer</c>), else null. Links in mails that anybody can ask for ("Forgot your password?")
    /// use only this: the address of a request is the Host header, which the one who asks chooses.
    /// </summary>
    public static Task<string?> PublicAsync(HttpContext http, SystemConfigService config, IConfiguration configuration)
        => PublicAsync(config, configuration, http.RequestAborted);

    /// <summary>The public address when it is set (Settings or <c>MatIdentity__Issuer</c>), else null; without a request (a binding of <c>identity.oidc</c>).</summary>
    public static async Task<string?> PublicAsync(SystemConfigService config, IConfiguration configuration, CancellationToken ct)
    {
        var issuer = (await config.GetAsync(ct)).Issuer;
        if (string.IsNullOrWhiteSpace(issuer))
        {
            issuer = configuration[$"{MatIdentityOptions.SectionName}:Issuer"];
        }

        return string.IsNullOrWhiteSpace(issuer) ? null : issuer.Trim().TrimEnd('/');
    }

    public static async Task<string> GetAsync(HttpContext http, SystemConfigService config, IConfiguration configuration)
        => await PublicAsync(config, configuration, http.RequestAborted)
           ?? $"{http.Request.Scheme}://{http.Request.Host}{http.Request.PathBase}".TrimEnd('/');
}
