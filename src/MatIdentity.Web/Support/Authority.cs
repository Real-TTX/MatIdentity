using MatIdentity.Core.Configuration;

namespace MatIdentity.Web.Support;

/// <summary>The address the apps reach MatIdentity at (<c>MATIDENTITY_AUTHORITY</c>): the setting, or the address of the request.</summary>
public static class Authority
{
    public static async Task<string> GetAsync(HttpContext http, SystemConfigService config, IConfiguration configuration)
    {
        var issuer = (await config.GetAsync(http.RequestAborted)).Issuer;
        if (string.IsNullOrWhiteSpace(issuer))
        {
            issuer = configuration[$"{MatIdentityOptions.SectionName}:Issuer"];
        }

        return !string.IsNullOrWhiteSpace(issuer)
            ? issuer.TrimEnd('/')
            : $"{http.Request.Scheme}://{http.Request.Host}{http.Request.PathBase}".TrimEnd('/');
    }
}
