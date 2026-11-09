using Microsoft.AspNetCore.Mvc.RazorPages;

namespace MatIdentity.Web.Pages.Connections;

/// <summary>
/// The Connections area (MatDesign docs/PLATFORM.md, "The Connections area"): what MatIdentity offers (<c>identity.oidc</c>: the apps bound to it, by Mattiverse or here by
/// hand, a new secret, remove) and what it uses (<c>mail.smtp</c>). The content is the shared <c>&lt;mat-connections /&gt;</c> of MatPlatform, the same in every Mat app; its
/// forms post to MatPlatform, which makes the clients through <see cref="Platform.IdentityBindings"/>. Administrators only (the folder, and <c>ConnectionsAccess</c> in Program.cs).
/// </summary>
public class IndexModel : PageModel
{
    public void OnGet()
    {
    }
}
