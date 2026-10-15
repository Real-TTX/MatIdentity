using System.ComponentModel.DataAnnotations;
using MatIdentity.Core.Activity;
using MatIdentity.Core.Clients;
using MatIdentity.Core.Configuration;
using MatIdentity.Core.Entities;
using MatIdentity.Web.Support;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace MatIdentity.Web.Pages.Apps;

/// <summary>
/// Adds or changes an app. The secret of a new app (or a renewed one) is shown once, right after the save, on this page itself: it is not
/// stored anywhere in plain text, not even in a cookie for a redirect. With it the page shows the variables the app needs (docs/PLATFORM.md).
/// </summary>
public class EditModel : PageModel
{
    private readonly ClientService _clients;
    private readonly ActivityService _activity;
    private readonly SystemConfigService _config;
    private readonly IConfiguration _configuration;

    public EditModel(ClientService clients, ActivityService activity, SystemConfigService config, IConfiguration configuration)
    {
        _clients = clients;
        _activity = activity;
        _config = config;
        _configuration = configuration;
    }

    [BindProperty]
    public InputModel Input { get; set; } = new();

    /// <summary>The id of the app being edited (from the address); null for a new one.</summary>
    [BindProperty(SupportsGet = true, Name = "id")]
    public string? Id { get; set; }

    public bool IsEdit => !string.IsNullOrEmpty(Id);

    /// <summary>The secret that was made by this request, shown once.</summary>
    public string? NewSecret { get; private set; }

    public string AuthorityUrl { get; private set; } = string.Empty;

    public string? ManagedBy { get; private set; }

    [TempData] public string? StatusMessage { get; set; }
    [TempData] public bool IsError { get; set; }

    public class InputModel
    {
        [Required(ErrorMessage = "Please enter the id of the app.")]
        [Display(Name = "Id")]
        public string ClientId { get; set; } = string.Empty;

        [Required(ErrorMessage = "Please enter a name.")]
        [StringLength(100)]
        [Display(Name = "Name")]
        public string DisplayName { get; set; } = string.Empty;

        [Display(Name = "Address")]
        public string? HomeUrl { get; set; }

        public bool AllowSignIn { get; set; } = true;

        public bool AllowMachine { get; set; }

        public bool IsPublic { get; set; }

        [Display(Name = "Sign-in addresses")]
        public string? RedirectUris { get; set; }

        [Display(Name = "Addresses after sign-out")]
        public string? PostLogoutRedirectUris { get; set; }
    }

    public async Task<IActionResult> OnGetAsync()
    {
        AuthorityUrl = await Authority.GetAsync(HttpContext, _config, _configuration);
        if (!IsEdit)
        {
            return Page();
        }

        var client = await _clients.GetAsync(Id!, HttpContext.RequestAborted);
        if (client is null)
        {
            return NotFound();
        }

        Fill(client);
        return Page();
    }

    public async Task<IActionResult> OnPostAsync()
    {
        AuthorityUrl = await Authority.GetAsync(HttpContext, _config, _configuration);
        var existing = IsEdit ? await _clients.GetAsync(Id!, HttpContext.RequestAborted) : null;
        if (IsEdit && existing is null)
        {
            return NotFound();
        }

        if (!IsEdit && await _clients.GetAsync(Input.ClientId.Trim(), HttpContext.RequestAborted) is not null)
        {
            ModelState.AddModelError("Input.ClientId", "An app with this id exists already.");
        }

        if (!ModelState.IsValid)
        {
            ManagedBy = existing?.ManagedBy;
            return Page();
        }

        var result = await _clients.SaveAsync(new ClientInfo
        {
            ClientId = existing?.ClientId ?? Input.ClientId,
            DisplayName = Input.DisplayName,
            HomeUrl = Input.HomeUrl,
            AllowSignIn = Input.AllowSignIn,
            AllowMachine = Input.AllowMachine,
            IsPublic = existing?.IsPublic ?? Input.IsPublic,
            RedirectUris = Input.AllowSignIn ? ClientRules.SplitUris(Input.RedirectUris) : [],
            PostLogoutRedirectUris = Input.AllowSignIn ? ClientRules.SplitUris(Input.PostLogoutRedirectUris) : [],
            ManagedBy = existing?.ManagedBy,
        }, renewSecret: false, HttpContext.RequestAborted);

        if (!result.Succeeded)
        {
            foreach (var (field, message) in result.Errors)
            {
                ModelState.AddModelError("Input." + char.ToUpperInvariant(field[0]) + field[1..], message);
            }

            ManagedBy = existing?.ManagedBy;
            return Page();
        }

        await _activity.WriteAsync(existing is null ? ActivityKind.ClientCreated : ActivityKind.ClientChanged, username: User.GetUsername(),
            clientId: result.Client!.ClientId, ipAddress: HttpContext.Connection.RemoteIpAddress?.ToString(), ct: HttpContext.RequestAborted);

        if (result.Secret is not null)
        {
            // A new app: its secret now, once.
            Id = result.Client.ClientId;
            Fill(result.Client);
            NewSecret = result.Secret;
            return Page();
        }

        StatusMessage = "App saved.";
        return RedirectToPage("/Apps/Index");
    }

    public async Task<IActionResult> OnPostRenewSecretAsync()
    {
        AuthorityUrl = await Authority.GetAsync(HttpContext, _config, _configuration);
        var client = IsEdit ? await _clients.GetAsync(Id!, HttpContext.RequestAborted) : null;
        var secret = client is null ? null : await _clients.RenewSecretAsync(client.ClientId, HttpContext.RequestAborted);
        if (client is null || secret is null)
        {
            StatusMessage = "This app has no secret.";
            IsError = true;
            return RedirectToPage("/Apps/Index");
        }

        await _activity.WriteAsync(ActivityKind.ClientSecretRenewed, username: User.GetUsername(), clientId: client.ClientId,
            ipAddress: HttpContext.Connection.RemoteIpAddress?.ToString(), ct: HttpContext.RequestAborted);
        ModelState.Clear();
        Fill(client);
        NewSecret = secret;
        return Page();
    }

    /// <summary>The address an app receives the sign-in at, as most OpenID Connect libraries choose it (ASP.NET Core: /signin-oidc).</summary>
    public static string SuggestedRedirect(string? homeUrl)
        => string.IsNullOrWhiteSpace(homeUrl) ? "https://app.example.com/signin-oidc" : homeUrl.TrimEnd('/') + "/signin-oidc";

    private void Fill(ClientInfo client)
    {
        ManagedBy = client.ManagedBy;
        Input = new InputModel
        {
            ClientId = client.ClientId,
            DisplayName = client.DisplayName,
            HomeUrl = client.HomeUrl,
            AllowSignIn = client.AllowSignIn,
            AllowMachine = client.AllowMachine,
            IsPublic = client.IsPublic,
            RedirectUris = string.Join('\n', client.RedirectUris),
            PostLogoutRedirectUris = string.Join('\n', client.PostLogoutRedirectUris),
        };
    }
}
