using MatIdentity.Core.Clients;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace MatIdentity.Web.Pages.Account;

/// <summary>
/// Where <c>/connect/authorize</c> sends a person who may not use the app. The person is not sent back to the app: it would only show an error
/// of its own, and here the person learns why and what to do.
/// </summary>
public class NoAccessModel : PageModel
{
    private readonly ClientService _clients;

    public NoAccessModel(ClientService clients)
    {
        _clients = clients;
    }

    public string AppName { get; private set; } = "this app";

    public async Task OnGetAsync(string? app)
    {
        if (!string.IsNullOrEmpty(app) && await _clients.GetAsync(app, HttpContext.RequestAborted) is { } client)
        {
            AppName = client.DisplayName;
        }
    }
}
