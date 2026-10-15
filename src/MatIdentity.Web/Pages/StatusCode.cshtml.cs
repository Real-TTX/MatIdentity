using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace MatIdentity.Web.Pages;

/// <summary>
/// The page for an error status (404, 403, ...) so that the browser shows something friendly instead of an empty page. When an app sent a wrong
/// sign-in request (an unknown app, a redirect address that is not registered), OpenIddict answers with a status and this page says what was wrong:
/// the person cannot be sent back to an address that is not registered, so the explanation has to be here.
/// </summary>
[AllowAnonymous]
[IgnoreAntiforgeryToken]
public class StatusCodeModel : PageModel
{
    public string Title { get; private set; } = "Something went wrong";
    public string Message { get; private set; } = "The request could not be processed.";

    /// <summary>The error of the OpenID Connect request (<c>invalid_request: The specified 'redirect_uri' is not valid for this client application.</c>), if it was one.</summary>
    public string? ProtocolError { get; private set; }

    public void OnGet(int? code)
    {
        // The status of the original request stays: this page only explains it.
        (Title, Message) = code switch
        {
            404 => ("Not found", "This page does not exist, or the link no longer works."),
            403 => ("Access denied", "You do not have the permissions to open this page."),
            400 => ("Bad request", "The request was not understood."),
            429 => ("Too many attempts", "Please wait a minute and try again."),
            _ => ("Something went wrong", "The request could not be processed."),
        };

        if (HttpContext.GetOpenIddictServerResponse() is { Error: { } error } response)
        {
            Title = "The app sent a request MatIdentity cannot accept";
            Message = "Ask the administrator to check the app's settings in MatIdentity (its id and its addresses).";
            ProtocolError = string.IsNullOrEmpty(response.ErrorDescription) ? error : $"{error}: {response.ErrorDescription}";
        }
    }
}
