using OpenIddict.Abstractions;
using OpenIddict.Server;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace MatIdentity.Web.Infrastructure;

/// <summary>
/// With a fixed public address (the issuer), the discovery document names every endpoint under that address, whoever asks and over which way. An app
/// inside Docker reads the document at MatIdentity's internal address (MATIDENTITY_INTERNAL_URL); without this the document would name the internal host,
/// and the app would send the browser there. The app sends its own server-to-server calls to the internal address itself (docs/PLATFORM.md of MatDesign).
/// It works on the finished answer, because OpenIddict fills the endpoints from the request late.
/// </summary>
public sealed class PublicEndpoints : IOpenIddictServerHandler<ApplyConfigurationResponseContext>
{
    /// <summary>The members of the discovery document that are addresses of MatIdentity.</summary>
    private static readonly string[] EndpointMembers =
    [
        "authorization_endpoint", "token_endpoint", "userinfo_endpoint", "end_session_endpoint", "introspection_endpoint",
        "revocation_endpoint", "jwks_uri", "device_authorization_endpoint", "pushed_authorization_request_endpoint",
    ];

    /// <summary>Before the answer is written.</summary>
    public static OpenIddictServerHandlerDescriptor Descriptor { get; }
        = OpenIddictServerHandlerDescriptor.CreateBuilder<ApplyConfigurationResponseContext>()
            .UseSingletonHandler<PublicEndpoints>()
            .SetOrder(int.MinValue + 100_000)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public ValueTask HandleAsync(ApplyConfigurationResponseContext context)
    {
        // Without a configured issuer the document keeps the address of the request; an error answer has no endpoints.
        if (context.Options.Issuer is not { } issuer || !string.IsNullOrEmpty(context.Response.Error))
        {
            return ValueTask.CompletedTask;
        }

        foreach (var member in EndpointMembers)
        {
            if ((string?)context.Response[member] is { } value && Uri.TryCreate(value, UriKind.Absolute, out var endpoint))
            {
                context.Response[member] = Rebase(endpoint, issuer)!.AbsoluteUri;
            }
        }

        return ValueTask.CompletedTask;
    }

    /// <summary>The same path under the issuer (<c>http://internal:2300/connect/token</c> becomes <c>https://id.example.com/connect/token</c>).</summary>
    public static Uri? Rebase(Uri? endpoint, Uri issuer)
        => endpoint is null ? null : new Uri(new Uri(issuer.GetLeftPart(UriPartial.Authority) + "/"), endpoint.PathAndQuery.TrimStart('/'));
}
