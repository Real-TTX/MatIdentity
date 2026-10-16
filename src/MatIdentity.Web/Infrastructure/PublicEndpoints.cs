using OpenIddict.Server;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace MatIdentity.Web.Infrastructure;

/// <summary>
/// With a fixed public address (the issuer), the discovery document names every endpoint under that address, whoever asks and over which way. An app
/// inside Docker reads the document at MatIdentity's internal address (MATIDENTITY_INTERNAL_URL); without this the document would name the internal host,
/// and the app would send the browser there. The app sends its own server-to-server calls to the internal address itself (docs/PLATFORM.md of MatDesign).
/// </summary>
public sealed class PublicEndpoints : IOpenIddictServerHandler<HandleConfigurationRequestContext>
{
    /// <summary>After OpenIddict filled the document from the request, before it is written.</summary>
    public static OpenIddictServerHandlerDescriptor Descriptor { get; }
        = OpenIddictServerHandlerDescriptor.CreateBuilder<HandleConfigurationRequestContext>()
            .UseSingletonHandler<PublicEndpoints>()
            .SetOrder(int.MaxValue - 100_000)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public ValueTask HandleAsync(HandleConfigurationRequestContext context)
    {
        // The issuer is null here when none is configured: then the document keeps the address of the request.
        if (context.Options.Issuer is not { } issuer)
        {
            return ValueTask.CompletedTask;
        }

        context.AuthorizationEndpoint = Rebase(context.AuthorizationEndpoint, issuer);
        context.TokenEndpoint = Rebase(context.TokenEndpoint, issuer);
        context.UserInfoEndpoint = Rebase(context.UserInfoEndpoint, issuer);
        context.EndSessionEndpoint = Rebase(context.EndSessionEndpoint, issuer);
        context.IntrospectionEndpoint = Rebase(context.IntrospectionEndpoint, issuer);
        context.RevocationEndpoint = Rebase(context.RevocationEndpoint, issuer);
        context.JsonWebKeySetEndpoint = Rebase(context.JsonWebKeySetEndpoint, issuer);
        context.DeviceAuthorizationEndpoint = Rebase(context.DeviceAuthorizationEndpoint, issuer);
        context.PushedAuthorizationEndpoint = Rebase(context.PushedAuthorizationEndpoint, issuer);
        return ValueTask.CompletedTask;
    }

    /// <summary>The same path under the issuer (<c>http://internal:2300/connect/token</c> becomes <c>https://id.example.com/connect/token</c>).</summary>
    public static Uri? Rebase(Uri? endpoint, Uri issuer)
        => endpoint is null ? null : new Uri(new Uri(issuer.GetLeftPart(UriPartial.Authority) + "/"), endpoint.PathAndQuery.TrimStart('/'));
}
