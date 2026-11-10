using MatIdentity.Core.Access;
using MatIdentity.Core.Activity;
using MatIdentity.Core.Clients;
using MatIdentity.Core.Configuration;
using MatIdentity.Core.Entities;
using MatIdentity.Web.Infrastructure;
using MatIdentity.Web.Support;
using MatPlatform;

namespace MatIdentity.Web.Platform;

/// <summary>
/// The bindings of <c>identity.oidc</c> (MatDesign docs/PLATFORM.md, "<c>identity.oidc</c> (version 1)") for MatPlatform: the broker endpoints <c>/api/bindings</c> and the
/// Connections area. A binding is an OpenID Connect client of the consumer, made the one way every managed app is made (<see cref="ClientService.UpsertAsync"/> and
/// <see cref="ClientService.RemoveManagedAsync"/>, as <c>/api/v1/clients</c> does); this class only translates.
/// <list type="bullet">
/// <item>The client id is the consumer id (<c>-app</c> added when it is shorter than two characters), the name the consumer's, <c>managedBy</c> as the request says.</item>
/// <item>For every public address of the consumer: <c>&lt;address&gt;&lt;callback&gt;</c> to sign in and <c>&lt;address&gt;&lt;signedOut&gt;</c> after signing out; the first
/// address is its home. The back-channel logout goes to the internal address (<c>&lt;internalUrl&gt;&lt;backchannel&gt;</c>, server to server); none without one or with an
/// empty <c>backchannel</c>. A request without any address (a new key from the Connections area) keeps what the client has.</item>
/// <item>The roles are read from the consumer's <c>/api</c> (<see cref="AppRolesReader"/>); when it cannot be read the client keeps its roles.</item>
/// <item>A secret is made when the client is new or the request renews it, and handed out only then.</item>
/// </list>
/// Listed are the clients that carry a mark (<c>managedBy</c>): those made by bindings and by <c>/api/v1</c> with a mark. An app added under Apps has none: it is no binding,
/// so it is neither listed nor removed here.
/// </summary>
public sealed class IdentityBindings(
    ClientService clients,
    PermissionService permissions,
    ActivityService activity,
    SystemConfigService config,
    IConfiguration configuration,
    AppRolesReader rolesReader,
    IHttpContextAccessor http) : IMatBindingHandler
{
    public const string CallbackParam = "callback";
    public const string SignedOutParam = "signedOut";
    public const string BackchannelParam = "backchannel";

    public const string DefaultCallback = "/signin-oidc";
    public const string DefaultSignedOut = "/signout-callback-oidc";
    public const string DefaultBackchannel = "/signout-backchannel";

    public string Capability => MatCapabilities.IdentityOidc;

    /// <summary>The client id of a consumer: its id, with <c>-app</c> when it is shorter than two characters (a client id has at least two).</summary>
    public static string ClientIdOf(string consumer) => consumer.Length >= 2 ? consumer : consumer + "-app";

    public async Task<IReadOnlyList<MatBindingInfo>> ListAsync(CancellationToken ct)
    {
        var managed = (await clients.GetAllAsync(ct)).Where(c => !string.IsNullOrEmpty(c.ManagedBy)).ToList();
        var ids = managed.Select(c => c.ClientId).ToList();
        var since = await permissions.RegisteredAsync(ids, ct);
        var used = await activity.LastTokenAsync(ids, ct);
        return [.. managed.Select(c => new MatBindingInfo(Capability, c.ClientId, c.DisplayName, c.ManagedBy!,
            since.TryGetValue(c.ClientId, out var first) ? Utc(first) : null,
            used.TryGetValue(c.ClientId, out var last) ? Utc(last) : null))];
    }

    public async Task<MatBindResult> BindAsync(MatBindRequest request, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(request);
        var clientId = ClientIdOf(request.Consumer.Id);
        var addresses = request.Consumer.Addresses();
        var internalUrl = string.IsNullOrWhiteSpace(request.Consumer.InternalUrl) ? null : request.Consumer.InternalUrl.Trim().TrimEnd('/');
        var callback = PathOf(request.Param(CallbackParam, DefaultCallback));
        var signedOut = PathOf(request.Param(SignedOutParam, DefaultSignedOut));
        // An empty backchannel means none (Param would give the default for it).
        var backchannel = request.Params.TryGetValue(BackchannelParam, out var given) ? given?.Trim() ?? string.Empty : DefaultBackchannel;

        // The roles, permissions and quotas the consumer names in its /api, read where MatIdentity reaches it (the shared network first). Roles it cannot use
        // leave the client's as they are, and so does an /api that cannot be read or that names permissions or quotas MatIdentity cannot keep.
        var catalog = internalUrl is not null || addresses.Count > 0
            ? await rolesReader.ReadCatalogAsync(internalUrl ?? addresses[0], ct)
            : new AppCatalogRead(null, [], [], "The app has no address to ask.");
        var roles = catalog.Roles;
        if (roles is not null && PermissionService.ValidateRoles(roles).Count > 0)
        {
            roles = null;
        }

        var catalogUsable = catalog.Succeeded && PermissionService.ValidateCatalog(catalog.Permissions, catalog.Quotas).Count == 0;

        var name = string.IsNullOrWhiteSpace(request.Consumer.Name) ? clientId : request.Consumer.Name.Trim();
        var upsert = new ClientUpsert
        {
            ClientId = clientId,
            DisplayName = name.Length > 100 ? name[..100].Trim() : name,
            // Without an address (a new key from the Connections area) the client keeps its addresses; with them it gets exactly these.
            HomeUrl = addresses.Count > 0 ? addresses[0] : null,
            RedirectUris = addresses.Count > 0 ? [.. addresses.Select(a => a + callback)] : null,
            PostLogoutRedirectUris = addresses.Count > 0 ? [.. addresses.Select(a => a + signedOut)] : null,
            BackchannelLogoutUri = internalUrl is not null ? (backchannel.Length == 0 ? string.Empty : internalUrl + PathOf(backchannel))
                : addresses.Count > 0 ? string.Empty
                : null,
            AllowSignIn = true,
            ManagedBy = request.ManagedBy,
            RenewSecret = request.Renew,
            Roles = roles,
            Permissions = catalogUsable ? catalog.Permissions : null,
            Quotas = catalogUsable ? catalog.Quotas : null,
        };

        var (saved, created) = await clients.UpsertAsync(upsert, ct);
        if (!saved.Succeeded)
        {
            // A refusal (MatPlatform 2.2.0): 400 with the reason for a broker, the message in the Connections area; never a 500.
            var (key, message) = saved.Errors.First();
            throw new MatBindingRefusedException(string.IsNullOrEmpty(key) ? "client" : key, $"The app \"{clientId}\" cannot be saved: {message}");
        }

        await WriteAsync(created ? ActivityKind.ClientCreated : saved.Secret is null ? ActivityKind.ClientChanged : ActivityKind.ClientSecretRenewed, clientId, request.ManagedBy, ct);
        return new MatBindResult(new Dictionary<string, string?>
        {
            // The issuer of the tokens: the public address of MatIdentity, else the address the broker (or the request) names.
            ["authority"] = await Authority.PublicAsync(config, configuration, ct) ?? request.Provider.Url?.TrimEnd('/'),
            ["internalUrl"] = request.Provider.InternalUrl,
            ["clientId"] = clientId,
            ["clientSecret"] = saved.Secret,
        });
    }

    public async Task<bool> UnbindAsync(string consumer, string? managedBy, CancellationToken ct)
    {
        var clientId = ClientIdOf(consumer);
        // A client without a mark is no binding (an app added under Apps).
        if (await clients.GetAsync(clientId, ct) is not { ManagedBy: { Length: > 0 } } || await clients.RemoveManagedAsync(clientId, managedBy, ct) != ClientRemoval.Removed)
        {
            return false;
        }

        await WriteAsync(ActivityKind.ClientDeleted, clientId, managedBy, ct);
        return true;
    }

    /// <summary>The activity list: who asked (the person in the Connections area, else the caller of <c>/api/bindings</c>) and through what.</summary>
    private Task WriteAsync(ActivityKind kind, string clientId, string? managedBy, CancellationToken ct)
    {
        var context = http.HttpContext;
        var who = context?.User.Identity?.IsAuthenticated == true ? context.User.GetUsername() : context is null ? null : MatApiAccess.CallerOf(context, managedBy ?? "api");
        return activity.WriteAsync(kind, username: who, clientId: clientId, ipAddress: context?.Connection.RemoteIpAddress?.ToString(),
            detail: $"Through the binding of {MatCapabilities.IdentityOidc}" + (managedBy is null ? string.Empty : $" ({managedBy})"), ct: ct);
    }

    /// <summary>A path of a parameter, with one leading slash.</summary>
    private static string PathOf(string path) => "/" + path.Trim().TrimStart('/');

    private static DateTimeOffset Utc(DateTime time) => new(DateTime.SpecifyKind(time, DateTimeKind.Utc));
}
