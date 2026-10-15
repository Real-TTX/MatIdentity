using System.Net;
using System.Text.Json;
using MatIdentity.Core;
using MatIdentity.Core.Configuration;
using MatIdentity.Core.Data;
using MatIdentity.Core.Entities;
using MatIdentity.Web.Platform;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.StaticFiles;
using Microsoft.EntityFrameworkCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

// "docker HEALTHCHECK": the image has no curl, so the app checks itself and exits with 0 (healthy) or 1.
if (args.Contains("--healthcheck"))
{
    return await HealthCheck.RunAsync();
}

var builder = WebApplication.CreateBuilder(args);

// ---------------------------------------------------------------------------
// Configuration / options
// ---------------------------------------------------------------------------
builder.Services.Configure<MatIdentityOptions>(builder.Configuration.GetSection(MatIdentityOptions.SectionName));

// The key of the platform API has the same name in every app of the family (docs/PLATFORM.md): MAT_API_KEY.
var apiKey = builder.Configuration["MAT_API_KEY"];
builder.Services.PostConfigure<MatIdentityOptions>(options => options.ApiKey = string.IsNullOrWhiteSpace(options.ApiKey) ? apiKey : options.ApiKey);

// Resolve the data directory before the container is built (needed for keys + SQLite path).
// In Docker the Dockerfile sets MatIdentity__DataPath=/data; local runs fall back to App_Data.
var configuredDataPath = builder.Configuration[$"{MatIdentityOptions.SectionName}:DataPath"];
var dataPath = !string.IsNullOrWhiteSpace(configuredDataPath)
    ? configuredDataPath
    : Path.Combine(builder.Environment.ContentRootPath, "App_Data");

var appPaths = new AppPaths(dataPath);
appPaths.EnsureCreated();
builder.Services.AddSingleton(appPaths);
builder.Services.PostConfigure<MatIdentityOptions>(options => options.DataPath = dataPath);

// What OpenIddict needs at start: the issuer and the lifetime of an access token (settings of the UI; a change takes effect after a restart).
var startConfig = ReadSystemConfig(appPaths);
var issuer = !string.IsNullOrWhiteSpace(startConfig.Issuer) ? startConfig.Issuer : builder.Configuration[$"{MatIdentityOptions.SectionName}:Issuer"];
var tokenKeys = TokenKeys.LoadOrCreate(appPaths.TokenKeysPath);

// ---------------------------------------------------------------------------
// Infrastructure services
// ---------------------------------------------------------------------------

// Data Protection keys live on the mounted volume so cookies and protected secrets survive restarts.
builder.Services.AddDataProtection()
    .SetApplicationName("MatIdentity")
    .PersistKeysToFileSystem(new DirectoryInfo(appPaths.KeysPath));

builder.Services.AddDbContext<MatIdentityDbContext>(options =>
{
    options.UseSqlite(appPaths.SqliteConnectionString);
    options.UseOpenIddict<long>();
});

builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<ICurrentUserAccessor, HttpCurrentUserAccessor>();
builder.Services.AddSingleton<SetupState>();
builder.Services.AddSingleton<MatIdentity.Web.Support.Toolkit>();
builder.Services.AddSingleton<ApiAccess>();
builder.Services.AddScoped<IMatPlatformApp, IdentityPlatform>();
builder.Services.AddHttpClient();
builder.Services.AddScoped<AppRolesReader>();
builder.Services.AddMatIdentityCore();
builder.Services.AddMatIdentityRateLimits();

// X-Forwarded-* only from a proxy that is known (an identity server must not let anyone choose the address it limits and logs):
// MatIdentity__TrustedProxies (addresses or networks, separated by commas), else loopback and the private networks a Docker proxy sits in.
builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto | ForwardedHeaders.XForwardedHost;
    options.KnownIPNetworks.Clear();
    options.KnownProxies.Clear();
    var trusted = builder.Configuration[$"{MatIdentityOptions.SectionName}:TrustedProxies"];
    var networks = string.IsNullOrWhiteSpace(trusted) ? ["127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"] : trusted.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    foreach (var network in networks)
    {
        options.KnownIPNetworks.Add(System.Net.IPNetwork.Parse(network.Contains('/') ? network : network + (IPAddress.Parse(network).AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? "/128" : "/32")));
    }
});

// ---------------------------------------------------------------------------
// OpenID Connect: OpenIddict as the server, its own validation for the platform API
// ---------------------------------------------------------------------------
builder.Services.AddOpenIddict()
    .AddCore(options => options.UseEntityFrameworkCore().UseDbContext<MatIdentityDbContext>().ReplaceDefaultEntities<long>())
    .AddServer(options =>
    {
        options.SetAuthorizationEndpointUris("connect/authorize")
            .SetTokenEndpointUris("connect/token")
            .SetUserInfoEndpointUris("connect/userinfo")
            .SetEndSessionEndpointUris("connect/logout")
            .SetIntrospectionEndpointUris("connect/introspect")
            .SetRevocationEndpointUris("connect/revoke")
            .SetJsonWebKeySetEndpointUris(".well-known/jwks");

        options.AllowAuthorizationCodeFlow()
            .AllowRefreshTokenFlow()
            .AllowClientCredentialsFlow()
            .RequireProofKeyForCodeExchange();

        // The app scopes (app:<id>) are in the database; OpenIddict finds them there.
        options.RegisterScopes(Scopes.OpenId, Scopes.Profile, Scopes.Email, Scopes.Roles, Scopes.OfflineAccess);

        options.AddSigningKey(tokenKeys.Signing)
            .AddEncryptionKey(tokenKeys.Encryption);

        // The apps validate access tokens themselves with the published keys: signed, not encrypted.
        options.DisableAccessTokenEncryption();
        options.SetAccessTokenLifetime(TimeSpan.FromMinutes(Math.Clamp(startConfig.AccessTokenMinutes, SystemConfigService.MinTokenMinutes, SystemConfigService.MaxTokenMinutes)));

        if (!string.IsNullOrWhiteSpace(issuer) && SystemConfigService.IsValidIssuer(issuer))
        {
            options.SetIssuer(new Uri(issuer.TrimEnd('/') + "/"));
        }

        options.UseAspNetCore()
            .EnableAuthorizationEndpointPassthrough()
            .EnableTokenEndpointPassthrough()
            .EnableUserInfoEndpointPassthrough()
            .EnableEndSessionEndpointPassthrough()
            .EnableStatusCodePagesIntegration()
            // The container speaks http; TLS ends at the reverse proxy in front of it.
            .DisableTransportSecurityRequirement();
    })
    .AddValidation(options =>
    {
        options.UseLocalServer();
        options.AddAudiences(MatIdentity.Core.Clients.ClientRules.SelfId);
        options.UseAspNetCore();
    });

// ---------------------------------------------------------------------------
// Authentication / authorization of the pages: a cookie that carries a session token (the session lives in SQLite)
// ---------------------------------------------------------------------------
builder.Services.AddAuthentication(AuthConstants.CookieScheme)
    .AddCookie(AuthConstants.CookieScheme, options =>
    {
        options.Cookie.Name = "matidentity.auth";
        options.Cookie.HttpOnly = true;
        // Lax: the cookie comes along when an app sends the person here (a top-level navigation), so single sign-on works.
        options.Cookie.SameSite = SameSiteMode.Lax;
        options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
        options.LoginPath = "/Account/Login";
        options.LogoutPath = "/Account/Logout";
        options.AccessDeniedPath = "/Account/AccessDenied";
        // The session in the database decides how long a sign-in lasts (SystemConfig.SessionLifetimeDays); the cookie only has to outlive it.
        options.ExpireTimeSpan = TimeSpan.FromDays(SystemConfigService.MaxSessionDays);
        options.SlidingExpiration = true;
        options.Events.OnValidatePrincipal = SessionValidation.ValidateAsync;
    });

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AdminOnly", policy => policy.RequireRole(nameof(UserRole.Admin)));
    // Backstop: any endpoint without an explicit policy still requires an authenticated user.
    options.FallbackPolicy = new Microsoft.AspNetCore.Authorization.AuthorizationPolicyBuilder()
        .RequireAuthenticatedUser()
        .Build();
});

// ---------------------------------------------------------------------------
// Razor Pages (secure by default; open only what is needed before login)
// ---------------------------------------------------------------------------
builder.Services.AddRazorPages(options =>
{
    options.Conventions.AuthorizeFolder("/");
    options.Conventions.AllowAnonymousToPage("/Setup");
    options.Conventions.AllowAnonymousToPage("/Account/Login");
    options.Conventions.AllowAnonymousToPage("/Account/Logout");
    options.Conventions.AllowAnonymousToPage("/Account/AccessDenied");
    options.Conventions.AllowAnonymousToPage("/Error");
    options.Conventions.AllowAnonymousToPage("/StatusCode");

    foreach (var folder in new[] { "/Apps", "/Users", "/Groups", "/Activity", "/Settings" })
    {
        options.Conventions.AuthorizeFolder(folder, "AdminOnly");
    }
});

var app = builder.Build();

// ---------------------------------------------------------------------------
// HTTP pipeline
// ---------------------------------------------------------------------------
app.UseForwardedHeaders();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
}

var staticContentTypes = new FileExtensionContentTypeProvider();
staticContentTypes.Mappings[".webmanifest"] = "application/manifest+json";
app.UseStaticFiles(new StaticFileOptions { ContentTypeProvider = staticContentTypes });
// A 404 or 403 (and an error of the OpenID Connect protocol) shows a page of the app with the original status code.
app.UseStatusCodePagesWithReExecute("/StatusCode/{0}");
app.UseRouting();
app.UseRateLimiter();
app.UseAuthentication();
// First run: redirect everything to /Setup until an administrator exists.
app.UseMiddleware<SetupGuardMiddleware>();
app.UseMiddleware<PasswordChangeGuardMiddleware>();
app.UseAuthorization();
app.MapRazorPages();

app.MapOidcEndpoints();
app.MapMatPlatform(ApiAccess.RequireAsync, RateLimits.Api);
app.MapClientApi();
app.MapThemeApi();

// ---------------------------------------------------------------------------
// Database migration + first-run seed
// ---------------------------------------------------------------------------
await DbBootstrapper.InitializeAsync(app.Services, app.Logger);

app.Run();
return 0;

// The settings file as it is at start (the store is not built yet); a broken file means the defaults, the store keeps a copy of it later.
static SystemConfig ReadSystemConfig(AppPaths paths)
{
    var file = Path.Combine(paths.ConfigPath, SystemConfig.FileName + ".json");
    try
    {
        return File.Exists(file) ? JsonSerializer.Deserialize<SystemConfig>(File.ReadAllText(file), JsonConfigStore.JsonOptions) ?? new() : new();
    }
    catch (JsonException)
    {
        return new();
    }
}

/// <summary>The entry point, visible to the tests (WebApplicationFactory).</summary>
public partial class Program;
