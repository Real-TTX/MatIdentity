using System.Security.Cryptography;
using System.Text;
using Fido2NetLib;
using Fido2NetLib.Objects;
using MatIdentity.Core.Activity;
using MatIdentity.Core.Auth;
using MatIdentity.Core.Configuration;
using MatIdentity.Core.Entities;
using MatIdentity.Core.Users;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.Extensions.Caching.Memory;

namespace MatIdentity.Web.Infrastructure;

/// <summary>
/// Passkeys (WebAuthn) through Fido2NetLib: adding one to the account, signing in with one alone (a discoverable credential, no user name, no password),
/// and using one as the second step after the password. The browser part is <c>wwwroot/js/matidentity.js</c>. The options of a ceremony are kept on the
/// server for two minutes under a random id, so the challenge cannot be chosen by the browser. User verification (fingerprint, face, PIN) is required:
/// a passkey alone is two factors.
/// <code>
/// POST /api/passkeys/register/options   (signed in)  { }                         -> { id, options }
/// POST /api/passkeys/register           (signed in)  { id, name, response }      -> 204
/// POST /api/passkeys/signin/options                  { mode: "passkey" | "second-step" } -> { id, options }
/// POST /api/passkeys/signin                          { id, response, returnUrl }  -> { redirect }
/// </code>
/// </summary>
public static class PasskeyEndpoints
{
    private static readonly TimeSpan CeremonyLifetime = TimeSpan.FromMinutes(2);

    public static void MapPasskeyEndpoints(this WebApplication app)
    {
        var group = app.MapGroup("/api/passkeys").DisableAntiforgery().RequireRateLimiting(RateLimits.SignIn);
        group.MapPost("/register/options", RegisterOptionsAsync).RequireAuthorization();
        group.MapPost("/register", RegisterAsync).RequireAuthorization();
        group.MapPost("/signin/options", SignInOptionsAsync).AllowAnonymous();
        group.MapPost("/signin", SignInAsync).AllowAnonymous();
    }

    private static async Task<IResult> RegisterOptionsAsync(HttpContext http, IAntiforgery antiforgery, UserService users, PasskeyService passkeys, IMemoryCache cache)
    {
        if (!await ValidAntiforgeryAsync(http, antiforgery) || http.User.GetUserId() is not { } id || await users.GetAsync(id, http.RequestAborted) is not { } user)
        {
            return Results.BadRequest();
        }

        var existing = await passkeys.CredentialIdsAsync(user.Id, http.RequestAborted);
        var options = (await CreateFido2Async(http)).RequestNewCredential(new RequestNewCredentialParams
        {
            User = new Fido2User { Id = Encoding.UTF8.GetBytes(user.Subject), Name = user.Username, DisplayName = user.DisplayName },
            ExcludeCredentials = existing.Select(c => new PublicKeyCredentialDescriptor(B64.Decode(c))).ToList(),
            AuthenticatorSelection = new AuthenticatorSelection
            {
                ResidentKey = ResidentKeyRequirement.Required,
                UserVerification = UserVerificationRequirement.Required,
            },
            AttestationPreference = AttestationConveyancePreference.None,
        });

        var ceremony = Remember(cache, "register", user.Id, options.ToJson());
        return Results.Content($"{{\"id\":\"{ceremony}\",\"options\":{options.ToJson()}}}", "application/json");
    }

    private static async Task<IResult> RegisterAsync(HttpContext http, IAntiforgery antiforgery, RegisterBody body, UserService users, PasskeyService passkeys, IMemoryCache cache)
    {
        if (!await ValidAntiforgeryAsync(http, antiforgery) || http.User.GetUserId() is not { } id || await users.GetAsync(id, http.RequestAborted) is not { } user
            || Recall(cache, "register", body.Id) is not { UserId: var owner, Json: var json } || owner != user.Id)
        {
            return Problem("The request was too old or not yours. Try again.");
        }

        try
        {
            var credential = await (await CreateFido2Async(http)).MakeNewCredentialAsync(new MakeNewCredentialParams
            {
                AttestationResponse = body.Response,
                OriginalOptions = CredentialCreateOptions.FromJson(json),
                IsCredentialIdUniqueToUserCallback = async (args, ct) => !await passkeys.ExistsAsync(B64.Encode(args.CredentialId), ct),
            }, http.RequestAborted);

            await passkeys.AddAsync(user.Id, B64.Encode(credential.Id), credential.PublicKey, credential.SignCount, credential.AaGuid,
                string.IsNullOrWhiteSpace(body.Name) ? MatIdentity.Web.Support.Format.Browser(http.Request.Headers.UserAgent) : body.Name.Trim()[..Math.Min(100, body.Name.Trim().Length)], http.RequestAborted);
            return Results.NoContent();
        }
        catch (Fido2VerificationException ex)
        {
            return Problem("The passkey could not be checked: " + ex.Message);
        }
    }

    private static async Task<IResult> SignInOptionsAsync(HttpContext http, SignInOptionsBody body, PasskeyService passkeys, IMemoryCache cache)
    {
        long? userId = null;
        var allowed = new List<PublicKeyCredentialDescriptor>();
        if (body.Mode == "second-step")
        {
            // After the password: only the passkeys of that person.
            if (await SignInFlow.PendingAsync(http) is not { } pending)
            {
                return Problem("Sign in with your password first.");
            }

            userId = pending.UserId;
            var ids = await passkeys.CredentialIdsAsync(pending.UserId, http.RequestAborted);
            allowed.AddRange(ids.Select(c => new PublicKeyCredentialDescriptor(B64.Decode(c))));
        }

        // Passkey alone: no list, the device offers the passkeys it has for this site.
        var options = (await CreateFido2Async(http)).GetAssertionOptions(new GetAssertionOptionsParams
        {
            AllowedCredentials = allowed,
            UserVerification = UserVerificationRequirement.Required,
        });

        var ceremony = Remember(cache, "signin", userId ?? 0, options.ToJson());
        return Results.Content($"{{\"id\":\"{ceremony}\",\"options\":{options.ToJson()}}}", "application/json");
    }

    private static async Task<IResult> SignInAsync(HttpContext http, SignInBody body, PasskeyService passkeys, IMemoryCache cache, ActivityService activity)
    {
        if (Recall(cache, "signin", body.Id) is not { UserId: var expectedUser, Json: var json })
        {
            return Problem("The request was too old. Try again.");
        }

        var credentialId = B64.Encode(body.Response.RawId);
        var passkey = await passkeys.FindAsync(credentialId, http.RequestAborted);
        var ip = http.Connection.RemoteIpAddress?.ToString();
        if (passkey?.User is not { IsActive: true } user || (expectedUser != 0 && user.Id != expectedUser))
        {
            await activity.WriteAsync(ActivityKind.SignInFailed, ipAddress: ip, detail: "Unknown passkey", ct: http.RequestAborted);
            return Problem("This passkey is not known here.");
        }

        try
        {
            var result = await (await CreateFido2Async(http)).MakeAssertionAsync(new MakeAssertionParams
            {
                AssertionResponse = body.Response,
                OriginalOptions = AssertionOptions.FromJson(json),
                StoredPublicKey = passkey.PublicKey,
                StoredSignatureCounter = (uint)passkey.SignCount,
                IsUserHandleOwnerOfCredentialIdCallback = (args, _) => Task.FromResult(args.UserHandle is null || CryptographicOperations.FixedTimeEquals(args.UserHandle, Encoding.UTF8.GetBytes(user.Subject))),
            }, http.RequestAborted);

            await passkeys.UsedAsync(passkey.Id, result.SignCount, http.RequestAborted);
        }
        catch (Fido2VerificationException ex)
        {
            await activity.WriteAsync(ActivityKind.SignInFailed, user, ipAddress: ip, detail: "Passkey refused", ct: http.RequestAborted);
            return Problem("The passkey could not be checked: " + ex.Message);
        }

        var remember = expectedUser == 0 || (await SignInFlow.PendingAsync(http))?.Remember != false;
        await SignInFlow.CompleteAsync(http, user, remember, expectedUser == 0 ? "with a passkey" : "with the password and a passkey");
        var returnUrl = !string.IsNullOrEmpty(body.ReturnUrl) && body.ReturnUrl.StartsWith('/') && !body.ReturnUrl.StartsWith("//", StringComparison.Ordinal) ? body.ReturnUrl : "/";
        return Results.Json(new { redirect = returnUrl });
    }

    /// <summary>The relying party is the address the browser sees (behind the proxy: its host), so a passkey belongs to the public name of MatIdentity.</summary>
    private static async Task<Fido2> CreateFido2Async(HttpContext http)
    {
        var name = (await http.RequestServices.GetRequiredService<SystemConfigService>().GetAsync(http.RequestAborted)).InstanceName;
        return new Fido2(new Fido2Configuration
        {
            RPID = http.Request.Host.Host,
            RPName = name,
            Origins = new HashSet<string> { $"{http.Request.Scheme}://{http.Request.Host}" },
            TimestampDriftTolerance = 300_000,
        });
    }

    private static string Remember(IMemoryCache cache, string kind, long userId, string json)
    {
        var id = Convert.ToHexString(RandomNumberGenerator.GetBytes(16));
        cache.Set($"passkey:{kind}:{id}", (userId, json), CeremonyLifetime);
        return id;
    }

    /// <summary>The options of a ceremony, once (a second try with the same id finds nothing).</summary>
    private static (long UserId, string Json)? Recall(IMemoryCache cache, string kind, string? id)
    {
        if (string.IsNullOrEmpty(id) || !cache.TryGetValue($"passkey:{kind}:{id}", out (long, string) value))
        {
            return null;
        }

        cache.Remove($"passkey:{kind}:{id}");
        return value;
    }

    private static async Task<bool> ValidAntiforgeryAsync(HttpContext http, IAntiforgery antiforgery)
    {
        try
        {
            await antiforgery.ValidateRequestAsync(http);
            return true;
        }
        catch (AntiforgeryValidationException)
        {
            return false;
        }
    }

    /// <summary>Base64url without padding, as WebAuthn names credentials.</summary>
    private static class B64
    {
        public static string Encode(byte[] bytes) => System.Buffers.Text.Base64Url.EncodeToString(bytes);

        public static byte[] Decode(string text) => System.Buffers.Text.Base64Url.DecodeFromChars(text);
    }

    private static IResult Problem(string message) => Results.Json(new { error = message }, statusCode: StatusCodes.Status400BadRequest);

    public sealed record RegisterBody(string? Id, string? Name, AuthenticatorAttestationRawResponse Response);

    public sealed record SignInOptionsBody(string? Mode);

    public sealed record SignInBody(string? Id, AuthenticatorAssertionRawResponse Response, string? ReturnUrl);
}
