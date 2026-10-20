using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading.Channels;
using MatIdentity.Core.Auth;
using MatIdentity.Core.Clients;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Server;

namespace MatIdentity.Web.Infrastructure;

/// <summary>One logout token to send: to which app, at which address, for whom.</summary>
public sealed record LogoutNotice(string Issuer, string ClientId, string Address, string Subject, string? Sid);

/// <summary>
/// OpenID Connect Back-Channel Logout 1.0: when sessions end here (a sign-out, "sign out on other devices", a disabled account, a new password, "sign everyone out"),
/// every app that has a back-channel address and was signed in to from those sessions gets a signed <c>logout_token</c> (iss, aud = the app, sub, sid, events)
/// and ends its own session. A person out everywhere is announced to every such app with <c>sub</c> alone. The tokens go out after the answer
/// (<see cref="BackchannelLogoutWorker"/>).
/// </summary>
public sealed class BackchannelLogout : ISessionEndListener
{
    private readonly ClientService _clients;
    private readonly BackchannelLogoutQueue _queue;
    private readonly IOptionsMonitor<OpenIddictServerOptions> _server;
    private readonly IHttpContextAccessor _http;

    public BackchannelLogout(ClientService clients, BackchannelLogoutQueue queue, IOptionsMonitor<OpenIddictServerOptions> server, IHttpContextAccessor http)
    {
        _clients = clients;
        _queue = queue;
        _server = server;
        _http = http;
    }

    public async Task SessionsEndedAsync(IReadOnlyList<EndedSession> sessions, bool everywhere, CancellationToken ct)
    {
        if (sessions.Count == 0)
        {
            return;
        }

        var addresses = (await _clients.GetAllAsync(ct))
            .Where(c => !string.IsNullOrEmpty(c.BackchannelLogoutUri))
            .ToDictionary(c => c.ClientId, c => c.BackchannelLogoutUri!, StringComparer.Ordinal);
        if (addresses.Count == 0)
        {
            return;
        }

        var issuer = Issuer();
        if (everywhere)
        {
            // Every app hears it, with the subject alone: all sessions of the person there end.
            foreach (var subject in sessions.Select(s => s.Subject).Distinct(StringComparer.Ordinal))
            {
                foreach (var (clientId, address) in addresses)
                {
                    _queue.Enqueue(new LogoutNotice(issuer, clientId, address, subject, null));
                }
            }

            return;
        }

        foreach (var session in sessions)
        {
            foreach (var clientId in session.ClientIds.Distinct(StringComparer.Ordinal))
            {
                if (addresses.TryGetValue(clientId, out var address))
                {
                    _queue.Enqueue(new LogoutNotice(issuer, clientId, address, session.Subject, session.Sid));
                }
            }
        }
    }

    /// <summary>The issuer of the tokens: the public address when it is set, else the address of the request (as OpenIddict does).</summary>
    private string Issuer()
    {
        if (_server.CurrentValue.Issuer is { } fixedIssuer)
        {
            return fixedIssuer.AbsoluteUri;
        }

        var request = _http.HttpContext?.Request;
        return request is null ? "http://localhost/" : $"{request.Scheme}://{request.Host}{request.PathBase}/";
    }

    /// <summary>The logout token (a JWT of type <c>logout+jwt</c>, two minutes), signed with the key of the ID tokens.</summary>
    public static string CreateToken(LogoutNotice notice, SigningCredentials credentials, DateTime now)
    {
        var claims = new Dictionary<string, object>
        {
            ["sub"] = notice.Subject,
            ["jti"] = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)),
            ["events"] = new Dictionary<string, object> { ["http://schemas.openid.net/event/backchannel-logout"] = new Dictionary<string, object>() },
        };
        if (!string.IsNullOrEmpty(notice.Sid))
        {
            claims["sid"] = notice.Sid;
        }

        return new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = notice.Issuer,
            Audience = notice.ClientId,
            IssuedAt = now,
            NotBefore = now,
            Expires = now.AddMinutes(2),
            Claims = claims,
            TokenType = "logout+jwt",
            SigningCredentials = credentials,
        });
    }
}

/// <summary>The logout tokens waiting to be sent (in memory; a restart loses them, the app's session then ends at its own time).</summary>
public sealed class BackchannelLogoutQueue
{
    private readonly Channel<LogoutNotice> _channel = Channel.CreateBounded<LogoutNotice>(new BoundedChannelOptions(2000) { FullMode = BoundedChannelFullMode.DropOldest });

    public void Enqueue(LogoutNotice notice) => _channel.Writer.TryWrite(notice);

    public ChannelReader<LogoutNotice> Reader => _channel.Reader;
}

/// <summary>Sends the logout tokens: a POST with <c>logout_token</c>, five seconds, one more try. An app that cannot be reached is written to the log.</summary>
public sealed class BackchannelLogoutWorker : BackgroundService
{
    public const string HttpClientName = "backchannel-logout";

    private readonly BackchannelLogoutQueue _queue;
    private readonly IHttpClientFactory _http;
    private readonly IOptionsMonitor<OpenIddictServerOptions> _server;
    private readonly TimeProvider _time;
    private readonly ILogger<BackchannelLogoutWorker> _logger;

    public BackchannelLogoutWorker(BackchannelLogoutQueue queue, IHttpClientFactory http, IOptionsMonitor<OpenIddictServerOptions> server, TimeProvider time, ILogger<BackchannelLogoutWorker> logger)
    {
        _queue = queue;
        _http = http;
        _server = server;
        _time = time;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            await foreach (var notice in _queue.Reader.ReadAllAsync(stoppingToken))
            {
                await SendAsync(notice, stoppingToken);
            }
        }
        catch (OperationCanceledException)
        {
            // Stopping.
        }
    }

    private async Task SendAsync(LogoutNotice notice, CancellationToken ct)
    {
        var credentials = _server.CurrentValue.SigningCredentials.FirstOrDefault(c => c.Key is AsymmetricSecurityKey);
        if (credentials is null)
        {
            return;
        }

        for (var attempt = 1; attempt <= 2; attempt++)
        {
            try
            {
                var token = BackchannelLogout.CreateToken(notice, credentials, _time.GetUtcNow().UtcDateTime);
                using var client = _http.CreateClient(HttpClientName);
                client.Timeout = TimeSpan.FromSeconds(5);
                using var response = await client.PostAsync(notice.Address, new FormUrlEncodedContent(new Dictionary<string, string> { ["logout_token"] = token }), ct);
                if (response.IsSuccessStatusCode)
                {
                    return;
                }

                _logger.LogWarning("Back-channel logout at {App} ({Address}) answered {Status}", notice.ClientId, notice.Address, (int)response.StatusCode);
            }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException && !ct.IsCancellationRequested)
            {
                _logger.LogWarning("Back-channel logout at {App} ({Address}) failed: {Reason}", notice.ClientId, notice.Address, ex.Message);
            }

            if (attempt == 1)
            {
                await Task.Delay(TimeSpan.FromSeconds(2), ct);
            }
        }
    }
}
