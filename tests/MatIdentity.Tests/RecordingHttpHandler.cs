using System.Collections.Concurrent;

namespace MatIdentity.Tests;

/// <summary>The requests MatIdentity sends to the apps (back-channel logout), kept instead of sent; every answer is 200.</summary>
public sealed class RecordingHttpHandler : HttpMessageHandler
{
    private readonly ConcurrentQueue<(Uri Address, Dictionary<string, string> Form)> _requests;

    public RecordingHttpHandler(ConcurrentQueue<(Uri Address, Dictionary<string, string> Form)> requests)
    {
        _requests = requests;
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var body = request.Content is null ? string.Empty : await request.Content.ReadAsStringAsync(cancellationToken);
        var form = System.Web.HttpUtility.ParseQueryString(body);
        _requests.Enqueue((request.RequestUri!, form.AllKeys.Where(k => k is not null).ToDictionary(k => k!, k => form[k]!)));
        return new HttpResponseMessage(System.Net.HttpStatusCode.OK);
    }
}
