using System.Collections.Concurrent;
using System.Net;
using System.Text;

namespace MatIdentity.Tests;

/// <summary>The apps MatIdentity asks for their roles (<c>GET &lt;app&gt;/api</c>), answered from <see cref="IdentityFactory.AppDefinitions"/> instead of the network; anything else is 404.</summary>
public sealed class AppDefinitionHandler : HttpMessageHandler
{
    private readonly ConcurrentDictionary<string, string> _definitions;

    public AppDefinitionHandler(ConcurrentDictionary<string, string> definitions)
    {
        _definitions = definitions;
    }

    /// <summary>Every address that was asked.</summary>
    public static ConcurrentQueue<Uri> Asked { get; } = new();

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        Asked.Enqueue(request.RequestUri!);
        return Task.FromResult(_definitions.TryGetValue(request.RequestUri!.GetLeftPart(UriPartial.Path), out var json)
            ? new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(json, Encoding.UTF8, "application/json") }
            : new HttpResponseMessage(HttpStatusCode.NotFound));
    }
}
