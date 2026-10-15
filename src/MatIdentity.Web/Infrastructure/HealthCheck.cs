using System.Text.RegularExpressions;

namespace MatIdentity.Web.Infrastructure;

/// <summary>The container's own health check: <c>dotnet MatIdentity.Web.dll --healthcheck</c> asks <c>/api/health</c> on localhost (200 for ok and degraded, 503 for down).</summary>
public static partial class HealthCheck
{
    public static async Task<int> RunAsync()
    {
        var match = PortRegex().Match(Environment.GetEnvironmentVariable("ASPNETCORE_URLS") ?? string.Empty);
        var port = match.Success ? match.Groups[1].Value : "2300";

        try
        {
            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
            using var response = await http.GetAsync($"http://127.0.0.1:{port}/api/health");
            return response.IsSuccessStatusCode ? 0 : 1;
        }
        catch (HttpRequestException)
        {
            return 1;
        }
        catch (TaskCanceledException)
        {
            return 1;
        }
    }

    [GeneratedRegex(@":(\d+)")]
    private static partial Regex PortRegex();
}
