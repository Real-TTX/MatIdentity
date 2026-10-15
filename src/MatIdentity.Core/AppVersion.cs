using System.Reflection;

namespace MatIdentity.Core;

/// <summary>The version of the running MatIdentity (the assembly's informational version, set by the build per channel).</summary>
public static class AppVersion
{
    public static string Current { get; } =
        (Assembly.GetEntryAssembly() ?? typeof(AppVersion).Assembly)
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
            ?? "unknown";
}
