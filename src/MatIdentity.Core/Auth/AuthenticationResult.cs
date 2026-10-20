using MatIdentity.Core.Entities;

namespace MatIdentity.Core.Auth;

/// <summary>Result of a local username/password authentication attempt.</summary>
public sealed class AuthenticationResult
{
    public bool Succeeded { get; private init; }

    public User? User { get; private init; }

    public string? Error { get; private init; }

    /// <summary>This attempt locked the account (too many wrong ones in a row).</summary>
    public bool LockedNow { get; private init; }

    /// <summary>The account was locked: the password was not even looked at for the decision.</summary>
    public bool WasLocked { get; private init; }

    public static AuthenticationResult Success(User user) => new() { Succeeded = true, User = user };

    public static AuthenticationResult Failure(string error, bool lockedNow = false, bool wasLocked = false)
        => new() { Succeeded = false, Error = error, LockedNow = lockedNow, WasLocked = wasLocked };
}
