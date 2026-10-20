using MatIdentity.Core.Auth;
using MatIdentity.Core.Configuration;
using MatIdentity.Core.Entities;
using MatIdentity.Core.Mail;

namespace MatIdentity.Core.Users;

/// <summary>
/// What the links in mails do: "Forgot your password?" (no hint whether an account exists, at most <see cref="MaxResetsPerHour"/> mails an hour), the invitation
/// of a new person (they choose their password), and confirming an e-mail address. The links are <c>{address of MatIdentity}/Account/Reset?token=…</c> and
/// <c>/Account/Verify?token=…</c>.
/// </summary>
public sealed class AccountMailService
{
    public const int MaxResetsPerHour = 3;

    private static readonly AccountTokenPurpose[] PasswordPurposes = [AccountTokenPurpose.PasswordReset, AccountTokenPurpose.Invitation];
    private static readonly AccountTokenPurpose[] VerifyPurpose = [AccountTokenPurpose.EmailVerification];

    private readonly AuthService _auth;
    private readonly UserService _users;
    private readonly AccountTokenService _tokens;
    private readonly MailService _mail;
    private readonly MailQueue _queue;
    private readonly SystemConfigService _config;
    private readonly TimeProvider _time;

    public AccountMailService(AuthService auth, UserService users, AccountTokenService tokens, MailService mail, MailQueue queue, SystemConfigService config, TimeProvider time)
    {
        _auth = auth;
        _users = users;
        _tokens = tokens;
        _mail = mail;
        _queue = queue;
        _config = config;
        _time = time;
    }

    /// <summary>
    /// "Forgot your password?": a link to the address of the account, when there is an active account with an address for <paramref name="login"/> (user name
    /// or e-mail) and mail is set. The caller answers the same in every case. Returns the person a mail went to (for the activity list), or null.
    /// </summary>
    public async Task<User?> RequestPasswordResetAsync(string login, string linkBase, CancellationToken ct = default)
    {
        var user = await _auth.FindAsync(login, ct);
        if (user is not { IsActive: true } || string.IsNullOrEmpty(user.Email) || !await _mail.IsAvailableAsync(ct)
            || await _tokens.CountSinceAsync(user.Id, AccountTokenPurpose.PasswordReset, _time.GetUtcNow().UtcDateTime.AddHours(-1), ct) >= MaxResetsPerHour)
        {
            return null;
        }

        var key = await _tokens.IssueAsync(user.Id, AccountTokenPurpose.PasswordReset, user.Email, ct);
        _queue.Enqueue(MailTemplates.PasswordReset(user.Email, user.DisplayName, await InstanceAsync(ct), Link(linkBase, "Reset", key), AccountTokenService.ResetLifetime));
        return user;
    }

    /// <summary>Sends the invitation of a person (the mail goes out now, so the administrator sees an error). Null when it went out, else why not.</summary>
    public async Task<string?> InviteAsync(User user, string linkBase, string? invitedBy, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(user.Email))
        {
            return "The person has no e-mail address.";
        }

        var key = await _tokens.IssueAsync(user.Id, AccountTokenPurpose.Invitation, user.Email, ct);
        var mail = MailTemplates.Invitation(user.Email, user.DisplayName, await InstanceAsync(ct), Link(linkBase, "Reset", key), AccountTokenService.InvitationLifetime, invitedBy);
        var error = await _mail.SendAsync(mail, ct);
        if (error is not null)
        {
            await _tokens.RevokeAsync(user.Id, AccountTokenPurpose.Invitation, ct);
        }

        return error;
    }

    /// <summary>A link that confirms the current address of <paramref name="user"/> (sent after the answer). False without an address, when it is confirmed, or without mail.</summary>
    public async Task<bool> SendVerificationAsync(User user, string linkBase, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(user.Email) || user.EmailVerified || !await _mail.IsAvailableAsync(ct))
        {
            return false;
        }

        var key = await _tokens.IssueAsync(user.Id, AccountTokenPurpose.EmailVerification, user.Email, ct);
        _queue.Enqueue(MailTemplates.VerifyEmail(user.Email, user.DisplayName, await InstanceAsync(ct), Link(linkBase, "Verify", key), AccountTokenService.VerificationLifetime));
        return true;
    }

    /// <summary>
    /// A person makes an account (registration is on): disabled until they follow the link to their address. An address that belongs to an account already gets
    /// nothing and the caller answers the same (no hint which addresses are known). The user name must be free (the caller checks it).
    /// </summary>
    public async Task<User?> RegisterAsync(string username, string displayName, string email, string password, string linkBase, CancellationToken ct = default)
    {
        if (await _users.EmailExistsAsync(email, null, ct))
        {
            return null;
        }

        var user = await _users.RegisterAsync(username, displayName, email, password, ct);
        await SendVerificationAsync(user, linkBase, ct);
        return user;
    }

    /// <summary>The open link for a new password (a reset or an invitation), or null when it is used, expired or unknown.</summary>
    public Task<AccountToken?> FindPasswordLinkAsync(string? key, CancellationToken ct = default) => _tokens.FindAsync(key, PasswordPurposes, ct);

    /// <summary>
    /// Sets the password of the link and uses the link up; the address the link went to counts as confirmed. Null when the link does not work (any more);
    /// the caller ends the person's sessions and app sign-ins.
    /// </summary>
    public async Task<User?> SetPasswordAsync(string? key, string newPassword, CancellationToken ct = default)
    {
        if (await FindPasswordLinkAsync(key, ct) is not { User: { IsActive: true } user } token)
        {
            return null;
        }

        await _tokens.UseAsync(token, ct);
        await _tokens.RevokeAsync(user.Id, AccountTokenPurpose.PasswordReset, ct);
        await _tokens.RevokeAsync(user.Id, AccountTokenPurpose.Invitation, ct);
        await _users.ChangePasswordAsync(user.Id, newPassword, ct);
        if (SameAddress(token.Email, user.Email))
        {
            await _users.SetEmailVerifiedAsync(user.Id, ct);
        }

        return user;
    }

    /// <summary>Confirms the address of a link; the person, or null when the link does not work or the address has changed since.</summary>
    public async Task<User?> VerifyEmailAsync(string? key, CancellationToken ct = default)
    {
        if (await _tokens.FindAsync(key, VerifyPurpose, ct) is not { User: { } user } token || !SameAddress(token.Email, user.Email))
        {
            return null;
        }

        await _tokens.UseAsync(token, ct);
        await _users.SetEmailVerifiedAsync(user.Id, ct);
        if (user.PendingRegistration)
        {
            // A registration: the confirmed address makes the account work.
            await _users.ActivateRegistrationAsync(user.Id, ct);
        }

        return user;
    }

    /// <summary>The people whose invitation is still open (for the list of people).</summary>
    public Task<HashSet<long>> OpenInvitationsAsync(CancellationToken ct = default) => _tokens.OpenInvitationsAsync(ct);

    /// <summary>A password nobody knows, for an invited person until they choose one.</summary>
    public static string UnusablePassword() => Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));

    private static bool SameAddress(string? a, string? b) => !string.IsNullOrEmpty(a) && string.Equals(a.Trim(), b?.Trim(), StringComparison.OrdinalIgnoreCase);

    private static string Link(string linkBase, string page, string key) => $"{linkBase.TrimEnd('/')}/Account/{page}?token={key}";

    private async Task<string> InstanceAsync(CancellationToken ct) => (await _config.GetAsync(ct)).InstanceName;
}
