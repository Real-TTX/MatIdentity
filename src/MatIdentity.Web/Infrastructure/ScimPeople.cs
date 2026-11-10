using MatIdentity.Core.Access;
using MatIdentity.Core.Activity;
using MatIdentity.Core.Auth;
using MatIdentity.Core.Clients;
using MatIdentity.Core.Configuration;
using MatIdentity.Core.Entities;
using MatIdentity.Core.Users;

namespace MatIdentity.Web.Infrastructure;

/// <summary>
/// What a change of a person through SCIM does, the same as the pages of People: a new person (invited when there is no password), a change (signed out everywhere when the
/// account is disabled or gets a new password), a removal (signed out everywhere first), and the guard of the last active administrator. Every change in the activity list.
/// </summary>
public sealed class ScimPeople(
    UserService users,
    PermissionService permissions,
    SessionService sessions,
    TokenRevoker revoker,
    AccountMailService accounts,
    ActivityService activity,
    SystemConfigService config,
    IConfiguration configuration,
    IHttpContextAccessor http)
{
    /// <summary>The problem of a new password for a person (null: none, or no password).</summary>
    public async Task<string?> CheckPasswordAsync(string? password, string userName, string? email, CancellationToken ct)
        => password is null ? null : PasswordPolicy.Check(password, (await config.GetAsync(ct)).PasswordMinLength, userName, email);

    /// <summary>
    /// True when the change would leave no active administrator: <paramref name="user"/> is the last one and is to be no administrator any more, or not active
    /// (a removal passes both as false).
    /// </summary>
    public async Task<bool> LastAdministratorAsync(User user, bool active, bool administrator, CancellationToken ct)
        => user is { Role: UserRole.Admin, IsActive: true } && !(active && administrator) && await users.CountActiveAdminsAsync(ct) <= 1;

    public async Task<User> CreateAsync(HttpContext context, UserInput input, string actor, CancellationToken ct)
    {
        var displayName = input.DisplayName ?? input.UserName!;
        var invite = input.Password is null && input.Email is not null && input.Active != false;
        // Without a password nobody knows one until the person chooses one with the link of the invitation.
        var created = await users.CreateAsync(input.UserName!, displayName, input.Email, input.Password ?? AccountMailService.UnusablePassword(),
            input.Administrator == true ? UserRole.Admin : UserRole.User, mustChangePassword: false, ct);
        await users.SetExternalIdAsync(created.Id, input.ExternalId, ct);
        if (input.Active == false)
        {
            await users.UpdateAsync(created.Id, displayName, input.Email, created.Role, false, null, ct);
        }

        if (input.Grants is { } grants)
        {
            await permissions.ReplaceGrantsAsync(created.Id, null, grants, ct);
        }

        await activity.WriteAsync(ActivityKind.PersonCreated, username: actor, ipAddress: Ip(), detail: created.Username + (created.Role == UserRole.Admin ? " (administrator)" : string.Empty) + ", SCIM", ct: ct);
        if (invite)
        {
            var linkBase = await Support.Authority.GetAsync(context, config, configuration);
            if (await accounts.InviteAsync(created, linkBase, actor, ct) is null)
            {
                await activity.WriteAsync(ActivityKind.InvitationSent, username: actor, ipAddress: Ip(), detail: created.Username, ct: ct);
            }
        }

        return (await users.GetAsync(created.Id, ct))!;
    }

    public async Task UpdateAsync(User user, UserInput input, string actor, CancellationToken ct)
    {
        var active = input.Active ?? user.IsActive;
        var role = input.Administrator is { } administrator ? (administrator ? UserRole.Admin : UserRole.User) : user.Role;
        await users.UpdateAsync(user.Id, input.DisplayName ?? input.UserName ?? user.Username, input.Email, role, active, input.Password, ct);
        if (input.UserName is { } name && !string.Equals(name, user.Username, StringComparison.Ordinal))
        {
            await users.SetUsernameAsync(user.Id, name, ct);
        }

        await users.SetExternalIdAsync(user.Id, input.ExternalId, ct);
        if (input.Grants is { } grants)
        {
            await permissions.ReplaceGrantsAsync(user.Id, null, grants, ct);
        }

        // A disabled account or a password set from outside: out everywhere, as on the page of the person.
        if ((user.IsActive && !active) || input.Password is not null)
        {
            await sessions.InvalidateAllAsync(user.Id, ct: ct);
            await revoker.RevokeForSubjectAsync(user.Subject, ct);
        }

        await activity.WriteAsync(ActivityKind.PersonChanged, username: actor, ipAddress: Ip(), detail: user.Username + ", SCIM", ct: ct);
    }

    public async Task DeleteAsync(User user, string actor, CancellationToken ct)
    {
        // Signed out everywhere first: their sessions here and what the apps hold for them.
        await sessions.InvalidateAllAsync(user.Id, ct: ct);
        await revoker.RevokeForSubjectAsync(user.Subject, ct);
        await permissions.RemoveUserAsync(user.Id, ct);
        await users.DeleteAsync(user.Id, ct);
        await activity.WriteAsync(ActivityKind.PersonDeleted, username: actor, ipAddress: Ip(), detail: user.Username + ", SCIM", ct: ct);
    }

    private string? Ip() => http.HttpContext?.Connection.RemoteIpAddress?.ToString();
}
