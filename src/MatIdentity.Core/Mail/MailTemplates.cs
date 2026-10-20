namespace MatIdentity.Core.Mail;

/// <summary>The few mails of MatIdentity, plain text and short: what happened, the link, how long it works, and what to do if it was not you.</summary>
public static class MailTemplates
{
    public static OutgoingMail PasswordReset(string to, string name, string instance, string link, TimeSpan lifetime) => new(to, name,
        $"{instance}: set a new password",
        $"""
        Hello {name},

        someone asked to set a new password for your account at {instance}. If it was you, open this link within {Minutes(lifetime)}:

        {link}

        If it was not you, ignore this mail; your password stays as it is.
        """);

    public static OutgoingMail Invitation(string to, string name, string instance, string link, TimeSpan lifetime, string? invitedBy) => new(to, name,
        $"{instance}: your account",
        $"""
        Hello {name},

        {(string.IsNullOrEmpty(invitedBy) ? "an administrator" : invitedBy)} has made you an account at {instance}, the sign-in for your apps.
        Choose your password with this link (it works for {Days(lifetime)}):

        {link}
        """);

    public static OutgoingMail VerifyEmail(string to, string name, string instance, string link, TimeSpan lifetime) => new(to, name,
        $"{instance}: confirm your e-mail address",
        $"""
        Hello {name},

        please confirm that this is your e-mail address at {instance} (the link works for {Days(lifetime)}):

        {link}

        If you do not know {instance}, ignore this mail.
        """);

    public static OutgoingMail Test(string to, string name, string instance) => new(to, name,
        $"{instance}: test mail",
        $"""
        Hello {name},

        this is the test mail of {instance}. The mail settings work.
        """);

    private static string Minutes(TimeSpan span) => $"{(int)span.TotalMinutes} minutes";

    private static string Days(TimeSpan span) => span.TotalHours < 48 ? $"{(int)span.TotalHours} hours" : $"{(int)span.TotalDays} days";
}
