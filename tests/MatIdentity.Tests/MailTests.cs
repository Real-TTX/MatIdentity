using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using MatIdentity.Core.Configuration;
using MatIdentity.Core.Mail;
using MatIdentity.Core.Security;
using Microsoft.Extensions.Logging.Abstractions;

namespace MatIdentity.Tests;

/// <summary>
/// Mail through MatSMTP (the site in memory runs with MATSMTP_*, as Mattiverse sets them): the settings are fixed in the page and in /api/configure, the password
/// is never sent back; and the own SMTP server of the settings when MatSMTP is not there.
/// </summary>
[Collection(TestCollection.Name)]
public sealed class MailTests
{
    private readonly IdentityFactory _site;

    public MailTests(IdentityFactory site)
    {
        _site = site;
    }

    [Fact]
    public async Task With_MatSMTP_the_mail_settings_are_fixed_in_the_api_and_the_password_is_never_sent()
    {
        var api = _site.Api();
        using var definition = JsonDocument.Parse(await api.GetStringAsync("/api"));
        var smtpHost = definition.RootElement.GetProperty("configure").EnumerateArray().Single(f => f.GetProperty("key").GetString() == "smtpHost");
        Assert.True(smtpHost.GetProperty("fixed").GetBoolean());
        Assert.Contains("MatSMTP", smtpHost.GetProperty("hint").GetString());

        var values = await api.GetStringAsync("/api/configure");
        Assert.Contains("matsmtp.test", values);
        Assert.DoesNotContain("relay-secret", values);

        var change = await api.PutAsJsonAsync("/api/configure", new { values = new { smtpHost = "smtp.elsewhere.test" } });
        Assert.Equal(HttpStatusCode.BadRequest, change.StatusCode);
    }

    [Fact]
    public async Task With_MatSMTP_the_settings_page_shows_it_and_sends_a_test_mail_through_it()
    {
        var browser = await _site.AdminAsync();
        var page = await browser.GetStringAsync("/Settings");
        Assert.Contains("Mail is sent through MatSMTP (matsmtp.test:2025) as id@example.test", page);
        Assert.DoesNotContain("Input.SmtpHost", page);
        Assert.DoesNotContain("relay-secret", page);

        var response = await IdentityFactory.PostFormAsync(browser, "/Settings", [], "/Settings?handler=TestMail");
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        var sent = _site.Mails.Sent.Last(s => s.Mail.Subject.Contains("test mail"));
        Assert.Equal("admin@example.com", sent.Mail.ToAddress);
        Assert.Equal("matsmtp.test", sent.Target.Host);
        Assert.Equal("matidentity", sent.Target.Username);
        Assert.Equal("id@example.test", sent.Target.From);
    }

    [Fact]
    public async Task Without_MatSMTP_the_own_server_is_used_and_its_password_is_stored_encrypted()
    {
        var data = Path.Combine(Path.GetTempPath(), "matidentity-mail-" + Guid.NewGuid().ToString("N"));
        var paths = new AppPaths(data);
        paths.EnsureCreated();
        try
        {
            var config = new SystemConfigService(new JsonConfigStore(paths, NullLogger<JsonConfigStore>.Instance));
            var protector = new DataProtectionSecretProtector(Microsoft.AspNetCore.DataProtection.DataProtectionProvider.Create("tests"));
            var transport = new RecordingMailTransport();
            var mail = new MailService(new MailRelay(), config, protector, transport, NullLogger<MailService>.Instance);

            Assert.False(await mail.IsAvailableAsync());
            Assert.Equal("No mail server is set.", await mail.SendAsync(MailTemplates.Test("a@example.test", "A", "MatIdentity")));

            var settings = await config.GetAsync();
            settings.SmtpHost = "smtp.example.test";
            settings.SmtpPort = 465;
            settings.SmtpTls = "tls";
            settings.SmtpFrom = "id@example.test";
            settings.SmtpUsername = "id";
            settings.SmtpPasswordProtected = mail.ProtectPassword("smtp-password-42");
            Assert.Empty(await config.SaveAsync(settings));
            Assert.DoesNotContain("smtp-password-42", await File.ReadAllTextAsync(Path.Combine(paths.ConfigPath, "system.json")));

            Assert.Null(await mail.SendAsync(MailTemplates.Test("a@example.test", "A", "MatIdentity")));
            var (target, _) = Assert.Single(transport.Sent);
            Assert.Equal(("smtp.example.test", 465, MailTls.Tls, "smtp-password-42", false), (target.Host, target.Port, target.Tls, target.Password, target.Fixed));

            settings.SmtpFrom = "not an address";
            Assert.Contains("smtpFrom", (await config.SaveAsync(settings)).Keys);
        }
        finally
        {
            try
            {
                Directory.Delete(data, recursive: true);
            }
            catch (IOException)
            {
            }
        }
    }
}
