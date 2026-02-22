using MailKit.Net.Smtp;
using MailKit.Security;
using Microsoft.EntityFrameworkCore;
using MimeKit;
using OAuthProviderV2.Data;
using OAuthProviderV2.Models;

namespace OAuthProviderV2.Services.Email;

public interface IEmailService
{
    Task<bool> SendAsync(int? organizationId, string toEmail, string toName, string subject, string htmlBody);
    Task<bool> SendOtpAsync(string email, string otp);
    Task<bool> SendUserInviteAsync(string email, string name, string verifyUrl, string orgName);
    Task<bool> SendLoginAlertAsync(int organizationId, string email, string name, string ip, string browser, string os, string location);
    Task<bool> SendSecurityAlertAsync(int organizationId, string email, string subject, string message);
    Task<bool> TestConfigAsync(int? organizationId);
}

public class EmailService : IEmailService
{
    private readonly ApplicationDbContext _db;
    private readonly IConfiguration _config;

    public EmailService(ApplicationDbContext db, IConfiguration config)
    {
        _db = db;
        _config = config;
    }

    public async Task<bool> SendAsync(int? organizationId, string toEmail, string toName, string subject, string htmlBody)
    {
        try
        {
            var (host, port, ssl, user, pass, fromEmail, fromName) = await ResolveSmtpConfigAsync(organizationId);
            if (host == null) return false;

            var message = new MimeMessage();
            message.From.Add(new MailboxAddress(fromName, fromEmail));
            message.To.Add(new MailboxAddress(toName, toEmail));
            message.Subject = subject;

            var builder = new BodyBuilder { HtmlBody = WrapInTemplate(subject, htmlBody, fromName!) };
            message.Body = builder.ToMessageBody();

            using var client = new SmtpClient();
            await client.ConnectAsync(host, port, ssl ? SecureSocketOptions.StartTls : SecureSocketOptions.None);
            if (!string.IsNullOrEmpty(user))
                await client.AuthenticateAsync(user, pass);
            await client.SendAsync(message);
            await client.DisconnectAsync(true);
            return true;
        }
        catch (Exception ex)
        {
            // Log but don't throw — email failure should not break the flow
            Console.WriteLine($"[Email] Failed to send to {toEmail}: {ex.Message}");
            return false;
        }
    }

    public async Task<bool> SendOtpAsync(string email, string otp)
    {
        var html = $@"
            <h2 style='color:#6366f1;'>Your Verification Code</h2>
            <p>Use the following OTP to complete your registration:</p>
            <div style='text-align:center;margin:32px 0;'>
                <span style='font-size:48px;font-weight:900;letter-spacing:12px;color:#6366f1;
                             background:#f0f0ff;padding:16px 32px;border-radius:12px;'>{otp}</span>
            </div>
            <p style='color:#888;'>This code expires in <strong>10 minutes</strong>.</p>
            <p style='color:#888;'>If you did not request this, you can safely ignore this email.</p>";

        return await SendAsync(null, email, email, "Your OTP Verification Code", html);
    }

    public async Task<bool> SendUserInviteAsync(string email, string name, string verifyUrl, string orgName)
    {
        var html = $@"
            <h2>You've been invited to <span style='color:#6366f1;'>{orgName}</span></h2>
            <p>Hi {name},</p>
            <p>An administrator has added you to <strong>{orgName}</strong> on the OAuth Provider platform.</p>
            <p>Click the button below to verify your email address and activate your account:</p>
            <div style='text-align:center;margin:32px 0;'>
                <a href='{verifyUrl}' style='background:#6366f1;color:white;padding:14px 32px;
                   border-radius:8px;text-decoration:none;font-weight:600;font-size:16px;'>
                    Verify My Email &amp; Activate Account
                </a>
            </div>
            <p style='color:#888;'>This link expires in <strong>48 hours</strong>.</p>
            <p style='color:#888;'>If you did not expect this invitation, you can safely ignore this email.</p>";

        return await SendAsync(null, email, name, $"You're invited to {orgName} — Verify your email", html);
    }

    public async Task<bool> SendLoginAlertAsync(int organizationId, string email, string name, string ip, string browser, string os, string location)
    {
        var config = await _db.OrganizationEmailConfigs
            .FirstOrDefaultAsync(c => c.OrganizationId == organizationId);

        if (config?.AlertsEnabled == false || config?.LoginAlerts == false) return true;

        var html = $@"
            <h2 style='color:#f59e0b;'>⚠ New Login Detected</h2>
            <p>Hi {name},</p>
            <p>A new sign-in was detected on your account:</p>
            <table style='width:100%;border-collapse:collapse;margin:16px 0;'>
                <tr><td style='padding:8px;background:#f9f9f9;font-weight:600;width:140px;'>IP Address</td><td style='padding:8px;'>{ip}</td></tr>
                <tr><td style='padding:8px;background:#f9f9f9;font-weight:600;'>Browser</td><td style='padding:8px;'>{browser}</td></tr>
                <tr><td style='padding:8px;background:#f9f9f9;font-weight:600;'>Operating System</td><td style='padding:8px;'>{os}</td></tr>
                <tr><td style='padding:8px;background:#f9f9f9;font-weight:600;'>Location</td><td style='padding:8px;'>{location}</td></tr>
                <tr><td style='padding:8px;background:#f9f9f9;font-weight:600;'>Time</td><td style='padding:8px;'>{DateTime.UtcNow:MMM d, yyyy HH:mm} UTC</td></tr>
            </table>
            <p>If this was you, no action is needed.</p>
            <p style='color:#ef4444;'><strong>If this wasn't you, immediately change your password and contact your administrator.</strong></p>";

        return await SendAsync(organizationId, email, name, "New sign-in to your account", html);
    }

    public async Task<bool> SendSecurityAlertAsync(int organizationId, string email, string subject, string message)
    {
        var config = await _db.OrganizationEmailConfigs
            .FirstOrDefaultAsync(c => c.OrganizationId == organizationId);

        if (config?.AlertsEnabled == false || config?.SecurityAlerts == false) return true;

        var html = $@"
            <h2 style='color:#ef4444;'>🔒 Security Alert</h2>
            <p>{message}</p>
            <p style='color:#888;'>Time: {DateTime.UtcNow:MMM d, yyyy HH:mm} UTC</p>";

        return await SendAsync(organizationId, email, email, subject, html);
    }

    public async Task<bool> TestConfigAsync(int? organizationId)
    {
        var html = "<h2>Test Email</h2><p>Your email configuration is working correctly.</p>";
        var to = organizationId.HasValue
            ? (await _db.Organizations.FindAsync(organizationId))?.AdminEmail ?? "test@test.com"
            : "admin@oauthprovider.dev";
        return await SendAsync(organizationId, to, "Test", "OAuth Provider — Email Configuration Test", html);
    }

    private async Task<(string? host, int port, bool ssl, string? user, string? pass, string? fromEmail, string? fromName)> ResolveSmtpConfigAsync(int? organizationId)
    {
        // Try org-specific config first
        if (organizationId.HasValue)
        {
            var orgConfig = await _db.OrganizationEmailConfigs
                .FirstOrDefaultAsync(c => c.OrganizationId == organizationId && !c.UseDefaultProvider);

            if (orgConfig?.SmtpHost != null)
            {
                return (orgConfig.SmtpHost, orgConfig.SmtpPort, orgConfig.SmtpUseSsl,
                        orgConfig.SmtpUsername, DecryptPassword(orgConfig.SmtpPasswordEncrypted),
                        orgConfig.FromEmail, orgConfig.FromName);
            }
        }

        // Fall back to platform default
        var platform = await _db.PlatformEmailConfigs.FirstOrDefaultAsync();
        if (platform?.IsConfigured == true)
        {
            return (platform.SmtpHost, platform.SmtpPort, platform.SmtpUseSsl,
                    platform.SmtpUsername, DecryptPassword(platform.SmtpPasswordEncrypted),
                    platform.FromEmail, platform.FromName);
        }

        // Fall back to appsettings
        var host = _config["Email:SmtpHost"];
        if (string.IsNullOrEmpty(host)) return (null, 587, true, null, null, null, null);

        return (host,
                int.TryParse(_config["Email:SmtpPort"], out var p) ? p : 587,
                _config["Email:SmtpUseSsl"] != "false",
                _config["Email:SmtpUsername"],
                _config["Email:SmtpPassword"],
                _config["Email:FromEmail"],
                _config["Email:FromName"] ?? "OAuth Provider");
    }

    // Simple XOR obfuscation — replace with Azure Key Vault / data protection in production
    private static string? DecryptPassword(string? enc)
    {
        if (string.IsNullOrEmpty(enc)) return null;
        try { return System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(enc)); }
        catch { return enc; }
    }

    public static string EncryptPassword(string plain) =>
        Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(plain));

    private static string WrapInTemplate(string subject, string body, string senderName)
    {
        return $@"<!DOCTYPE html>
<html>
<head><meta charset='utf-8'><meta name='viewport' content='width=device-width'></head>
<body style='margin:0;padding:0;background:#f3f4f6;font-family:-apple-system,BlinkMacSystemFont,Segoe UI,sans-serif;'>
  <div style='max-width:580px;margin:40px auto;background:white;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,.08);'>
    <div style='background:linear-gradient(135deg,#6366f1,#8b5cf6);padding:32px;text-align:center;'>
      <h1 style='color:white;margin:0;font-size:22px;'>🔐 OAuth Provider</h1>
    </div>
    <div style='padding:40px 32px;color:#1f2937;line-height:1.6;'>
      {body}
    </div>
    <div style='background:#f9fafb;padding:20px 32px;text-align:center;color:#9ca3af;font-size:12px;border-top:1px solid #e5e7eb;'>
      Sent by {senderName} · OAuth Provider Platform
    </div>
  </div>
</body>
</html>";
    }
}
