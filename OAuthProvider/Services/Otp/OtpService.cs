using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using OAuthProviderV2.Data;
using OAuthProviderV2.Models;
using OAuthProviderV2.Services.Email;

namespace OAuthProviderV2.Services.Otp;

public interface IOtpService
{
    Task<string> GenerateAndSendAsync(string email, string purpose = "signup");
    Task<OtpVerifyResult> VerifyAsync(string email, string otp, string purpose = "signup");
    Task InvalidateAsync(string email, string purpose);
}

public enum OtpVerifyResult { Valid, Invalid, Expired, TooManyAttempts, NotFound }

public class OtpService : IOtpService
{
    private readonly ApplicationDbContext _db;
    private readonly IEmailService _email;

    public OtpService(ApplicationDbContext db, IEmailService email)
    {
        _db = db;
        _email = email;
    }

    public async Task<string> GenerateAndSendAsync(string email, string purpose = "signup")
    {
        // Invalidate any previous OTPs for this email+purpose
        var existing = await _db.OtpRecords
            .Where(o => o.Email == email && o.Purpose == purpose && !o.IsUsed)
            .ToListAsync();
        foreach (var old in existing) old.IsUsed = true;

        // Generate 6-digit OTP
        var otp = GenerateOtp();
        var hash = BCrypt.Net.BCrypt.HashPassword(otp);

        _db.OtpRecords.Add(new OtpRecord
        {
            Email     = email.ToLowerInvariant(),
            OtpHash   = hash,
            Purpose   = purpose,
            ExpiresAt = DateTime.UtcNow.AddMinutes(10),
        });
        await _db.SaveChangesAsync();

        await _email.SendOtpAsync(email, otp);
        return otp; // return for dev logging only — remove in production
    }

    public async Task<OtpVerifyResult> VerifyAsync(string email, string otp, string purpose = "signup")
    {
        var record = await _db.OtpRecords
            .Where(o => o.Email == email.ToLowerInvariant() && o.Purpose == purpose && !o.IsUsed)
            .OrderByDescending(o => o.CreatedAt)
            .FirstOrDefaultAsync();

        if (record == null) return OtpVerifyResult.NotFound;
        if (record.ExpiresAt < DateTime.UtcNow) return OtpVerifyResult.Expired;
        if (record.Attempts >= 5) return OtpVerifyResult.TooManyAttempts;

        record.Attempts++;
        await _db.SaveChangesAsync();

        if (!BCrypt.Net.BCrypt.Verify(otp, record.OtpHash))
            return OtpVerifyResult.Invalid;

        record.IsUsed = true;
        await _db.SaveChangesAsync();
        return OtpVerifyResult.Valid;
    }

    public async Task InvalidateAsync(string email, string purpose)
    {
        var records = await _db.OtpRecords
            .Where(o => o.Email == email.ToLowerInvariant() && o.Purpose == purpose && !o.IsUsed)
            .ToListAsync();
        foreach (var r in records) r.IsUsed = true;
        await _db.SaveChangesAsync();
    }

    private static string GenerateOtp()
    {
        using var rng = RandomNumberGenerator.Create();
        var bytes = new byte[4];
        rng.GetBytes(bytes);
        var num = Math.Abs(BitConverter.ToInt32(bytes, 0)) % 1_000_000;
        return num.ToString("D6");
    }
}
