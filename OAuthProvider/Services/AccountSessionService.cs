using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;

namespace OAuthProviderV2.Services;

/// <summary>
/// One entry in the multi-account session list stored in the browser cookie.
/// </summary>
public class AccountSession
{
    public string UserId    { get; set; } = "";
    public string Email     { get; set; } = "";
    public string FullName  { get; set; } = "";
    public string? OrgName  { get; set; }
    public string? AvatarInitials { get; set; }
    public string AvatarColor    { get; set; } = "#6366f1";
    public DateTime SignedInAt   { get; set; } = DateTime.UtcNow;
    /// <summary>True = currently the active signed-in session (ASP.NET Identity cookie user).</summary>
    public bool IsActive    { get; set; } = false;
}

/// <summary>
/// Manages the "saved accounts" list in a separate browser cookie (like Google's GAPS cookie).
/// This is distinct from the ASP.NET Identity auth cookie — it just remembers which accounts
/// have been signed into on this browser so the picker can show them.
/// </summary>
public interface IAccountSessionService
{
    List<AccountSession> GetSessions(HttpContext ctx);
    void AddOrUpdateSession(HttpContext ctx, AccountSession session);
    void SetActiveSession(HttpContext ctx, string userId);
    void RemoveSession(HttpContext ctx, string userId);
    void ClearAll(HttpContext ctx);
}

public class AccountSessionService : IAccountSessionService
{
    private const string CookieName = ".OAuthProvider.Accounts";
    private readonly IDataProtector _protector;

    // Colour palette — deterministic per user based on email hash
    private static readonly string[] _colors = new[]
    {
        "#6366f1", "#8b5cf6", "#ec4899", "#14b8a6",
        "#f59e0b", "#10b981", "#3b82f6", "#ef4444",
    };

    public AccountSessionService(IDataProtectionProvider dpProvider)
    {
        _protector = dpProvider.CreateProtector("OAuthProvider.AccountSessions.v1");
    }

    public List<AccountSession> GetSessions(HttpContext ctx)
    {
        var cookie = ctx.Request.Cookies[CookieName];
        if (string.IsNullOrEmpty(cookie)) return new();
        try
        {
            var json = _protector.Unprotect(cookie);
            return JsonSerializer.Deserialize<List<AccountSession>>(json) ?? new();
        }
        catch { return new(); }
    }

    public void AddOrUpdateSession(HttpContext ctx, AccountSession session)
    {
        var sessions = GetSessions(ctx);
        var existing = sessions.FirstOrDefault(s => s.UserId == session.UserId);
        if (existing != null) sessions.Remove(existing);

        // Assign deterministic colour from email hash
        if (string.IsNullOrEmpty(session.AvatarColor) || session.AvatarColor == "#6366f1")
        {
            var idx = Math.Abs(session.Email.GetHashCode()) % _colors.Length;
            session.AvatarColor = _colors[idx];
        }

        sessions.Add(session);
        Save(ctx, sessions);
    }

    public void SetActiveSession(HttpContext ctx, string userId)
    {
        var sessions = GetSessions(ctx);
        foreach (var s in sessions) s.IsActive = s.UserId == userId;
        Save(ctx, sessions);
    }

    public void RemoveSession(HttpContext ctx, string userId)
    {
        var sessions = GetSessions(ctx);
        sessions.RemoveAll(s => s.UserId == userId);
        // If active was removed, set the most recent as active
        if (sessions.Any() && !sessions.Any(s => s.IsActive))
            sessions[^1].IsActive = true;
        Save(ctx, sessions);
    }

    public void ClearAll(HttpContext ctx)
    {
        ctx.Response.Cookies.Delete(CookieName);
    }

    private void Save(HttpContext ctx, List<AccountSession> sessions)
    {
        var json      = JsonSerializer.Serialize(sessions);
        var protected_ = _protector.Protect(json);
        ctx.Response.Cookies.Append(CookieName, protected_, new CookieOptions
        {
            HttpOnly  = true,
            Secure    = true,
            SameSite  = SameSiteMode.Lax,
            Expires   = DateTimeOffset.UtcNow.AddDays(30),
        });
    }
}
