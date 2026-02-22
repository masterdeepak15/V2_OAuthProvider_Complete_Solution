using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using OAuthProviderV2.Data;
using OAuthProviderV2.Models;
using OAuthProviderV2.Services;
using OAuthProviderV2.Services.Audit;
using OAuthProviderV2.Services.Email;

namespace OAuthProviderV2.Pages.Account;

public class LoginModel : PageModel
{
    private readonly SignInManager<ApplicationUser>  _signIn;
    private readonly UserManager<ApplicationUser>    _userMgr;
    private readonly ApplicationDbContext            _db;
    private readonly IAuditService                   _audit;
    private readonly IEmailService                   _email;
    private readonly IAccountSessionService          _sessions;

    public LoginModel(
        SignInManager<ApplicationUser> signIn,
        UserManager<ApplicationUser> userMgr,
        ApplicationDbContext db,
        IAuditService audit,
        IEmailService email,
        IAccountSessionService sessions)
    {
        _signIn   = signIn;
        _userMgr  = userMgr;
        _db       = db;
        _audit    = audit;
        _email    = email;
        _sessions = sessions;
    }

    [BindProperty(SupportsGet = true)]
    public string? ReturnUrl { get; set; }

    /// picker | email | password
    public string ViewMode { get; set; } = "email";
    public string? Email { get; set; }
    public string? ErrorMessage { get; set; }
    public bool ShowVerificationPending { get; set; }
    public string ActiveColor { get; set; } = "#6366f1";
    public List<AccountSession> SavedAccounts { get; set; } = new();

    public void OnGet(string? mode)
    {
        SavedAccounts = _sessions.GetSessions(HttpContext);
        ViewMode = (SavedAccounts.Any() && mode != "new") ? "picker" : "email";
    }

    public async Task<IActionResult> OnPostEmailAsync(string email, string? returnUrl)
    {
        ReturnUrl = returnUrl;
        Email = email?.Trim().ToLowerInvariant();
        SavedAccounts = _sessions.GetSessions(HttpContext);
        if (string.IsNullOrEmpty(Email)) { ErrorMessage = "Enter your email."; ViewMode = "email"; return Page(); }
        var user = await _userMgr.FindByEmailAsync(Email);
        if (user == null) { ErrorMessage = "No account found with that email."; ViewMode = "email"; return Page(); }
        ActiveColor = DetermineColor(Email);
        ViewMode = "password";
        return Page();
    }

    public async Task<IActionResult> OnPostPasswordAsync(string email, string password, string? returnUrl)
    {
        ReturnUrl = returnUrl;
        Email = email?.Trim().ToLowerInvariant();
        ActiveColor = DetermineColor(Email ?? "");
        SavedAccounts = _sessions.GetSessions(HttpContext);
        var session = _audit.ParseSession(HttpContext);
        var user = await _userMgr.FindByEmailAsync(Email ?? "");
        if (user == null) { ErrorMessage = "Invalid email or password."; ViewMode = "password"; return Page(); }

        if (user.OrganizationId.HasValue)
        {
            var org = await _db.Organizations.FindAsync(user.OrganizationId.Value);
            if (org?.IsBlocked == true)
            {
                ErrorMessage = "This organization has been suspended.";
                await LogAsync(user, false, "Org blocked", session); ViewMode = "password"; return Page();
            }
        }

        if (!user.IsEmailVerified && !await _userMgr.IsInRoleAsync(user, "SuperAdmin"))
        {
            ShowVerificationPending = true;
            await LogAsync(user, false, "Email not verified", session); ViewMode = "password"; return Page();
        }

        if (!user.IsActive)
        {
            ErrorMessage = "Your account has been disabled.";
            await LogAsync(user, false, "Account inactive", session); ViewMode = "password"; return Page();
        }

        var result = await _signIn.PasswordSignInAsync(user, password, isPersistent: true, lockoutOnFailure: true);

        if (result.Succeeded)
        {
            user.LastLoginAt = DateTime.UtcNow;
            await _userMgr.UpdateAsync(user);
            await LogAsync(user, true, null, session);

            string? orgName = null;
            if (user.OrganizationId.HasValue)
            {
                var org = await _db.Organizations.FindAsync(user.OrganizationId.Value);
                orgName = org?.Name;
                _ = _email.SendLoginAlertAsync(user.OrganizationId.Value, user.Email!,
                    user.FullName ?? user.Email!, session.IpAddress ?? "unknown",
                    $"{session.Browser} {session.BrowserVersion}",
                    $"{session.OperatingSystem} {session.OsVersion}", "Unknown");
            }

            _sessions.AddOrUpdateSession(HttpContext, new AccountSession
            {
                UserId = user.Id, Email = user.Email!, FullName = user.FullName ?? "",
                OrgName = orgName ?? "Super Admin", AvatarInitials = Initials(user), IsActive = true,
            });
            _sessions.SetActiveSession(HttpContext, user.Id);

            return Redirect(Url.IsLocalUrl(returnUrl) ? returnUrl! : "/");
        }

        if (result.IsLockedOut)
        {
            ErrorMessage = "Account locked. Try again in 15 minutes.";
            await LogAsync(user, false, "Locked out", session); ViewMode = "password"; return Page();
        }

        ErrorMessage = "Incorrect password.";
        await LogAsync(user, false, "Wrong password", session);
        ViewMode = "password"; return Page();
    }

    public async Task<IActionResult> OnPostSwitchAccountAsync(string switchUserId, string? returnUrl)
    {
        var acct = _sessions.GetSessions(HttpContext).FirstOrDefault(s => s.UserId == switchUserId);
        if (acct == null) return Redirect("/Account/Login");
        var user = await _userMgr.FindByIdAsync(switchUserId);
        if (user == null) { _sessions.RemoveSession(HttpContext, switchUserId); return Redirect("/Account/Login"); }
        await _signIn.SignOutAsync();
        await _signIn.SignInAsync(user, isPersistent: true);
        _sessions.SetActiveSession(HttpContext, switchUserId);
        user.LastLoginAt = DateTime.UtcNow;
        await _userMgr.UpdateAsync(user);
        return Redirect(Url.IsLocalUrl(returnUrl) ? returnUrl! : "/");
    }

    public async Task<IActionResult> OnPostSignoutAllAsync(string? returnUrl)
    {
        await _signIn.SignOutAsync();
        _sessions.ClearAll(HttpContext);
        return Redirect("/Account/Login?ReturnUrl=" + Uri.EscapeDataString(returnUrl ?? "/"));
    }

    private static string Initials(ApplicationUser u)
    {
        var f = u.FirstName?.Trim() ?? ""; var l = u.LastName?.Trim() ?? "";
        if (f.Length > 0 && l.Length > 0) return $"{f[0]}{l[0]}".ToUpper();
        if (f.Length > 0) return f[0..1].ToUpper();
        return u.Email?[0..1].ToUpper() ?? "?";
    }

    private static readonly string[] _colors =
        { "#6366f1","#8b5cf6","#ec4899","#14b8a6","#f59e0b","#10b981","#3b82f6","#ef4444" };

    private static string DetermineColor(string email) =>
        _colors[Math.Abs(email.GetHashCode()) % _colors.Length];

    private async Task LogAsync(ApplicationUser user, bool success, string? reason, SessionInfo session)
    {
        _db.AuditLogs.Add(new AuditLog
        {
            OrganizationId = user.OrganizationId, UserId = user.Id, UserEmail = user.Email,
            EventType = success ? "LoginSuccess" : "LoginFailed", EventCategory = "auth",
            Success = success, FailureReason = reason,
            IpAddress = session.IpAddress, UserAgent = session.UserAgent,
            Browser = session.Browser, BrowserVersion = session.BrowserVersion,
            OperatingSystem = session.OperatingSystem, OsVersion = session.OsVersion,
            DeviceType = session.DeviceType, DeviceBrand = session.DeviceBrand,
        });
        await _db.SaveChangesAsync();
    }
}
