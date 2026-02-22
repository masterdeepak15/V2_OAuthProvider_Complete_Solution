using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using OAuthProvider.Data;
using OAuthProvider.Models;

namespace OAuthProvider.Pages.Account;

public class LoginModel : PageModel
{
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly ApplicationDbContext _db;

    public LoginModel(
        SignInManager<ApplicationUser> signInManager,
        UserManager<ApplicationUser> userManager,
        ApplicationDbContext db)
    {
        _signInManager = signInManager;
        _userManager = userManager;
        _db = db;
    }

    [BindProperty(SupportsGet = true)]
    public string? ReturnUrl { get; set; }

    public string? Email { get; set; }
    public string? ErrorMessage { get; set; }

    public void OnGet()
    {
        // Nothing to do — just render the form
    }

    public async Task<IActionResult> OnPostAsync(string email, string password, string? returnUrl)
    {
        Email = email;

        if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(password))
        {
            ErrorMessage = "Email and password are required.";
            return Page();
        }

        var user = await _userManager.FindByEmailAsync(email);
        if (user == null)
        {
            ErrorMessage = "Invalid email or password.";
            await WriteAudit(null, false, "User not found");
            return Page();
        }

        var result = await _signInManager.PasswordSignInAsync(
            user, password, isPersistent: false, lockoutOnFailure: true);

        if (result.Succeeded)
        {
            user.LastLoginAt = DateTime.UtcNow;
            await _userManager.UpdateAsync(user);
            await WriteAudit(user.Id, true, null);

            var safeReturn = Url.IsLocalUrl(returnUrl) ? returnUrl : "/";
            return Redirect(safeReturn!);
        }

        if (result.IsLockedOut)
        {
            ErrorMessage = "Account is locked. Please contact an administrator.";
            await WriteAudit(user.Id, false, "Account locked");
            return Page();
        }

        ErrorMessage = "Invalid email or password.";
        await WriteAudit(user.Id, false, "Invalid password");
        return Page();
    }

    private async Task WriteAudit(string? userId, bool success, string? reason)
    {
        if (string.IsNullOrEmpty(userId)) return;

        _db.LoginAudits.Add(new LoginAudit
        {
            UserId = userId,
            IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString(),
            UserAgent = HttpContext.Request.Headers["User-Agent"].ToString(),
            Success = success,
            FailureReason = reason
        });
        await _db.SaveChangesAsync();
    }
}
