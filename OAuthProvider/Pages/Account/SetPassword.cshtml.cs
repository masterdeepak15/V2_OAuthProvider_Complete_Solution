// ── SetPassword.cshtml.cs ─────────────────────────────────────────────────────
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using OAuthProviderV2.Services;
using OAuthProviderV2.Services.Audit;

namespace OAuthProviderV2.Pages.Account;

public class SetPasswordModel : PageModel
{
    private readonly IOrganizationService _orgService;
    private readonly IAuditService _audit;

    public SetPasswordModel(IOrganizationService orgService, IAuditService audit)
    {
        _orgService = orgService;
        _audit = audit;
    }

    [BindProperty(SupportsGet = true)]
    public string? Token { get; set; }

    public bool TokenValid { get; set; }
    public bool Success { get; set; }
    public string? Email { get; set; }
    public string? ErrorMessage { get; set; }

    public async Task OnGetAsync()
    {
        if (string.IsNullOrEmpty(Token)) { TokenValid = false; return; }

        var user = await _orgService.GetUserByInviteTokenAsync(Token);
        TokenValid = user != null;
        Email = user?.Email;
    }

    public async Task<IActionResult> OnPostAsync(string? password, string? confirmPassword)
    {
        if (string.IsNullOrEmpty(Token)) { TokenValid = false; return Page(); }

        var user = await _orgService.GetUserByInviteTokenAsync(Token);
        if (user == null) { TokenValid = false; return Page(); }

        TokenValid = true;
        Email = user.Email;

        if (string.IsNullOrWhiteSpace(password) || password.Length < 8)
        {
            ErrorMessage = "Password must be at least 8 characters.";
            return Page();
        }
        if (password != confirmPassword)
        {
            ErrorMessage = "Passwords do not match.";
            return Page();
        }

        var (ok, error) = await _orgService.SetPasswordFromInviteAsync(Token, password);
        if (!ok)
        {
            ErrorMessage = error;
            return Page();
        }

        Success = true;
        await _audit.LogAsync(new AuditLogRequest
        {
            UserId        = user.Id,
            UserEmail     = user.Email,
            EventType     = "PasswordSet",
            EventCategory = "auth",
            Success       = true,
            HttpContext   = HttpContext,
        });
        return Page();
    }
}
