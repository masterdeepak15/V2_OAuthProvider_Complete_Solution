// ── VerifyEmail.cshtml.cs ─────────────────────────────────────────────────────
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using OAuthProviderV2.Services;
using OAuthProviderV2.Services.Audit;

namespace OAuthProviderV2.Pages.Account;

public class VerifyEmailModel : PageModel
{
    private readonly IOrganizationService _orgService;
    private readonly IAuditService _audit;

    public VerifyEmailModel(IOrganizationService orgService, IAuditService audit)
    {
        _orgService = orgService;
        _audit = audit;
    }

    public bool Success { get; set; }
    public string? Message { get; set; }

    public async Task OnGetAsync(string? token)
    {
        if (string.IsNullOrEmpty(token))
        {
            Message = "Invalid verification link.";
            return;
        }

        Success = await _orgService.VerifyUserEmailAsync(token);
        Message = Success
            ? "Your email has been verified! You can now sign in."
            : "This verification link is invalid or has expired. Please ask your administrator for a new link.";

        if (Success)
        {
            await _audit.LogAsync(new AuditLogRequest
            {
                EventType     = "EmailVerified",
                EventCategory = "auth",
                Success       = true,
                HttpContext   = HttpContext,
            });
        }
    }
}
