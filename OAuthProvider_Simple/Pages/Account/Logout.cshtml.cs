using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using OAuthProvider.Models;

namespace OAuthProvider.Pages.Account;

// The logout form is rendered inside an interactive Blazor component (MainLayout).
// Blazor's antiforgery token differs from Razor Pages' token, so we skip
// antiforgery validation here. The worst-case CSRF risk (forced logout) is acceptable.
[IgnoreAntiforgeryToken]
public class LogoutModel : PageModel
{
    private readonly SignInManager<ApplicationUser> _signInManager;

    public LogoutModel(SignInManager<ApplicationUser> signInManager)
    {
        _signInManager = signInManager;
    }

    public async Task<IActionResult> OnPostAsync()
    {
        await _signInManager.SignOutAsync();
        return Redirect("/Account/Login");
    }

    // Block GET-based logout attempts
    public IActionResult OnGet() => Redirect("/");
}
