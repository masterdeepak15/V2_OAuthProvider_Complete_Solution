using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using OAuthClient.Services;

namespace OAuthClient.Pages.Account;

[IgnoreAntiforgeryToken]   // form is posted from inside the Blazor interactive layout
public class LogoutModel : PageModel
{
    private readonly ITokenStore _tokens;
    private readonly IOAuthFlowService _oauth;

    public LogoutModel(ITokenStore tokens, IOAuthFlowService oauth)
    {
        _tokens = tokens;
        _oauth  = oauth;
    }

    public async Task<IActionResult> OnPostAsync()
    {
        // Revoke the access token at the provider
        var sessionId = User.FindFirst("session_id")?.Value;
        if (!string.IsNullOrEmpty(sessionId))
        {
            var entry = _tokens.Get(sessionId);
            if (entry != null)
            {
                try { await _oauth.RevokeTokenAsync(entry.AccessToken); } catch { /* best-effort */ }
                _tokens.Delete(sessionId);
            }
        }

        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        return Redirect("/Account/Login");
    }

    public IActionResult OnGet() => Redirect("/");
}
