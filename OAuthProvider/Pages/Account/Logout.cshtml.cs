using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using OAuthProviderV2.Models;
using OAuthProviderV2.Services;

namespace OAuthProviderV2.Pages.Account;

public class LogoutModel : PageModel
{
    private readonly SignInManager<ApplicationUser> _signIn;
    private readonly IAccountSessionService         _sessions;
    private readonly UserManager<ApplicationUser>   _userMgr;

    public LogoutModel(SignInManager<ApplicationUser> signIn,
        IAccountSessionService sessions, UserManager<ApplicationUser> userMgr)
    {
        _signIn = signIn; _sessions = sessions; _userMgr = userMgr;
    }

    // GET — render the auto-submit form
    public void OnGet() { }

    // POST — sign out
    public async Task<IActionResult> OnPostAsync(string? signOutUserId)
    {
        if (!string.IsNullOrEmpty(signOutUserId))
        {
            _sessions.RemoveSession(HttpContext, signOutUserId);
            var remaining = _sessions.GetSessions(HttpContext);
            if (remaining.Any())
            {
                var next = remaining.OrderByDescending(s => s.SignedInAt).First();
                await _signIn.SignOutAsync();
                var nextUser = await _userMgr.FindByIdAsync(next.UserId);
                if (nextUser != null)
                {
                    await _signIn.SignInAsync(nextUser, isPersistent: true);
                    _sessions.SetActiveSession(HttpContext, next.UserId);
                    return Redirect("/");
                }
            }
        }

        await _signIn.SignOutAsync();
        _sessions.ClearAll(HttpContext);
        return Redirect("/Account/Login");
    }
}
