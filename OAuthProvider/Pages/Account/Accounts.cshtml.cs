using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using OAuthProviderV2.Models;
using OAuthProviderV2.Services;

namespace OAuthProviderV2.Pages.Account;

public class AccountsModel : PageModel
{
    private readonly IAccountSessionService        _sessions;
    private readonly SignInManager<ApplicationUser> _signIn;
    private readonly UserManager<ApplicationUser>   _userMgr;

    public AccountsModel(IAccountSessionService sessions,
        SignInManager<ApplicationUser> signIn, UserManager<ApplicationUser> userMgr)
    {
        _sessions = sessions; _signIn = signIn; _userMgr = userMgr;
    }

    public List<AccountSession> Accounts { get; set; } = new();

    public void OnGet() => Accounts = _sessions.GetSessions(HttpContext);

    public async Task<IActionResult> OnPostSwitchAsync(string userId)
    {
        var user = await _userMgr.FindByIdAsync(userId);
        if (user == null) { _sessions.RemoveSession(HttpContext, userId); return RedirectToPage(); }
        await _signIn.SignOutAsync();
        await _signIn.SignInAsync(user, isPersistent: true);
        _sessions.SetActiveSession(HttpContext, userId);
        return Redirect("/");
    }

    public IActionResult OnPostRemove(string userId)
    {
        _sessions.RemoveSession(HttpContext, userId);
        return RedirectToPage();
    }

    public async Task<IActionResult> OnPostSignoutAll()
    {
        await _signIn.SignOutAsync();
        _sessions.ClearAll(HttpContext);
        return Redirect("/Account/Login");
    }
}
