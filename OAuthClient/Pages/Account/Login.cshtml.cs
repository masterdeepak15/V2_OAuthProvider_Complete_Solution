using System.Security.Cryptography;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Caching.Memory;
using OAuthClient.Services;

namespace OAuthClient.Pages.Account;

public class LoginModel : PageModel
{
    private readonly IOAuthFlowService _oauth;
    private readonly IPkceService _pkce;
    private readonly IMemoryCache _cache;

    public LoginModel(IOAuthFlowService oauth, IPkceService pkce, IMemoryCache cache)
    {
        _oauth = oauth;
        _pkce = pkce;
        _cache = cache;
    }

    [BindProperty(SupportsGet = true)]
    public string? ReturnUrl { get; set; }

    public string? Error { get; set; }

    public void OnGet()
    {
        // Grab error from query string if provider sent one back
        Error = Request.Query["error_description"].FirstOrDefault()
             ?? Request.Query["error"].FirstOrDefault();
    }

    public IActionResult OnPost(string? returnUrl)
    {
        // 1. Generate cryptographically-secure state & PKCE pair
        var state = GenerateState();
        var pair  = _pkce.Generate();

        // 2. Store verifier + returnUrl server-side for 10 minutes
        //    Key = state value, so we can retrieve it in the callback
        _cache.Set($"pkce:{state}", pair.Verifier, TimeSpan.FromMinutes(10));
        _cache.Set($"ret:{state}",  returnUrl ?? "/",  TimeSpan.FromMinutes(10));

        // 3. Redirect browser to provider's /authorize
        var authorizeUrl = _oauth.BuildAuthorizeUrl(state, pair.Challenge, pair.Method);
        return Redirect(authorizeUrl);
    }

    private static string GenerateState()
    {
        var bytes = new byte[32];
        RandomNumberGenerator.Fill(bytes);
        return Convert.ToBase64String(bytes)
                      .Replace("+", "-").Replace("/", "_").TrimEnd('=');
    }
}
