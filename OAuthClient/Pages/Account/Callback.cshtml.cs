using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Caching.Memory;
using OAuthClient.Models;
using OAuthClient.Services;

namespace OAuthClient.Pages.Account;

/// <summary>
/// The OAuth Provider redirects here after the user authenticates.
/// URL: /auth/callback?code=XXX&state=YYY
///
/// This page must be static SSR (no Blazor rendermode) because it
/// writes the Set-Cookie header directly to the HTTP response.
/// </summary>
public class CallbackModel : PageModel
{
    private readonly IOAuthFlowService _oauth;
    private readonly ITokenStore _tokens;
    private readonly IMemoryCache _cache;
    private readonly OAuthSettings _settings;
    private readonly ILogger<CallbackModel> _logger;

    public string? ErrorMessage { get; private set; }

    public CallbackModel(
        IOAuthFlowService oauth,
        ITokenStore tokens,
        IMemoryCache cache,
        OAuthSettings settings,
        ILogger<CallbackModel> logger)
    {
        _oauth    = oauth;
        _tokens   = tokens;
        _cache    = cache;
        _settings = settings;
        _logger   = logger;
    }

    public async Task<IActionResult> OnGetAsync(
        string? code,
        string? state,
        string? error,
        string? error_description)
    {
        // ── 1. Handle provider errors ─────────────────────────────────────
        if (!string.IsNullOrEmpty(error))
        {
            _logger.LogWarning("OAuth provider returned error: {Error} — {Desc}", error, error_description);
            ErrorMessage = error_description ?? error;
            return Page();
        }

        if (string.IsNullOrEmpty(code) || string.IsNullOrEmpty(state))
        {
            ErrorMessage = "Missing code or state parameter.";
            return Page();
        }

        // ── 2. Validate state (CSRF protection) ───────────────────────────
        if (!_cache.TryGetValue<string>($"pkce:{state}", out var codeVerifier)
            || string.IsNullOrEmpty(codeVerifier))
        {
            ErrorMessage = "Invalid or expired state. Please try signing in again.";
            return Page();
        }

        var returnUrl = _cache.Get<string>($"ret:{state}") ?? "/";

        // Consume both cache entries — one-time use
        _cache.Remove($"pkce:{state}");
        _cache.Remove($"ret:{state}");

        // ── 3. Exchange authorization code for tokens ─────────────────────
        TokenResponse tokenResp;
        try
        {
            tokenResp = await _oauth.ExchangeCodeAsync(code, codeVerifier, _settings.RedirectUri);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Token exchange failed");
            ErrorMessage = "Could not reach the OAuth Provider. Is it running on port 5000?";
            return Page();
        }

        if (!string.IsNullOrEmpty(tokenResp.Error))
        {
            ErrorMessage = tokenResp.ErrorDescription ?? tokenResp.Error;
            return Page();
        }

        if (string.IsNullOrEmpty(tokenResp.AccessToken))
        {
            ErrorMessage = "No access token returned.";
            return Page();
        }

        // ── 4. Fetch user profile ─────────────────────────────────────────
        UserProfile? profile;
        try
        {
            profile = await _oauth.GetUserInfoAsync(tokenResp.AccessToken);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "UserInfo call failed");
            profile = null;
        }

        // ── 5. Build ClaimsPrincipal ──────────────────────────────────────
        var sessionId = Guid.NewGuid().ToString("N");

        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, profile?.Sub ?? sessionId),
            new(ClaimTypes.Email,          profile?.Email ?? ""),
            new(ClaimTypes.Name,           profile?.Name ?? profile?.Email ?? "User"),
            new("given_name",              profile?.GivenName ?? ""),
            new("family_name",             profile?.FamilyName ?? ""),
            new("session_id",              sessionId),
        };

        var identity  = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        var principal = new ClaimsPrincipal(identity);

        // ── 6. Store tokens server-side (tokens never go to browser) ─────
        var expiresAt = DateTime.UtcNow.AddSeconds(tokenResp.ExpiresIn > 0 ? tokenResp.ExpiresIn : 3600);
        _tokens.Save(sessionId, tokenResp.AccessToken, tokenResp.RefreshToken, expiresAt);

        // ── 7. Issue app session cookie ───────────────────────────────────
        await HttpContext.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            principal,
            new AuthenticationProperties
            {
                IsPersistent = true,
                ExpiresUtc   = DateTimeOffset.UtcNow.AddDays(7),
            });

        return Redirect(returnUrl);
    }
}
