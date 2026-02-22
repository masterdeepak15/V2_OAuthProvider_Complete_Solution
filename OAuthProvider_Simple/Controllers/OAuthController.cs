using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using OAuthProvider.Data;
using OAuthProvider.Models;
using OAuthProvider.Services;

namespace OAuthProvider.Controllers;

[ApiController]
public class OAuthController : ControllerBase
{
    private readonly IOAuthService _oauth;
    private readonly ApplicationDbContext _db;
    private readonly UserManager<ApplicationUser> _userManager;

    public OAuthController(IOAuthService oauth, ApplicationDbContext db, UserManager<ApplicationUser> userManager)
    {
        _oauth = oauth;
        _db = db;
        _userManager = userManager;
    }

    // GET /authorize - Show consent screen or redirect
    [HttpGet("/authorize")]
    public async Task<IActionResult> Authorize(
        [FromQuery] string response_type,
        [FromQuery] string client_id,
        [FromQuery] string redirect_uri,
        [FromQuery] string? scope,
        [FromQuery] string? state,
        [FromQuery] string? code_challenge,
        [FromQuery] string? code_challenge_method)
    {
        if (response_type != "code")
            return BadRequest(new { error = "unsupported_response_type" });

        var client = await _oauth.ValidateClientAsync(client_id);
        if (client == null)
            return BadRequest(new { error = "invalid_client" });

        if (!await _oauth.ValidateRedirectUriAsync(client.Id, redirect_uri))
            return BadRequest(new { error = "invalid_redirect_uri" });

        if (!User.Identity?.IsAuthenticated == true)
        {
            var returnUrl = Request.QueryString.Value;
            return Redirect($"/Account/Login?returnUrl=/authorize{Uri.EscapeDataString(returnUrl ?? "")}");
        }

        var user = await _userManager.GetUserAsync(User);
        if (user == null) return Unauthorized();

        var authCode = await _oauth.CreateAuthorizationCodeAsync(client.Id, user.Id, redirect_uri, scope ?? "openid", code_challenge, code_challenge_method);
        var callbackUrl = $"{redirect_uri}?code={authCode.Code}";
        if (!string.IsNullOrEmpty(state)) callbackUrl += $"&state={Uri.EscapeDataString(state)}";

        return Redirect(callbackUrl);
    }

    // POST /token - Token endpoint
    [HttpPost("/token")]
    public async Task<IActionResult> Token([FromForm] TokenRequest request)
    {
        // Support Basic auth for client credentials
        var clientId = request.client_id;
        var clientSecret = request.client_secret;

        if (string.IsNullOrEmpty(clientId))
        {
            var authHeader = Request.Headers["Authorization"].ToString();
            if (authHeader.StartsWith("Basic "))
            {
                var decoded = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(authHeader[6..]));
                var parts = decoded.Split(':', 2);
                clientId = parts[0];
                clientSecret = parts.Length > 1 ? parts[1] : null;
            }
        }

        if (string.IsNullOrEmpty(clientId))
            return BadRequest(new { error = "invalid_client" });

        var client = await _oauth.ValidateClientAsync(clientId, clientSecret);
        if (client == null && request.grant_type != "authorization_code")
            return Unauthorized(new { error = "invalid_client" });

        switch (request.grant_type)
        {
            case "authorization_code":
            {
                var (access, refresh, error) = await _oauth.ExchangeCodeAsync(
                    request.code ?? "", clientId, request.code_verifier, request.redirect_uri ?? "");
                if (error != null) return BadRequest(new { error });
                return TokenResponse(access!, refresh, client!);
            }
            case "client_credentials":
            {
                var (access, refresh, error) = await _oauth.ClientCredentialsAsync(clientId);
                if (error != null) return BadRequest(new { error });
                return TokenResponse(access!, refresh, client!);
            }
            case "refresh_token":
            {
                var (access, refresh, error) = await _oauth.RefreshTokenAsync(request.refresh_token ?? "", clientId);
                if (error != null) return BadRequest(new { error });
                return TokenResponse(access!, refresh, client!);
            }
            default:
                return BadRequest(new { error = "unsupported_grant_type" });
        }
    }

    // GET /userinfo
    [HttpGet("/userinfo")]
    [Authorize]
    public async Task<IActionResult> UserInfo()
    {
        var authHeader = Request.Headers["Authorization"].ToString();
        if (!authHeader.StartsWith("Bearer ")) return Unauthorized();
        var token = authHeader[7..];

        var user = await _oauth.GetUserFromTokenAsync(token);
        if (user == null) return Unauthorized();

        return Ok(new
        {
            sub = user.Id,
            email = user.Email,
            email_verified = user.EmailConfirmed,
            given_name = user.FirstName,
            family_name = user.LastName,
            name = $"{user.FirstName} {user.LastName}".Trim()
        });
    }

    // POST /revoke
    [HttpPost("/revoke")]
    public async Task<IActionResult> Revoke([FromForm] string token)
    {
        await _oauth.RevokeTokenAsync(token);
        return Ok();
    }

    // GET /.well-known/openid-configuration
    [HttpGet("/.well-known/openid-configuration")]
    public IActionResult OpenIdConfig()
    {
        var baseUrl = $"{Request.Scheme}://{Request.Host}";
        return Ok(new
        {
            issuer = baseUrl,
            authorization_endpoint = $"{baseUrl}/authorize",
            token_endpoint = $"{baseUrl}/token",
            userinfo_endpoint = $"{baseUrl}/userinfo",
            revocation_endpoint = $"{baseUrl}/revoke",
            response_types_supported = new[] { "code" },
            grant_types_supported = new[] { "authorization_code", "client_credentials", "refresh_token" },
            scopes_supported = new[] { "openid", "profile", "email", "api" },
            token_endpoint_auth_methods_supported = new[] { "client_secret_basic", "client_secret_post" },
            code_challenge_methods_supported = new[] { "S256", "plain" }
        });
    }

    private IActionResult TokenResponse(AccessToken access, RefreshToken? refresh, OAuthClient client)
    {
        var response = new Dictionary<string, object>
        {
            ["access_token"] = access.Token,
            ["token_type"] = "Bearer",
            ["expires_in"] = client.AccessTokenLifetimeSeconds,
            ["scope"] = access.Scopes
        };
        if (refresh != null) response["refresh_token"] = refresh.Token;
        return Ok(response);
    }
}

public class TokenRequest
{
    public string grant_type { get; set; } = string.Empty;
    public string? client_id { get; set; }
    public string? client_secret { get; set; }
    public string? code { get; set; }
    public string? redirect_uri { get; set; }
    public string? code_verifier { get; set; }
    public string? refresh_token { get; set; }
    public string? scope { get; set; }
}
