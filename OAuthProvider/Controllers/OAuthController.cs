using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OAuthProviderV2.Services;
using OAuthProviderV2.Services.Audit;

namespace OAuthProviderV2.Controllers;

[ApiController]
public class OAuthController : ControllerBase
{
    private readonly IOAuthService _oauth;
    private readonly IAuditService _audit;
    private readonly IConfiguration _config;

    public OAuthController(IOAuthService oauth, IAuditService audit, IConfiguration config)
    {
        _oauth  = oauth;
        _audit  = audit;
        _config = config;
    }

    // ── Discovery ──────────────────────────────────────────────────────────────

    [HttpGet("/.well-known/openid-configuration")]
    public IActionResult Discovery()
    {
        var issuer = _config["Jwt:Issuer"];
        return Ok(new
        {
            issuer,
            authorization_endpoint           = $"{issuer}/authorize",
            token_endpoint                   = $"{issuer}/token",
            userinfo_endpoint                = $"{issuer}/userinfo",
            revocation_endpoint              = $"{issuer}/revoke",
            response_types_supported         = new[] { "code" },
            grant_types_supported            = new[] { "authorization_code", "client_credentials", "refresh_token" },
            subject_types_supported          = new[] { "public" },
            id_token_signing_alg_values      = new[] { "HS256" },
            scopes_supported                 = new[] { "openid", "profile", "email", "api", "offline_access" },
            token_endpoint_auth_methods      = new[] { "client_secret_post", "client_secret_basic" },
            code_challenge_methods_supported = new[] { "S256", "plain" },
        });
    }

    // ── CORS preflight for token endpoint ─────────────────────────────────────

    [HttpOptions("/token")]
    public async Task<IActionResult> TokenPreflight(
        [FromHeader(Name = "Origin")]      string? origin,
        [FromQuery]                         string? client_id)
    {
        if (string.IsNullOrEmpty(origin) || string.IsNullOrEmpty(client_id))
            return BadRequest();

        var client = await _oauth.ValidateClientAsync(client_id);
        if (client == null) return Unauthorized();

        if (!await _oauth.ValidateCorsOriginAsync(client.Id, origin))
            return Forbid();

        Response.Headers["Access-Control-Allow-Origin"]  = origin;
        Response.Headers["Access-Control-Allow-Methods"] = "POST, OPTIONS";
        Response.Headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization";
        Response.Headers["Access-Control-Max-Age"]       = "86400";
        return NoContent();
    }

    // ── Authorization endpoint ────────────────────────────────────────────────

    [HttpGet("/authorize")]
    public async Task<IActionResult> Authorize(
        [FromQuery] string? response_type,
        [FromQuery] string? client_id,
        [FromQuery] string? redirect_uri,
        [FromQuery] string? scope,
        [FromQuery] string? state,
        [FromQuery] string? code_challenge,
        [FromQuery] string? code_challenge_method)
    {
        if (response_type != "code")
            return BadRequest(new { error = "unsupported_response_type" });

        if (string.IsNullOrEmpty(client_id) || string.IsNullOrEmpty(redirect_uri))
            return BadRequest(new { error = "invalid_request" });

        var client = await _oauth.ValidateClientAsync(client_id);
        if (client == null)
            return BadRequest(new { error = "invalid_client" });

        if (!await _oauth.ValidateRedirectUriAsync(client.Id, redirect_uri))
            return BadRequest(new { error = "redirect_uri_mismatch" });

        // Require authentication — redirect to login (which returns here via ReturnUrl)
        if (!User.Identity?.IsAuthenticated ?? true)
        {
            var qs = Request.QueryString.Value;
            return Redirect($"/Account/Login?ReturnUrl={Uri.EscapeDataString($"/authorize{qs}")}");
        }

        // Show consent screen — the user must explicitly approve the client's access request.
        // The consent page handles code issuance after the user clicks "Allow".
        var consentUrl = $"/Account/Consent" +
            $"?client_id={Uri.EscapeDataString(client_id)}" +
            $"&redirect_uri={Uri.EscapeDataString(redirect_uri)}" +
            $"&scope={Uri.EscapeDataString(scope ?? "openid")}" +
            (state != null ? $"&state={Uri.EscapeDataString(state)}" : "") +
            (code_challenge != null ? $"&code_challenge={Uri.EscapeDataString(code_challenge)}" : "") +
            (code_challenge_method != null ? $"&code_challenge_method={Uri.EscapeDataString(code_challenge_method)}" : "");

        return Redirect(consentUrl);
    }

    // ── Token endpoint ────────────────────────────────────────────────────────

    [HttpPost("/token")]
    public async Task<IActionResult> Token()
    {
        var form = await Request.ReadFormAsync();
        var (clientId, clientSecret) = ExtractClientCredentials(form);

        if (string.IsNullOrEmpty(clientId))
            return Unauthorized(new { error = "invalid_client" });

        // Per-client dynamic CORS
        var origin = Request.Headers["Origin"].FirstOrDefault();
        if (!string.IsNullOrEmpty(origin))
        {
            var c = await _oauth.ValidateClientAsync(clientId);
            if (c != null && await _oauth.ValidateCorsOriginAsync(c.Id, origin))
                Response.Headers["Access-Control-Allow-Origin"] = origin;
        }

        var grantType = form["grant_type"].ToString();
        return grantType switch
        {
            "authorization_code" => await HandleAuthCodeAsync(form, clientId),
            "client_credentials" => await HandleClientCredsAsync(clientId, clientSecret),
            "refresh_token"      => await HandleRefreshAsync(form, clientId),
            _                    => BadRequest(new { error = "unsupported_grant_type" }),
        };
    }

    private async Task<IActionResult> HandleAuthCodeAsync(IFormCollection form, string clientId)
    {
        var code        = form["code"].ToString();
        var redirectUri = form["redirect_uri"].ToString();
        var verifier    = form["code_verifier"].ToString();

        var (access, refresh, error) = await _oauth.ExchangeCodeAsync(code, clientId, verifier, redirectUri);
        if (error != null) return BadRequest(new { error });

        await _audit.LogAsync(new AuditLogRequest
        {
            EventType     = "TokenIssued",
            EventCategory = "oauth",
            HttpContext   = HttpContext,
        });

        return BuildTokenResponse(access!, refresh);
    }

    private async Task<IActionResult> HandleClientCredsAsync(string clientId, string? clientSecret)
    {
        var (access, _, error) = await _oauth.ClientCredentialsAsync(clientId);
        if (error != null) return BadRequest(new { error });
        return BuildTokenResponse(access!, null);
    }

    private async Task<IActionResult> HandleRefreshAsync(IFormCollection form, string clientId)
    {
        var refreshToken = form["refresh_token"].ToString();
        var (access, refresh, error) = await _oauth.RefreshTokenAsync(refreshToken, clientId);
        if (error != null) return BadRequest(new { error });
        return BuildTokenResponse(access!, refresh);
    }

    private IActionResult BuildTokenResponse(OAuthProviderV2.Models.AccessToken access, OAuthProviderV2.Models.RefreshToken? refresh)
    {
        var result = new Dictionary<string, object>
        {
            ["access_token"] = access.Token,
            ["token_type"]   = "Bearer",
            ["expires_in"]   = (int)(access.ExpiresAt - DateTime.UtcNow).TotalSeconds,
            ["scope"]        = access.Scopes,
        };
        if (refresh != null) result["refresh_token"] = refresh.Token;
        return Ok(result);
    }

    // ── UserInfo endpoint ─────────────────────────────────────────────────────

    [HttpGet("/userinfo")]
    public async Task<IActionResult> UserInfo()
    {
        var authHeader = Request.Headers["Authorization"].ToString();
        if (!authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            return Unauthorized(new { error = "invalid_token" });

        var token = authHeader["Bearer ".Length..].Trim();
        var user  = await _oauth.GetUserFromTokenAsync(token);
        if (user == null) return Unauthorized(new { error = "invalid_token" });

        await _audit.LogAsync(new AuditLogRequest
        {
            UserId        = user.Id,
            EventType     = "UserinfoAccessed",
            EventCategory = "oauth",
            HttpContext   = HttpContext,
        });

        return Ok(new
        {
            sub            = user.Id,
            email          = user.Email,
            email_verified = user.EmailConfirmed,
            given_name     = user.FirstName,
            family_name    = user.LastName,
            name           = user.FullName,
        });
    }

    // ── Revocation endpoint ───────────────────────────────────────────────────

    [HttpPost("/revoke")]
    public async Task<IActionResult> Revoke()
    {
        var form  = await Request.ReadFormAsync();
        var token = form["token"].ToString();
        if (!string.IsNullOrEmpty(token))
        {
            await _oauth.RevokeTokenAsync(token);
            await _audit.LogAsync(new AuditLogRequest
            {
                EventType     = "TokenRevoked",
                EventCategory = "oauth",
                HttpContext   = HttpContext,
            });
        }
        return Ok(); // RFC 7009: always 200
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private (string? clientId, string? clientSecret) ExtractClientCredentials(IFormCollection form)
    {
        // Try form body first
        var clientId     = form["client_id"].ToString();
        var clientSecret = form["client_secret"].ToString();
        if (!string.IsNullOrEmpty(clientId))
            return (clientId, string.IsNullOrEmpty(clientSecret) ? null : clientSecret);

        // Try HTTP Basic auth header
        var authHeader = Request.Headers["Authorization"].ToString();
        if (authHeader.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                var decoded  = Encoding.UTF8.GetString(Convert.FromBase64String(authHeader[6..]));
                var colon    = decoded.IndexOf(':');
                if (colon > 0)
                    return (decoded[..colon], decoded[(colon + 1)..]);
            }
            catch { /* ignore malformed header */ }
        }

        return (null, null);
    }
}
