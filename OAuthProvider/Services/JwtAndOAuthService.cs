using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using OAuthProviderV2.Data;
using OAuthProviderV2.Models;

namespace OAuthProviderV2.Services;

// ─── JWT ──────────────────────────────────────────────────────────────────────

public interface IJwtService
{
    string GenerateAccessToken(ApplicationUser? user, OAuthClient client, string scopes);
    string GenerateRefreshToken();
    ClaimsPrincipal? ValidateToken(string token);
}

public class JwtService : IJwtService
{
    private readonly IConfiguration _config;
    public JwtService(IConfiguration config) => _config = config;

    public string GenerateAccessToken(ApplicationUser? user, OAuthClient client, string scopes)
    {
        var key     = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:SigningKey"]!));
        var creds   = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        var issuer  = _config["Jwt:Issuer"];
        var claims  = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Iss, issuer!),
            new(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString()),
            new("client_id", client.ClientId),
            new("org_id", client.OrganizationId.ToString()),
            new("scope", scopes),
        };

        if (user != null)
        {
            claims.Add(new(JwtRegisteredClaimNames.Sub, user.Id));
            claims.Add(new(JwtRegisteredClaimNames.Email, user.Email ?? ""));
            if (user.FirstName != null) claims.Add(new("given_name", user.FirstName));
            if (user.LastName  != null) claims.Add(new("family_name", user.LastName));
        }

        var token = new JwtSecurityToken(
            issuer: issuer,
            claims: claims,
            expires: DateTime.UtcNow.AddSeconds(client.AccessTokenLifetimeSeconds),
            signingCredentials: creds);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    public string GenerateRefreshToken()
    {
        var bytes = new byte[64];
        RandomNumberGenerator.Fill(bytes);
        return Convert.ToBase64String(bytes).Replace("+", "-").Replace("/", "_").TrimEnd('=');
    }

    public ClaimsPrincipal? ValidateToken(string token)
    {
        try
        {
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:SigningKey"]!));
            var handler = new JwtSecurityTokenHandler();
            return handler.ValidateToken(token, new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey         = key,
                ValidateIssuer           = true,
                ValidIssuer              = _config["Jwt:Issuer"],
                ValidateAudience         = false,
                ClockSkew                = TimeSpan.FromSeconds(30),
            }, out _);
        }
        catch { return null; }
    }
}

// ─── OAuth ────────────────────────────────────────────────────────────────────

public interface IOAuthService
{
    Task<OAuthClient?> ValidateClientAsync(string clientId, string? clientSecret = null, int? orgId = null);
    Task<bool> ValidateRedirectUriAsync(int clientId, string redirectUri);
    Task<AuthorizationCode> CreateAuthorizationCodeAsync(int clientId, int orgId, string userId, string redirectUri, string scopes, string? codeChallenge = null, string? codeChallengeMethod = null);
    Task<(AccessToken? access, RefreshToken? refresh, string? error)> ExchangeCodeAsync(string code, string clientId, string? codeVerifier, string redirectUri);
    Task<(AccessToken? access, RefreshToken? refresh, string? error)> ClientCredentialsAsync(string clientId);
    Task<(AccessToken? access, RefreshToken? refresh, string? error)> RefreshTokenAsync(string refreshToken, string clientId);
    Task<bool> RevokeTokenAsync(string token);
    Task<ApplicationUser?> GetUserFromTokenAsync(string token);
    Task<bool> ValidateCorsOriginAsync(int clientId, string origin);
}

public class OAuthService : IOAuthService
{
    private readonly ApplicationDbContext _db;
    private readonly IJwtService _jwt;

    public OAuthService(ApplicationDbContext db, IJwtService jwt) { _db = db; _jwt = jwt; }

    public async Task<OAuthClient?> ValidateClientAsync(string clientId, string? clientSecret = null, int? orgId = null)
    {
        var query = _db.OAuthClients
            .Include(c => c.AllowedScopes)
            .Include(c => c.AllowedGrantTypes)
            .Include(c => c.RedirectUris)
            .Include(c => c.CorsOrigins)
            .Include(c => c.Organization)
            .Where(c => c.ClientId == clientId && c.IsEnabled);

        // Org isolation — only match clients belonging to the expected org
        if (orgId.HasValue)
            query = query.Where(c => c.OrganizationId == orgId.Value);

        var client = await query.FirstOrDefaultAsync();
        if (client == null) return null;

        // Block access if org is blocked
        if (client.Organization.IsBlocked) return null;

        if (clientSecret != null && !BCrypt.Net.BCrypt.Verify(clientSecret, client.ClientSecretHash))
            return null;

        return client;
    }

    public async Task<bool> ValidateRedirectUriAsync(int clientId, string redirectUri) =>
        await _db.OAuthClientRedirectUris.AnyAsync(r => r.OAuthClientId == clientId && r.Uri == redirectUri);

    public async Task<bool> ValidateCorsOriginAsync(int clientId, string origin) =>
        await _db.OAuthClientCorsOrigins.AnyAsync(c => c.OAuthClientId == clientId && c.Origin == origin);

    public async Task<AuthorizationCode> CreateAuthorizationCodeAsync(int clientId, int orgId, string userId, string redirectUri, string scopes, string? codeChallenge = null, string? codeChallengeMethod = null)
    {
        var code = new AuthorizationCode
        {
            OAuthClientId        = clientId,
            OrganizationId       = orgId,
            UserId               = userId,
            Code                 = GenerateCode(),
            RedirectUri          = redirectUri,
            Scopes               = scopes,
            CodeChallenge        = codeChallenge,
            CodeChallengeMethod  = codeChallengeMethod,
            ExpiresAt            = DateTime.UtcNow.AddMinutes(10),
        };
        _db.AuthorizationCodes.Add(code);
        await _db.SaveChangesAsync();
        return code;
    }

    public async Task<(AccessToken?, RefreshToken?, string?)> ExchangeCodeAsync(string code, string clientId, string? codeVerifier, string redirectUri)
    {
        var client = await ValidateClientAsync(clientId);
        if (client == null) return (null, null, "invalid_client");

        var authCode = await _db.AuthorizationCodes.Include(c => c.User)
            .FirstOrDefaultAsync(c => c.Code == code && !c.IsUsed && c.ExpiresAt > DateTime.UtcNow);

        if (authCode == null || authCode.OAuthClientId != client.Id) return (null, null, "invalid_grant");
        if (authCode.RedirectUri != redirectUri) return (null, null, "redirect_uri_mismatch");

        if (authCode.CodeChallenge != null)
        {
            if (codeVerifier == null) return (null, null, "code_verifier_required");
            if (!VerifyCodeChallenge(authCode.CodeChallenge, authCode.CodeChallengeMethod, codeVerifier))
                return (null, null, "invalid_code_verifier");
        }

        authCode.IsUsed = true;
        var (access, refresh) = await IssueTokensAsync(client, authCode.User, authCode.Scopes);
        await _db.SaveChangesAsync();
        return (access, refresh, null);
    }

    public async Task<(AccessToken?, RefreshToken?, string?)> ClientCredentialsAsync(string clientId)
    {
        var client = await ValidateClientAsync(clientId);
        if (client == null) return (null, null, "invalid_client");
        if (!client.AllowedGrantTypes.Any(g => g.GrantType == "client_credentials"))
            return (null, null, "unauthorized_client");

        var scopes = string.Join(" ", client.AllowedScopes.Select(s => s.Scope));
        var (access, refresh) = await IssueTokensAsync(client, null, scopes);
        await _db.SaveChangesAsync();
        return (access, refresh, null);
    }

    public async Task<(AccessToken?, RefreshToken?, string?)> RefreshTokenAsync(string refreshToken, string clientId)
    {
        var client = await ValidateClientAsync(clientId);
        if (client == null) return (null, null, "invalid_client");

        var rt = await _db.RefreshTokens.Include(t => t.User)
            .FirstOrDefaultAsync(t => t.Token == refreshToken && !t.IsRevoked && t.ExpiresAt > DateTime.UtcNow);

        if (rt == null || rt.OAuthClientId != client.Id) return (null, null, "invalid_grant");

        rt.IsRevoked = true;
        var (access, refresh) = await IssueTokensAsync(client, rt.User, rt.Scopes);
        await _db.SaveChangesAsync();
        return (access, refresh, null);
    }

    public async Task<bool> RevokeTokenAsync(string token)
    {
        var at = await _db.AccessTokens.FirstOrDefaultAsync(t => t.Token == token);
        if (at != null) { at.IsRevoked = true; await _db.SaveChangesAsync(); return true; }
        var rt = await _db.RefreshTokens.FirstOrDefaultAsync(t => t.Token == token);
        if (rt != null) { rt.IsRevoked = true; await _db.SaveChangesAsync(); return true; }
        return false;
    }

    public async Task<ApplicationUser?> GetUserFromTokenAsync(string token)
    {
        var principal = _jwt.ValidateToken(token);
        var userId = principal?.FindFirst("sub")?.Value ?? principal?.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (userId == null) return null;
        return await _db.Users.FindAsync(userId);
    }

    private async Task<(AccessToken access, RefreshToken? refresh)> IssueTokensAsync(OAuthClient client, ApplicationUser? user, string scopes)
    {
        var jwtToken = _jwt.GenerateAccessToken(user, client, scopes);
        var access = new AccessToken
        {
            OAuthClientId  = client.Id,
            OrganizationId = client.OrganizationId,
            UserId         = user?.Id,
            Token          = jwtToken,
            Scopes         = scopes,
            ExpiresAt      = DateTime.UtcNow.AddSeconds(client.AccessTokenLifetimeSeconds),
        };
        _db.AccessTokens.Add(access);

        RefreshToken? refresh = null;
        if (client.AllowedGrantTypes.Any(g => g.GrantType == "refresh_token") || user != null)
        {
            refresh = new RefreshToken
            {
                OAuthClientId  = client.Id,
                OrganizationId = client.OrganizationId,
                UserId         = user?.Id,
                Token          = _jwt.GenerateRefreshToken(),
                Scopes         = scopes,
                ExpiresAt      = DateTime.UtcNow.AddDays(client.RefreshTokenLifetimeDays),
            };
            _db.RefreshTokens.Add(refresh);
        }

        return (access, refresh);
    }

    private static string GenerateCode()
    {
        var bytes = new byte[32];
        RandomNumberGenerator.Fill(bytes);
        return Convert.ToBase64String(bytes).Replace("+", "-").Replace("/", "_").TrimEnd('=');
    }

    private static bool VerifyCodeChallenge(string challenge, string? method, string verifier)
    {
        if (method?.ToUpper() == "S256")
        {
            var hash = SHA256.HashData(Encoding.ASCII.GetBytes(verifier));
            var computed = Convert.ToBase64String(hash).Replace("+", "-").Replace("/", "_").TrimEnd('=');
            return computed == challenge;
        }
        return verifier == challenge;
    }
}
