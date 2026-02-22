using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using OAuthProvider.Data;
using OAuthProvider.Models;

namespace OAuthProvider.Services;

public interface IOAuthService
{
    Task<OAuthClient?> ValidateClientAsync(string clientId, string? clientSecret = null);
    Task<bool> ValidateRedirectUriAsync(int clientId, string redirectUri);
    Task<AuthorizationCode> CreateAuthorizationCodeAsync(int clientId, string userId, string redirectUri, string scopes, string? codeChallenge = null, string? codeChallengeMethod = null);
    Task<(AccessToken? access, RefreshToken? refresh, string? error)> ExchangeCodeAsync(string code, string clientId, string? codeVerifier, string redirectUri);
    Task<(AccessToken? access, RefreshToken? refresh, string? error)> ClientCredentialsAsync(string clientId);
    Task<(AccessToken? access, RefreshToken? refresh, string? error)> RefreshTokenAsync(string refreshToken, string clientId);
    Task<bool> RevokeTokenAsync(string token);
    Task<ApplicationUser?> GetUserFromTokenAsync(string token);
}

public class OAuthService : IOAuthService
{
    private readonly ApplicationDbContext _db;
    private readonly IJwtService _jwt;

    public OAuthService(ApplicationDbContext db, IJwtService jwt)
    {
        _db = db;
        _jwt = jwt;
    }

    public async Task<OAuthClient?> ValidateClientAsync(string clientId, string? clientSecret = null)
    {
        var client = await _db.OAuthClients
            .Include(c => c.AllowedScopes)
            .Include(c => c.AllowedGrantTypes)
            .Include(c => c.RedirectUris)
            .FirstOrDefaultAsync(c => c.ClientId == clientId && c.IsEnabled);

        if (client == null) return null;
        if (clientSecret != null && !BCrypt.Net.BCrypt.Verify(clientSecret, client.ClientSecretHash))
            return null;

        return client;
    }

    public async Task<bool> ValidateRedirectUriAsync(int clientId, string redirectUri)
    {
        return await _db.OAuthClientRedirectUris
            .AnyAsync(r => r.OAuthClientId == clientId && r.Uri == redirectUri);
    }

    public async Task<AuthorizationCode> CreateAuthorizationCodeAsync(int clientId, string userId, string redirectUri, string scopes, string? codeChallenge = null, string? codeChallengeMethod = null)
    {
        var code = new AuthorizationCode
        {
            OAuthClientId = clientId,
            UserId = userId,
            Code = GenerateCode(),
            RedirectUri = redirectUri,
            Scopes = scopes,
            CodeChallenge = codeChallenge,
            CodeChallengeMethod = codeChallengeMethod,
            ExpiresAt = DateTime.UtcNow.AddMinutes(10)
        };
        _db.AuthorizationCodes.Add(code);
        await _db.SaveChangesAsync();
        return code;
    }

    public async Task<(AccessToken? access, RefreshToken? refresh, string? error)> ExchangeCodeAsync(string code, string clientId, string? codeVerifier, string redirectUri)
    {
        var client = await ValidateClientAsync(clientId);
        if (client == null) return (null, null, "invalid_client");

        var authCode = await _db.AuthorizationCodes
            .Include(c => c.User)
            .FirstOrDefaultAsync(c => c.Code == code && !c.IsUsed && c.ExpiresAt > DateTime.UtcNow);

        if (authCode == null || authCode.OAuthClientId != client.Id)
            return (null, null, "invalid_grant");

        if (authCode.RedirectUri != redirectUri)
            return (null, null, "redirect_uri_mismatch");

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

    public async Task<(AccessToken? access, RefreshToken? refresh, string? error)> ClientCredentialsAsync(string clientId)
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

    public async Task<(AccessToken? access, RefreshToken? refresh, string? error)> RefreshTokenAsync(string refreshToken, string clientId)
    {
        var client = await ValidateClientAsync(clientId);
        if (client == null) return (null, null, "invalid_client");

        var rt = await _db.RefreshTokens
            .Include(t => t.User)
            .FirstOrDefaultAsync(t => t.Token == refreshToken && !t.IsRevoked && t.ExpiresAt > DateTime.UtcNow);

        if (rt == null || rt.OAuthClientId != client.Id)
            return (null, null, "invalid_grant");

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
        var userId = principal?.FindFirst("sub")?.Value ?? principal?.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
        if (userId == null) return null;
        return await _db.Users.FindAsync(userId);
    }

    private async Task<(AccessToken access, RefreshToken? refresh)> IssueTokensAsync(OAuthClient client, ApplicationUser? user, string scopes)
    {
        var jwtToken = _jwt.GenerateAccessToken(user, client, scopes);
        var access = new AccessToken
        {
            OAuthClientId = client.Id,
            UserId = user?.Id,
            Token = jwtToken,
            Scopes = scopes,
            ExpiresAt = DateTime.UtcNow.AddSeconds(client.AccessTokenLifetimeSeconds)
        };
        _db.AccessTokens.Add(access);

        RefreshToken? refresh = null;
        if (client.AllowedGrantTypes.Any(g => g.GrantType == "refresh_token") || user != null)
        {
            refresh = new RefreshToken
            {
                OAuthClientId = client.Id,
                UserId = user?.Id,
                Token = _jwt.GenerateRefreshToken(),
                Scopes = scopes,
                ExpiresAt = DateTime.UtcNow.AddDays(client.RefreshTokenLifetimeDays)
            };
            _db.RefreshTokens.Add(refresh);
        }

        return (access, refresh);
    }

    private static string GenerateCode()
    {
        var bytes = new byte[32];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(bytes);
        return Convert.ToBase64String(bytes).Replace("+", "-").Replace("/", "_").TrimEnd('=');
    }

    private static bool VerifyCodeChallenge(string challenge, string? method, string verifier)
    {
        if (method == "S256")
        {
            var hash = SHA256.HashData(Encoding.ASCII.GetBytes(verifier));
            var computed = Convert.ToBase64String(hash).Replace("+", "-").Replace("/", "_").TrimEnd('=');
            return computed == challenge;
        }
        return verifier == challenge; // plain
    }
}
