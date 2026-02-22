using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using OAuthProvider.Models;

namespace OAuthProvider.Services;

public interface IJwtService
{
    string GenerateAccessToken(ApplicationUser? user, OAuthClient client, string scopes);
    string GenerateRefreshToken();
    ClaimsPrincipal? ValidateToken(string token);
}

public class JwtService : IJwtService
{
    private readonly IConfiguration _config;
    private readonly SymmetricSecurityKey _signingKey;

    public JwtService(IConfiguration config)
    {
        _config = config;
        var keyBytes = Encoding.UTF8.GetBytes(_config["Jwt:SigningKey"] ?? throw new InvalidOperationException("JWT signing key not configured"));
        _signingKey = new SymmetricSecurityKey(keyBytes);
    }

    public string GenerateAccessToken(ApplicationUser? user, OAuthClient client, string scopes)
    {
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new(JwtRegisteredClaimNames.Iss, _config["Jwt:Issuer"] ?? "oauth-provider"),
            new("client_id", client.ClientId),
            new("scope", scopes),
        };

        if (user != null)
        {
            claims.Add(new(JwtRegisteredClaimNames.Sub, user.Id));
            claims.Add(new(JwtRegisteredClaimNames.Email, user.Email ?? ""));
            if (!string.IsNullOrEmpty(user.FirstName))
                claims.Add(new("given_name", user.FirstName));
            if (!string.IsNullOrEmpty(user.LastName))
                claims.Add(new("family_name", user.LastName));
        }

        var token = new JwtSecurityToken(
            issuer: _config["Jwt:Issuer"] ?? "oauth-provider",
            audience: client.ClientId,
            claims: claims,
            notBefore: DateTime.UtcNow,
            expires: DateTime.UtcNow.AddSeconds(client.AccessTokenLifetimeSeconds),
            signingCredentials: new SigningCredentials(_signingKey, SecurityAlgorithms.HmacSha256)
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    public string GenerateRefreshToken()
    {
        var bytes = new byte[64];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(bytes);
        return Convert.ToBase64String(bytes).Replace("+", "-").Replace("/", "_").TrimEnd('=');
    }

    public ClaimsPrincipal? ValidateToken(string token)
    {
        try
        {
            var handler = new JwtSecurityTokenHandler();
            var principal = handler.ValidateToken(token, new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = _signingKey,
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero
            }, out _);
            return principal;
        }
        catch { return null; }
    }
}
