namespace OAuthProvider.Models;

public class Project
{
    public int Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public bool IsActive { get; set; } = true;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;

    public ICollection<OAuthClient> Clients { get; set; } = new List<OAuthClient>();
    public ICollection<ProjectUser> ProjectUsers { get; set; } = new List<ProjectUser>();
}

public class ProjectUser
{
    public int Id { get; set; }
    public int ProjectId { get; set; }
    public string UserId { get; set; } = string.Empty;
    public string Role { get; set; } = "developer";
    public DateTime AssignedAt { get; set; } = DateTime.UtcNow;

    public Project Project { get; set; } = null!;
    public ApplicationUser User { get; set; } = null!;
}

public class OAuthClient
{
    public int Id { get; set; }
    public int ProjectId { get; set; }
    public string ClientId { get; set; } = string.Empty;
    public string ClientSecretHash { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public bool IsEnabled { get; set; } = true;
    public int AccessTokenLifetimeSeconds { get; set; } = 3600;
    public int RefreshTokenLifetimeDays { get; set; } = 30;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;

    public Project Project { get; set; } = null!;
    public ICollection<OAuthClientRedirectUri> RedirectUris { get; set; } = new List<OAuthClientRedirectUri>();
    public ICollection<OAuthClientScope> AllowedScopes { get; set; } = new List<OAuthClientScope>();
    public ICollection<OAuthClientGrantType> AllowedGrantTypes { get; set; } = new List<OAuthClientGrantType>();
    public ICollection<AuthorizationCode> AuthorizationCodes { get; set; } = new List<AuthorizationCode>();
    public ICollection<AccessToken> AccessTokens { get; set; } = new List<AccessToken>();
    public ICollection<RefreshToken> RefreshTokens { get; set; } = new List<RefreshToken>();
}

public class OAuthClientRedirectUri
{
    public int Id { get; set; }
    public int OAuthClientId { get; set; }
    public string Uri { get; set; } = string.Empty;

    public OAuthClient Client { get; set; } = null!;
}

public class OAuthScope
{
    public int Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public bool IsDefault { get; set; } = false;
}

public class OAuthClientScope
{
    public int Id { get; set; }
    public int OAuthClientId { get; set; }
    public string Scope { get; set; } = string.Empty;

    public OAuthClient Client { get; set; } = null!;
}

public class OAuthClientGrantType
{
    public int Id { get; set; }
    public int OAuthClientId { get; set; }
    public string GrantType { get; set; } = string.Empty;

    public OAuthClient Client { get; set; } = null!;
}

public class AuthorizationCode
{
    public int Id { get; set; }
    public int OAuthClientId { get; set; }
    public string UserId { get; set; } = string.Empty;
    public string Code { get; set; } = string.Empty;
    public string RedirectUri { get; set; } = string.Empty;
    public string Scopes { get; set; } = string.Empty;
    public string? CodeChallenge { get; set; }
    public string? CodeChallengeMethod { get; set; }
    public bool IsUsed { get; set; } = false;
    public DateTime ExpiresAt { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public OAuthClient Client { get; set; } = null!;
    public ApplicationUser User { get; set; } = null!;
}

public class AccessToken
{
    public int Id { get; set; }
    public int OAuthClientId { get; set; }
    public string? UserId { get; set; }
    public string Token { get; set; } = string.Empty;
    public string Scopes { get; set; } = string.Empty;
    public bool IsRevoked { get; set; } = false;
    public DateTime ExpiresAt { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public OAuthClient Client { get; set; } = null!;
    public ApplicationUser? User { get; set; }
}

public class RefreshToken
{
    public int Id { get; set; }
    public int OAuthClientId { get; set; }
    public string? UserId { get; set; }
    public string Token { get; set; } = string.Empty;
    public string Scopes { get; set; } = string.Empty;
    public bool IsRevoked { get; set; } = false;
    public int? AccessTokenId { get; set; }
    public DateTime ExpiresAt { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public OAuthClient Client { get; set; } = null!;
    public ApplicationUser? User { get; set; }
}

public class LoginAudit
{
    public int Id { get; set; }
    public string UserId { get; set; } = string.Empty;
    public string? IpAddress { get; set; }
    public string? UserAgent { get; set; }
    public bool Success { get; set; }
    public string? FailureReason { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public ApplicationUser User { get; set; } = null!;
}
