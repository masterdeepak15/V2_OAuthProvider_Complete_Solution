using Microsoft.AspNetCore.Identity;

namespace OAuthProviderV2.Models;

// ═══════════════════════════════════════════════════════════
//  IDENTITY
// ═══════════════════════════════════════════════════════════

public class ApplicationUser : IdentityUser
{
    public string? FirstName { get; set; }
    public string? LastName { get; set; }
    public string? FullName => $"{FirstName} {LastName}".Trim();
    public bool IsActive { get; set; } = true;
    public bool IsEmailVerified { get; set; } = false;
    public string? EmailVerificationToken { get; set; }
    public DateTime? EmailVerificationTokenExpiry { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? LastLoginAt { get; set; }

    // Multi-tenancy — null = SuperAdmin (platform level)
    public int? OrganizationId { get; set; }
    public Organization? Organization { get; set; }

    public ICollection<OrganizationUser> OrganizationUsers { get; set; } = new List<OrganizationUser>();
    public ICollection<AuditLog> AuditLogs { get; set; } = new List<AuditLog>();
}

// ═══════════════════════════════════════════════════════════
//  ORGANIZATION (Tenant)
// ═══════════════════════════════════════════════════════════

public class Organization
{
    public int Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string Slug { get; set; } = string.Empty;       // unique, url-safe
    public string? Description { get; set; }
    public string? LogoUrl { get; set; }
    public string? Website { get; set; }
    public bool IsActive { get; set; } = true;
    public bool IsBlocked { get; set; } = false;
    public string? BlockReason { get; set; }
    public int MaxUsers { get; set; } = 50;
    public int MaxProjects { get; set; } = 10;
    public int MaxClients { get; set; } = 20;
    public string AdminEmail { get; set; } = string.Empty;
    public string? OwnerId { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;

    // OTP signup state
    public string? PendingOtpHash { get; set; }
    public DateTime? OtpExpiresAt { get; set; }
    public int OtpAttempts { get; set; } = 0;

    public ApplicationUser? Owner { get; set; }
    public ICollection<OrganizationUser> Members { get; set; } = new List<OrganizationUser>();
    public ICollection<Project> Projects { get; set; } = new List<Project>();
    public OrganizationEmailConfig? EmailConfig { get; set; }
    public ICollection<AuditLog> AuditLogs { get; set; } = new List<AuditLog>();
    public ICollection<WafRule> WafRules { get; set; } = new List<WafRule>();
}

public class OrganizationUser
{
    public int Id { get; set; }
    public int OrganizationId { get; set; }
    public string UserId { get; set; } = string.Empty;
    public string Role { get; set; } = "member";     // owner | admin | developer | member
    public bool IsActive { get; set; } = true;
    public DateTime JoinedAt { get; set; } = DateTime.UtcNow;

    public Organization Organization { get; set; } = null!;
    public ApplicationUser User { get; set; } = null!;
}

// ═══════════════════════════════════════════════════════════
//  EMAIL CONFIGURATION (per-org + platform default)
// ═══════════════════════════════════════════════════════════

public class OrganizationEmailConfig
{
    public int Id { get; set; }
    public int OrganizationId { get; set; }
    public bool UseDefaultProvider { get; set; } = true;   // use platform SMTP
    public string? SmtpHost { get; set; }
    public int SmtpPort { get; set; } = 587;
    public bool SmtpUseSsl { get; set; } = true;
    public string? SmtpUsername { get; set; }
    public string? SmtpPasswordEncrypted { get; set; }
    public string? FromEmail { get; set; }
    public string? FromName { get; set; }
    public bool AlertsEnabled { get; set; } = true;
    public bool LoginAlerts { get; set; } = true;
    public bool SecurityAlerts { get; set; } = true;
    public bool WafAlerts { get; set; } = true;
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;

    public Organization Organization { get; set; } = null!;
}

public class PlatformEmailConfig
{
    public int Id { get; set; }
    public string SmtpHost { get; set; } = string.Empty;
    public int SmtpPort { get; set; } = 587;
    public bool SmtpUseSsl { get; set; } = true;
    public string SmtpUsername { get; set; } = string.Empty;
    public string SmtpPasswordEncrypted { get; set; } = string.Empty;
    public string FromEmail { get; set; } = string.Empty;
    public string FromName { get; set; } = "OAuth Provider";
    public bool IsConfigured { get; set; } = false;
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
}

// ═══════════════════════════════════════════════════════════
//  PROJECTS & OAUTH CLIENTS
// ═══════════════════════════════════════════════════════════

public class Project
{
    public int Id { get; set; }
    public int OrganizationId { get; set; }              // tenant isolation
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public bool IsActive { get; set; } = true;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;

    public Organization Organization { get; set; } = null!;
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
    public int OrganizationId { get; set; }              // denormalized for fast isolation queries
    public string ClientId { get; set; } = string.Empty;
    public string ClientSecretHash { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public bool IsEnabled { get; set; } = true;
    public int AccessTokenLifetimeSeconds { get; set; } = 3600;
    public int RefreshTokenLifetimeDays { get; set; } = 30;
    public string ClientType { get; set; } = "confidential";  // confidential | public
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;

    public Project Project { get; set; } = null!;
    public Organization Organization { get; set; } = null!;
    public ICollection<OAuthClientRedirectUri> RedirectUris { get; set; } = new List<OAuthClientRedirectUri>();
    public ICollection<OAuthClientCorsOrigin> CorsOrigins { get; set; } = new List<OAuthClientCorsOrigin>();
    public ICollection<OAuthClientScope> AllowedScopes { get; set; } = new List<OAuthClientScope>();
    public ICollection<OAuthClientGrantType> AllowedGrantTypes { get; set; } = new List<OAuthClientGrantType>();
    public ICollection<OAuthClientPostLogoutUri> PostLogoutRedirectUris { get; set; } = new List<OAuthClientPostLogoutUri>();
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

public class OAuthClientCorsOrigin
{
    public int Id { get; set; }
    public int OAuthClientId { get; set; }
    public string Origin { get; set; } = string.Empty;  // e.g. https://app.example.com
    public OAuthClient Client { get; set; } = null!;
}

public class OAuthClientPostLogoutUri
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
    public bool IsSystem { get; set; } = false;
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

// ═══════════════════════════════════════════════════════════
//  TOKENS
// ═══════════════════════════════════════════════════════════

public class AuthorizationCode
{
    public int Id { get; set; }
    public int OAuthClientId { get; set; }
    public int OrganizationId { get; set; }
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
    public int OrganizationId { get; set; }
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
    public int OrganizationId { get; set; }
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

// ═══════════════════════════════════════════════════════════
//  OTP (for signup)
// ═══════════════════════════════════════════════════════════

public class OtpRecord
{
    public int Id { get; set; }
    public string Email { get; set; } = string.Empty;
    public string OtpHash { get; set; } = string.Empty;
    public int Attempts { get; set; } = 0;
    public bool IsUsed { get; set; } = false;
    public string Purpose { get; set; } = "signup";    // signup | password_reset
    public DateTime ExpiresAt { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}

// ═══════════════════════════════════════════════════════════
//  AUDIT LOG (per-org, detailed)
// ═══════════════════════════════════════════════════════════

public class AuditLog
{
    public long Id { get; set; }
    public int? OrganizationId { get; set; }           // null = platform-level event
    public string? UserId { get; set; }
    public string? UserEmail { get; set; }
    public string EventType { get; set; } = string.Empty;
    public string EventCategory { get; set; } = string.Empty;  // auth | oauth | admin | waf | system
    public string? ResourceType { get; set; }          // User | Client | Project | Token
    public string? ResourceId { get; set; }
    public string? ResourceName { get; set; }
    public bool Success { get; set; } = true;
    public string? FailureReason { get; set; }
    public string? Details { get; set; }               // JSON extra data

    // Session / Device details
    public string? IpAddress { get; set; }
    public string? UserAgent { get; set; }
    public string? Browser { get; set; }
    public string? BrowserVersion { get; set; }
    public string? OperatingSystem { get; set; }
    public string? OsVersion { get; set; }
    public string? DeviceType { get; set; }            // Desktop | Mobile | Tablet
    public string? DeviceBrand { get; set; }
    public string? Country { get; set; }
    public string? City { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public Organization? Organization { get; set; }
    public ApplicationUser? User { get; set; }
}

// ═══════════════════════════════════════════════════════════
//  WAF — Web Application Firewall
// ═══════════════════════════════════════════════════════════

public class WafEvent
{
    public long Id { get; set; }
    public int? OrganizationId { get; set; }
    public string IpAddress { get; set; } = string.Empty;
    public string RequestPath { get; set; } = string.Empty;
    public string RequestMethod { get; set; } = string.Empty;
    public string? QueryString { get; set; }
    public string? UserAgent { get; set; }
    public string ThreatType { get; set; } = string.Empty;   // rate_limit | sql_inject | xss | path_traversal | suspicious_ua | brute_force | geo_block
    public string ThreatLevel { get; set; } = "medium";       // low | medium | high | critical
    public bool WasBlocked { get; set; } = true;
    public string? RuleName { get; set; }
    public string? MatchedPattern { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public Organization? Organization { get; set; }
}

public class WafRule
{
    public int Id { get; set; }
    public int? OrganizationId { get; set; }           // null = platform-wide rule
    public string Name { get; set; } = string.Empty;
    public string RuleType { get; set; } = string.Empty;  // ip_block | ip_allow | rate_limit | path_block | ua_block | geo_block
    public string Pattern { get; set; } = string.Empty;
    public bool IsEnabled { get; set; } = true;
    public bool IsBlock { get; set; } = true;
    public string? Notes { get; set; }
    public int Priority { get; set; } = 100;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public Organization? Organization { get; set; }
}

public class IpRateLimit
{
    public int Id { get; set; }
    public string IpAddress { get; set; } = string.Empty;
    public string Endpoint { get; set; } = string.Empty;
    public int RequestCount { get; set; } = 0;
    public DateTime WindowStart { get; set; } = DateTime.UtcNow;
    public DateTime? BlockedUntil { get; set; }
}
