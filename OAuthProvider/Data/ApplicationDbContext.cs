using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using OAuthProviderV2.Models;

namespace OAuthProviderV2.Data;

public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options) { }

    // ── Organizations ─────────────────────────────────────────────────────────
    public DbSet<Organization> Organizations => Set<Organization>();
    public DbSet<OrganizationUser> OrganizationUsers => Set<OrganizationUser>();
    public DbSet<OrganizationEmailConfig> OrganizationEmailConfigs => Set<OrganizationEmailConfig>();
    public DbSet<PlatformEmailConfig> PlatformEmailConfigs => Set<PlatformEmailConfig>();

    // ── Projects & Clients ────────────────────────────────────────────────────
    public DbSet<Project> Projects => Set<Project>();
    public DbSet<ProjectUser> ProjectUsers => Set<ProjectUser>();
    public DbSet<OAuthClient> OAuthClients => Set<OAuthClient>();
    public DbSet<OAuthClientRedirectUri> OAuthClientRedirectUris => Set<OAuthClientRedirectUri>();
    public DbSet<OAuthClientCorsOrigin> OAuthClientCorsOrigins => Set<OAuthClientCorsOrigin>();
    public DbSet<OAuthClientPostLogoutUri> OAuthClientPostLogoutUris => Set<OAuthClientPostLogoutUri>();
    public DbSet<OAuthScope> OAuthScopes => Set<OAuthScope>();
    public DbSet<OAuthClientScope> OAuthClientScopes => Set<OAuthClientScope>();
    public DbSet<OAuthClientGrantType> OAuthClientGrantTypes => Set<OAuthClientGrantType>();

    // ── Tokens ────────────────────────────────────────────────────────────────
    public DbSet<AuthorizationCode> AuthorizationCodes => Set<AuthorizationCode>();
    public DbSet<AccessToken> AccessTokens => Set<AccessToken>();
    public DbSet<RefreshToken> RefreshTokens => Set<RefreshToken>();

    // ── OTP ───────────────────────────────────────────────────────────────────
    public DbSet<OtpRecord> OtpRecords => Set<OtpRecord>();

    // ── Audit & WAF ───────────────────────────────────────────────────────────
    public DbSet<AuditLog> AuditLogs => Set<AuditLog>();
    public DbSet<WafEvent> WafEvents => Set<WafEvent>();
    public DbSet<WafRule> WafRules => Set<WafRule>();
    public DbSet<IpRateLimit> IpRateLimits => Set<IpRateLimit>();

    protected override void OnModelCreating(ModelBuilder b)
    {
        base.OnModelCreating(b);

        // ── ApplicationUser ───────────────────────────────────────────────────
        b.Entity<ApplicationUser>(e =>
        {
            e.HasOne(u => u.Organization)
             .WithMany()
             .HasForeignKey(u => u.OrganizationId)
             .OnDelete(DeleteBehavior.SetNull);
        });

        // ── Organization ──────────────────────────────────────────────────────
        b.Entity<Organization>(e =>
        {
            e.HasIndex(o => o.Slug).IsUnique();
            e.HasOne(o => o.Owner)
             .WithMany()
             .HasForeignKey(o => o.OwnerId)
             .OnDelete(DeleteBehavior.SetNull);
        });

        // ── OrganizationUser ──────────────────────────────────────────────────
        b.Entity<OrganizationUser>(e =>
        {
            e.HasIndex(ou => new { ou.OrganizationId, ou.UserId }).IsUnique();
            e.HasOne(ou => ou.Organization).WithMany(o => o.Members)
             .HasForeignKey(ou => ou.OrganizationId).OnDelete(DeleteBehavior.Cascade);
            e.HasOne(ou => ou.User).WithMany(u => u.OrganizationUsers)
             .HasForeignKey(ou => ou.UserId).OnDelete(DeleteBehavior.Cascade);
        });

        // ── OrganizationEmailConfig ───────────────────────────────────────────
        b.Entity<OrganizationEmailConfig>(e =>
        {
            e.HasOne(ec => ec.Organization)
             .WithOne(o => o.EmailConfig)
             .HasForeignKey<OrganizationEmailConfig>(ec => ec.OrganizationId)
             .OnDelete(DeleteBehavior.Cascade);
        });

        // ── Project ───────────────────────────────────────────────────────────
        b.Entity<Project>(e =>
        {
            e.HasOne(p => p.Organization).WithMany(o => o.Projects)
             .HasForeignKey(p => p.OrganizationId).OnDelete(DeleteBehavior.Cascade);
        });

        // ── ProjectUser ───────────────────────────────────────────────────────
        b.Entity<ProjectUser>(e =>
        {
            e.HasIndex(pu => new { pu.ProjectId, pu.UserId }).IsUnique();
            e.HasOne(pu => pu.Project).WithMany(p => p.ProjectUsers)
             .HasForeignKey(pu => pu.ProjectId).OnDelete(DeleteBehavior.Cascade);
            e.HasOne(pu => pu.User).WithMany()
             .HasForeignKey(pu => pu.UserId).OnDelete(DeleteBehavior.Cascade);
        });

        // ── OAuthClient ───────────────────────────────────────────────────────
        b.Entity<OAuthClient>(e =>
        {
            e.HasIndex(c => c.ClientId).IsUnique();
            e.HasOne(c => c.Project).WithMany(p => p.Clients)
             .HasForeignKey(c => c.ProjectId).OnDelete(DeleteBehavior.Cascade);
            e.HasOne(c => c.Organization).WithMany()
             .HasForeignKey(c => c.OrganizationId).OnDelete(DeleteBehavior.Restrict);
        });

        b.Entity<OAuthClientRedirectUri>(e =>
        {
            e.HasOne(r => r.Client).WithMany(c => c.RedirectUris)
             .HasForeignKey(r => r.OAuthClientId).OnDelete(DeleteBehavior.Cascade);
        });

        b.Entity<OAuthClientCorsOrigin>(e =>
        {
            e.HasOne(r => r.Client).WithMany(c => c.CorsOrigins)
             .HasForeignKey(r => r.OAuthClientId).OnDelete(DeleteBehavior.Cascade);
        });

        b.Entity<OAuthClientPostLogoutUri>(e =>
        {
            e.HasOne(r => r.Client).WithMany(c => c.PostLogoutRedirectUris)
             .HasForeignKey(r => r.OAuthClientId).OnDelete(DeleteBehavior.Cascade);
        });

        b.Entity<OAuthClientScope>(e =>
        {
            e.HasOne(s => s.Client).WithMany(c => c.AllowedScopes)
             .HasForeignKey(s => s.OAuthClientId).OnDelete(DeleteBehavior.Cascade);
        });

        b.Entity<OAuthClientGrantType>(e =>
        {
            e.HasOne(g => g.Client).WithMany(c => c.AllowedGrantTypes)
             .HasForeignKey(g => g.OAuthClientId).OnDelete(DeleteBehavior.Cascade);
        });

        // ── Tokens ────────────────────────────────────────────────────────────
        b.Entity<AuthorizationCode>(e =>
        {
            e.HasIndex(ac => ac.Code).IsUnique();
            e.HasOne(ac => ac.Client).WithMany(c => c.AuthorizationCodes)
             .HasForeignKey(ac => ac.OAuthClientId).OnDelete(DeleteBehavior.Cascade);
            e.HasOne(ac => ac.User).WithMany()
             .HasForeignKey(ac => ac.UserId).OnDelete(DeleteBehavior.Cascade);
        });

        b.Entity<AccessToken>(e =>
        {
            e.HasIndex(at => at.Token);
            e.HasOne(at => at.Client).WithMany(c => c.AccessTokens)
             .HasForeignKey(at => at.OAuthClientId).OnDelete(DeleteBehavior.Cascade);
            e.HasOne(at => at.User).WithMany()
             .HasForeignKey(at => at.UserId).OnDelete(DeleteBehavior.SetNull);
        });

        b.Entity<RefreshToken>(e =>
        {
            e.HasIndex(rt => rt.Token);
            e.HasOne(rt => rt.Client).WithMany(c => c.RefreshTokens)
             .HasForeignKey(rt => rt.OAuthClientId).OnDelete(DeleteBehavior.Cascade);
            e.HasOne(rt => rt.User).WithMany()
             .HasForeignKey(rt => rt.UserId).OnDelete(DeleteBehavior.SetNull);
        });

        // ── Audit ─────────────────────────────────────────────────────────────
        b.Entity<AuditLog>(e =>
        {
            e.HasIndex(al => al.OrganizationId);
            e.HasIndex(al => al.CreatedAt);
            e.HasIndex(al => al.EventType);
            e.HasOne(al => al.Organization).WithMany(o => o.AuditLogs)
             .HasForeignKey(al => al.OrganizationId).OnDelete(DeleteBehavior.SetNull);
            e.HasOne(al => al.User).WithMany(u => u.AuditLogs)
             .HasForeignKey(al => al.UserId).OnDelete(DeleteBehavior.SetNull);
        });

        // ── WAF ───────────────────────────────────────────────────────────────
        b.Entity<WafEvent>(e =>
        {
            e.HasIndex(we => we.CreatedAt);
            e.HasIndex(we => we.IpAddress);
            e.HasIndex(we => we.ThreatType);
            e.HasOne(we => we.Organization).WithMany()
             .HasForeignKey(we => we.OrganizationId).OnDelete(DeleteBehavior.SetNull);
        });

        b.Entity<WafRule>(e =>
        {
            e.HasOne(wr => wr.Organization).WithMany(o => o.WafRules)
             .HasForeignKey(wr => wr.OrganizationId).OnDelete(DeleteBehavior.Cascade);
        });

        b.Entity<IpRateLimit>(e =>
        {
            e.HasIndex(rl => new { rl.IpAddress, rl.Endpoint }).IsUnique();
        });
    }
}
