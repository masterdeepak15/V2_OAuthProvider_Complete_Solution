using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using OAuthProvider.Models;

namespace OAuthProvider.Data;

public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options) { }

    public DbSet<Project> Projects => Set<Project>();
    public DbSet<ProjectUser> ProjectUsers => Set<ProjectUser>();
    public DbSet<OAuthClient> OAuthClients => Set<OAuthClient>();
    public DbSet<OAuthClientRedirectUri> OAuthClientRedirectUris => Set<OAuthClientRedirectUri>();
    public DbSet<OAuthScope> OAuthScopes => Set<OAuthScope>();
    public DbSet<OAuthClientScope> OAuthClientScopes => Set<OAuthClientScope>();
    public DbSet<OAuthClientGrantType> OAuthClientGrantTypes => Set<OAuthClientGrantType>();
    public DbSet<AuthorizationCode> AuthorizationCodes => Set<AuthorizationCode>();
    public DbSet<AccessToken> AccessTokens => Set<AccessToken>();
    public DbSet<RefreshToken> RefreshTokens => Set<RefreshToken>();
    public DbSet<LoginAudit> LoginAudits => Set<LoginAudit>();

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        builder.Entity<ApplicationUser>(e =>
        {
            e.Property(u => u.FirstName).HasMaxLength(100);
            e.Property(u => u.LastName).HasMaxLength(100);
        });

        builder.Entity<Project>(e =>
        {
            e.HasKey(p => p.Id);
            e.Property(p => p.Name).IsRequired().HasMaxLength(200);
            e.HasMany(p => p.Clients).WithOne(c => c.Project).HasForeignKey(c => c.ProjectId).OnDelete(DeleteBehavior.Cascade);
            e.HasMany(p => p.ProjectUsers).WithOne(pu => pu.Project).HasForeignKey(pu => pu.ProjectId).OnDelete(DeleteBehavior.Cascade);
        });

        builder.Entity<ProjectUser>(e =>
        {
            e.HasKey(pu => pu.Id);
            e.HasOne(pu => pu.User).WithMany(u => u.ProjectUsers).HasForeignKey(pu => pu.UserId).OnDelete(DeleteBehavior.Cascade);
        });

        builder.Entity<OAuthClient>(e =>
        {
            e.HasKey(c => c.Id);
            e.Property(c => c.ClientId).IsRequired().HasMaxLength(100);
            e.HasIndex(c => c.ClientId).IsUnique();
            e.Property(c => c.Name).IsRequired().HasMaxLength(200);
            e.HasMany(c => c.RedirectUris).WithOne(r => r.Client).HasForeignKey(r => r.OAuthClientId).OnDelete(DeleteBehavior.Cascade);
            e.HasMany(c => c.AllowedScopes).WithOne(s => s.Client).HasForeignKey(s => s.OAuthClientId).OnDelete(DeleteBehavior.Cascade);
            e.HasMany(c => c.AllowedGrantTypes).WithOne(g => g.Client).HasForeignKey(g => g.OAuthClientId).OnDelete(DeleteBehavior.Cascade);
        });

        builder.Entity<OAuthClientRedirectUri>(e =>
        {
            e.HasKey(r => r.Id);
            e.Property(r => r.Uri).IsRequired().HasMaxLength(2000);
        });

        builder.Entity<OAuthScope>(e =>
        {
            e.HasKey(s => s.Id);
            e.Property(s => s.Name).IsRequired().HasMaxLength(100);
            e.HasIndex(s => s.Name).IsUnique();
        });

        builder.Entity<OAuthClientScope>(e =>
        {
            e.HasKey(s => s.Id);
            e.Property(s => s.Scope).IsRequired().HasMaxLength(100);
        });

        builder.Entity<OAuthClientGrantType>(e =>
        {
            e.HasKey(g => g.Id);
            e.Property(g => g.GrantType).IsRequired().HasMaxLength(100);
        });

        builder.Entity<AuthorizationCode>(e =>
        {
            e.HasKey(c => c.Id);
            e.Property(c => c.Code).IsRequired().HasMaxLength(512);
            e.HasIndex(c => c.Code).IsUnique();
            e.HasOne(c => c.User).WithMany().HasForeignKey(c => c.UserId).OnDelete(DeleteBehavior.Cascade);
        });

        builder.Entity<AccessToken>(e =>
        {
            e.HasKey(t => t.Id);
            e.Property(t => t.Token).IsRequired().HasMaxLength(2048);
            e.HasOne(t => t.User).WithMany().HasForeignKey(t => t.UserId).OnDelete(DeleteBehavior.SetNull);
        });

        builder.Entity<RefreshToken>(e =>
        {
            e.HasKey(t => t.Id);
            e.Property(t => t.Token).IsRequired().HasMaxLength(512);
            e.HasIndex(t => t.Token).IsUnique();
            e.HasOne(t => t.User).WithMany().HasForeignKey(t => t.UserId).OnDelete(DeleteBehavior.SetNull);
        });

        builder.Entity<LoginAudit>(e =>
        {
            e.HasKey(a => a.Id);
            e.HasOne(a => a.User).WithMany(u => u.LoginAudits).HasForeignKey(a => a.UserId).OnDelete(DeleteBehavior.Cascade);
        });
    }
}
