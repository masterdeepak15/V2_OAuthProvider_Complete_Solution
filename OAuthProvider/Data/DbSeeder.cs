using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using OAuthProviderV2.Models;

namespace OAuthProviderV2.Data;

public static class DbSeeder
{
    public static async Task SeedAsync(IServiceProvider services)
    {
        using var scope = services.CreateScope();
        var db      = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        var userMgr = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var roleMgr = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();

        await db.Database.MigrateAsync();

        // ── Roles ─────────────────────────────────────────────────────────────
        string[] roles = { "SuperAdmin", "OrgAdmin", "OrgUser" };
        foreach (var role in roles)
            if (!await roleMgr.RoleExistsAsync(role))
                await roleMgr.CreateAsync(new IdentityRole(role));

        // ── Default OAuth Scopes ──────────────────────────────────────────────
        var scopes = new[]
        {
            new OAuthScope { Name = "openid",  Description = "OpenID Connect identity", IsDefault = true, IsSystem = true },
            new OAuthScope { Name = "profile", Description = "User profile (name)",     IsDefault = true, IsSystem = true },
            new OAuthScope { Name = "email",   Description = "Email address",           IsDefault = true, IsSystem = true },
            new OAuthScope { Name = "api",     Description = "API access",              IsDefault = false },
            new OAuthScope { Name = "offline_access", Description = "Refresh tokens",  IsDefault = false },
        };

        foreach (var s in scopes)
            if (!await db.OAuthScopes.AnyAsync(x => x.Name == s.Name))
                db.OAuthScopes.Add(s);

        await db.SaveChangesAsync();

        // ── Super Admin user ──────────────────────────────────────────────────
        const string superEmail    = "superadmin@oauthprovider.internal";
        const string superPassword = "SuperAdmin@123456!";

        if (await userMgr.FindByEmailAsync(superEmail) == null)
        {
            var superAdmin = new ApplicationUser
            {
                UserName        = superEmail,
                Email           = superEmail,
                FirstName       = "Super",
                LastName        = "Admin",
                EmailConfirmed  = true,
                IsActive        = true,
                IsEmailVerified = true,
                OrganizationId  = null,   // Super admin has no org
            };

            var result = await userMgr.CreateAsync(superAdmin, superPassword);
            if (result.Succeeded)
            {
                await userMgr.AddToRoleAsync(superAdmin, "SuperAdmin");
                Console.WriteLine("╔═══════════════════════════════════════════╗");
                Console.WriteLine("║         OAUTH PROVIDER V2 — SEEDED       ║");
                Console.WriteLine("╠═══════════════════════════════════════════╣");
                Console.WriteLine($"║  Super Admin: {superEmail,-27}║");
                Console.WriteLine($"║  Password:    {superPassword,-27}║");
                Console.WriteLine("╚═══════════════════════════════════════════╝");
            }
        }

        // ── Default WAF rules (platform-wide) ────────────────────────────────
        if (!await db.WafRules.AnyAsync())
        {
            db.WafRules.Add(new WafRule
            {
                Name      = "Block common scanner user-agents",
                RuleType  = "ua_block",
                Pattern   = "sqlmap|nikto|nmap|masscan",
                IsEnabled = true,
                IsBlock   = true,
                Notes     = "Automatically created on first run",
            });
            await db.SaveChangesAsync();
        }
    }
}
