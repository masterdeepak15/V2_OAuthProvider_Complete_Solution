using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using OAuthProvider.Models;

namespace OAuthProvider.Data;

public static class DbSeeder
{
    public static async Task SeedAsync(IServiceProvider services)
    {
        using var scope = services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();

        await db.Database.MigrateAsync();

        // Seed Roles
        foreach (var role in new[] { "Admin", "Developer" })
        {
            if (!await roleManager.RoleExistsAsync(role))
                await roleManager.CreateAsync(new IdentityRole(role));
        }

        // Seed Admin User
        var adminEmail = "admin@oauthprovider.dev";
        if (await userManager.FindByEmailAsync(adminEmail) == null)
        {
            var admin = new ApplicationUser
            {
                UserName = adminEmail,
                Email = adminEmail,
                FirstName = "System",
                LastName = "Admin",
                EmailConfirmed = true,
                IsActive = true
            };
            await userManager.CreateAsync(admin, "Admin@123456!");
            await userManager.AddToRolesAsync(admin, new[] { "Admin", "Developer" });

            // Seed sample project
            var project = new Project { Name = "Sample Project", Description = "Demo OAuth Project" };
            db.Projects.Add(project);
            await db.SaveChangesAsync();

            db.ProjectUsers.Add(new ProjectUser { ProjectId = project.Id, UserId = admin.Id, Role = "admin" });

            // Seed default scopes
            var scopes = new[] {
                new OAuthScope { Name = "openid", Description = "OpenID Connect scope" },
                new OAuthScope { Name = "profile", Description = "Access to user profile", IsDefault = true },
                new OAuthScope { Name = "email", Description = "Access to user email" },
                new OAuthScope { Name = "api", Description = "API access" }
            };
            db.OAuthScopes.AddRange(scopes);
            await db.SaveChangesAsync();

            // Seed sample OAuth client
            var clientId = "sample-client-" + Guid.NewGuid().ToString("N")[..8];
            var secret = Guid.NewGuid().ToString("N");
            var client = new OAuthClient
            {
                ProjectId = project.Id,
                ClientId = clientId,
                ClientSecretHash = BCrypt.Net.BCrypt.HashPassword(secret),
                Name = "Sample Web App",
                Description = "Demo client application",
                AccessTokenLifetimeSeconds = 3600,
                RefreshTokenLifetimeDays = 30
            };
            db.OAuthClients.Add(client);
            await db.SaveChangesAsync();

            db.OAuthClientRedirectUris.Add(new OAuthClientRedirectUri { OAuthClientId = client.Id, Uri = "https://localhost:5001/auth/callback" });
            db.OAuthClientScopes.AddRange(
                new OAuthClientScope { OAuthClientId = client.Id, Scope = "openid" },
                new OAuthClientScope { OAuthClientId = client.Id, Scope = "profile" },
                new OAuthClientScope { OAuthClientId = client.Id, Scope = "email" }
            );
            db.OAuthClientGrantTypes.AddRange(
                new OAuthClientGrantType { OAuthClientId = client.Id, GrantType = "authorization_code" },
                new OAuthClientGrantType { OAuthClientId = client.Id, GrantType = "refresh_token" }
            );
            await db.SaveChangesAsync();

            Console.WriteLine("=== SEED DATA ===");
            Console.WriteLine($"Admin: {adminEmail} / Admin@123456!");
            Console.WriteLine($"Client ID: {clientId}");
            Console.WriteLine($"Client Secret: {secret}");
            Console.WriteLine("=================");
        }
    }
}
