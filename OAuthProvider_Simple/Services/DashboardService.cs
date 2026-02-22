using Microsoft.EntityFrameworkCore;
using OAuthProvider.Data;
using OAuthProvider.Models;

namespace OAuthProvider.Services;

public interface IDashboardService
{
    Task<DashboardStats> GetStatsAsync();
    Task<List<LoginAudit>> GetRecentLoginsAsync(int count = 10);
    Task<List<AccessToken>> GetActiveTokensAsync();
    Task<List<Project>> GetProjectsAsync();
    Task<Project?> GetProjectAsync(int id);
    Task<Project> CreateProjectAsync(string name, string? description);
    Task UpdateProjectAsync(Project project);
    Task DeleteProjectAsync(int id);
    Task<List<OAuthClient>> GetClientsByProjectAsync(int projectId);
    Task<OAuthClient?> GetClientAsync(int id);
    Task<(OAuthClient client, string rawSecret)> CreateClientAsync(int projectId, string name, string? description, List<string> redirectUris, List<string> scopes, List<string> grantTypes, int tokenLifetime, int refreshLifetime);
    Task<string> RegenerateSecretAsync(int clientId);
    Task UpdateClientAsync(OAuthClient client, List<string> redirectUris, List<string> scopes, List<string> grantTypes);
    Task SetClientEnabledAsync(int clientId, bool enabled);
    Task DeleteClientAsync(int clientId);
    Task<List<ApplicationUser>> GetUsersAsync();
    Task<ApplicationUser?> GetUserAsync(string id);
    Task SetUserLockedAsync(string userId, bool locked);
    Task<List<string>> GetUserRolesAsync(string userId);
    Task SetUserRolesAsync(string userId, List<string> roles);
    Task<List<LoginAudit>> GetUserLoginHistoryAsync(string userId);
    Task AssignUserToProjectAsync(int projectId, string userId, string role);
    Task RemoveUserFromProjectAsync(int projectId, string userId);
    Task<List<OAuthScope>> GetScopesAsync();
}

public class DashboardStats
{
    public int TotalUsers { get; set; }
    public int TotalProjects { get; set; }
    public int TotalClients { get; set; }
    public int ActiveTokens { get; set; }
}

public class DashboardService : IDashboardService
{
    private readonly ApplicationDbContext _db;
    private readonly Microsoft.AspNetCore.Identity.UserManager<ApplicationUser> _userManager;

    public DashboardService(ApplicationDbContext db, Microsoft.AspNetCore.Identity.UserManager<ApplicationUser> userManager)
    {
        _db = db;
        _userManager = userManager;
    }

    public async Task<DashboardStats> GetStatsAsync() => new DashboardStats
    {
        TotalUsers = await _db.Users.CountAsync(),
        TotalProjects = await _db.Projects.CountAsync(),
        TotalClients = await _db.OAuthClients.CountAsync(),
        ActiveTokens = await _db.AccessTokens.CountAsync(t => !t.IsRevoked && t.ExpiresAt > DateTime.UtcNow)
    };

    public async Task<List<LoginAudit>> GetRecentLoginsAsync(int count = 10) =>
        await _db.LoginAudits.Include(a => a.User).OrderByDescending(a => a.CreatedAt).Take(count).ToListAsync();

    public async Task<List<AccessToken>> GetActiveTokensAsync() =>
        await _db.AccessTokens.Include(t => t.Client).Include(t => t.User)
            .Where(t => !t.IsRevoked && t.ExpiresAt > DateTime.UtcNow)
            .OrderByDescending(t => t.CreatedAt).ToListAsync();

    public async Task<List<Project>> GetProjectsAsync() =>
        await _db.Projects.Include(p => p.Clients).Include(p => p.ProjectUsers).ThenInclude(pu => pu.User).ToListAsync();

    public async Task<Project?> GetProjectAsync(int id) =>
        await _db.Projects.Include(p => p.Clients).Include(p => p.ProjectUsers).ThenInclude(pu => pu.User).FirstOrDefaultAsync(p => p.Id == id);

    public async Task<Project> CreateProjectAsync(string name, string? description)
    {
        var project = new Project { Name = name, Description = description };
        _db.Projects.Add(project);
        await _db.SaveChangesAsync();
        return project;
    }

    public async Task UpdateProjectAsync(Project project)
    {
        project.UpdatedAt = DateTime.UtcNow;
        _db.Projects.Update(project);
        await _db.SaveChangesAsync();
    }

    public async Task DeleteProjectAsync(int id)
    {
        var p = await _db.Projects.FindAsync(id);
        if (p != null) { _db.Projects.Remove(p); await _db.SaveChangesAsync(); }
    }

    public async Task<List<OAuthClient>> GetClientsByProjectAsync(int projectId) =>
        await _db.OAuthClients.Include(c => c.RedirectUris).Include(c => c.AllowedScopes)
            .Include(c => c.AllowedGrantTypes).Where(c => c.ProjectId == projectId).ToListAsync();

    public async Task<OAuthClient?> GetClientAsync(int id) =>
        await _db.OAuthClients.Include(c => c.RedirectUris).Include(c => c.AllowedScopes)
            .Include(c => c.AllowedGrantTypes).Include(c => c.Project)
            .FirstOrDefaultAsync(c => c.Id == id);

    public async Task<(OAuthClient client, string rawSecret)> CreateClientAsync(int projectId, string name, string? description, List<string> redirectUris, List<string> scopes, List<string> grantTypes, int tokenLifetime, int refreshLifetime)
    {
        var secret = Guid.NewGuid().ToString("N") + Guid.NewGuid().ToString("N");
        var client = new OAuthClient
        {
            ProjectId = projectId,
            ClientId = "client-" + Guid.NewGuid().ToString("N")[..12],
            ClientSecretHash = BCrypt.Net.BCrypt.HashPassword(secret),
            Name = name,
            Description = description,
            AccessTokenLifetimeSeconds = tokenLifetime,
            RefreshTokenLifetimeDays = refreshLifetime
        };
        _db.OAuthClients.Add(client);
        await _db.SaveChangesAsync();

        foreach (var uri in redirectUris.Where(u => !string.IsNullOrWhiteSpace(u)))
            _db.OAuthClientRedirectUris.Add(new OAuthClientRedirectUri { OAuthClientId = client.Id, Uri = uri.Trim() });
        foreach (var scope in scopes.Where(s => !string.IsNullOrWhiteSpace(s)))
            _db.OAuthClientScopes.Add(new OAuthClientScope { OAuthClientId = client.Id, Scope = scope.Trim() });
        foreach (var gt in grantTypes.Where(g => !string.IsNullOrWhiteSpace(g)))
            _db.OAuthClientGrantTypes.Add(new OAuthClientGrantType { OAuthClientId = client.Id, GrantType = gt.Trim() });

        await _db.SaveChangesAsync();
        return (client, secret);
    }

    public async Task<string> RegenerateSecretAsync(int clientId)
    {
        var client = await _db.OAuthClients.FindAsync(clientId) ?? throw new InvalidOperationException("Client not found");
        var secret = Guid.NewGuid().ToString("N") + Guid.NewGuid().ToString("N");
        client.ClientSecretHash = BCrypt.Net.BCrypt.HashPassword(secret);
        client.UpdatedAt = DateTime.UtcNow;
        await _db.SaveChangesAsync();
        return secret;
    }

    public async Task UpdateClientAsync(OAuthClient client, List<string> redirectUris, List<string> scopes, List<string> grantTypes)
    {
        var existing = await _db.OAuthClients.FindAsync(client.Id) ?? throw new InvalidOperationException("Client not found");
        existing.Name = client.Name;
        existing.Description = client.Description;
        existing.AccessTokenLifetimeSeconds = client.AccessTokenLifetimeSeconds;
        existing.RefreshTokenLifetimeDays = client.RefreshTokenLifetimeDays;
        existing.UpdatedAt = DateTime.UtcNow;

        var oldUris = _db.OAuthClientRedirectUris.Where(r => r.OAuthClientId == client.Id);
        _db.OAuthClientRedirectUris.RemoveRange(oldUris);
        var oldScopes = _db.OAuthClientScopes.Where(s => s.OAuthClientId == client.Id);
        _db.OAuthClientScopes.RemoveRange(oldScopes);
        var oldGts = _db.OAuthClientGrantTypes.Where(g => g.OAuthClientId == client.Id);
        _db.OAuthClientGrantTypes.RemoveRange(oldGts);

        foreach (var uri in redirectUris.Where(u => !string.IsNullOrWhiteSpace(u)))
            _db.OAuthClientRedirectUris.Add(new OAuthClientRedirectUri { OAuthClientId = client.Id, Uri = uri.Trim() });
        foreach (var scope in scopes.Where(s => !string.IsNullOrWhiteSpace(s)))
            _db.OAuthClientScopes.Add(new OAuthClientScope { OAuthClientId = client.Id, Scope = scope.Trim() });
        foreach (var gt in grantTypes.Where(g => !string.IsNullOrWhiteSpace(g)))
            _db.OAuthClientGrantTypes.Add(new OAuthClientGrantType { OAuthClientId = client.Id, GrantType = gt.Trim() });

        await _db.SaveChangesAsync();
    }

    public async Task SetClientEnabledAsync(int clientId, bool enabled)
    {
        var client = await _db.OAuthClients.FindAsync(clientId);
        if (client != null) { client.IsEnabled = enabled; await _db.SaveChangesAsync(); }
    }

    public async Task DeleteClientAsync(int clientId)
    {
        var client = await _db.OAuthClients.FindAsync(clientId);
        if (client != null) { _db.OAuthClients.Remove(client); await _db.SaveChangesAsync(); }
    }

    public async Task<List<ApplicationUser>> GetUsersAsync() =>
        await _db.Users.OrderBy(u => u.Email).ToListAsync();

    public async Task<ApplicationUser?> GetUserAsync(string id) =>
        await _db.Users.FindAsync(id);

    public async Task SetUserLockedAsync(string userId, bool locked)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user != null)
        {
            if (locked) await _userManager.SetLockoutEndDateAsync(user, DateTimeOffset.MaxValue);
            else await _userManager.SetLockoutEndDateAsync(user, null);
        }
    }

    public async Task<List<string>> GetUserRolesAsync(string userId)
    {
        var user = await _userManager.FindByIdAsync(userId);
        return user == null ? new() : (await _userManager.GetRolesAsync(user)).ToList();
    }

    public async Task SetUserRolesAsync(string userId, List<string> roles)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null) return;
        var current = await _userManager.GetRolesAsync(user);
        await _userManager.RemoveFromRolesAsync(user, current);
        await _userManager.AddToRolesAsync(user, roles);
    }

    public async Task<List<LoginAudit>> GetUserLoginHistoryAsync(string userId) =>
        await _db.LoginAudits.Where(a => a.UserId == userId).OrderByDescending(a => a.CreatedAt).Take(50).ToListAsync();

    public async Task AssignUserToProjectAsync(int projectId, string userId, string role)
    {
        var existing = await _db.ProjectUsers.FirstOrDefaultAsync(pu => pu.ProjectId == projectId && pu.UserId == userId);
        if (existing != null) { existing.Role = role; }
        else { _db.ProjectUsers.Add(new ProjectUser { ProjectId = projectId, UserId = userId, Role = role }); }
        await _db.SaveChangesAsync();
    }

    public async Task RemoveUserFromProjectAsync(int projectId, string userId)
    {
        var pu = await _db.ProjectUsers.FirstOrDefaultAsync(p => p.ProjectId == projectId && p.UserId == userId);
        if (pu != null) { _db.ProjectUsers.Remove(pu); await _db.SaveChangesAsync(); }
    }

    public async Task<List<OAuthScope>> GetScopesAsync() =>
        await _db.OAuthScopes.OrderBy(s => s.Name).ToListAsync();
}
