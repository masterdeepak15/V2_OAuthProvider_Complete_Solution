using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using OAuthProviderV2.Data;
using OAuthProviderV2.Models;
using OAuthProviderV2.Services;
using Xunit;

namespace OAuthProvider.Tests;

/// <summary>
/// Bug #3 regression: project-user assignment must actually gate which OAuth client a
/// user may authorize. Before the fix, UserCanAccessClientAsync did not exist and any
/// authenticated user (even cross-tenant) could authorize any client.
/// </summary>
public class UserCanAccessClientTests : IDisposable
{
    private readonly SqliteConnection _conn;
    private readonly ApplicationDbContext _db;
    private readonly OAuthService _sut;

    public UserCanAccessClientTests()
    {
        _conn = new SqliteConnection("DataSource=:memory:");
        _conn.Open();
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseSqlite(_conn).Options;
        _db = new ApplicationDbContext(options);
        _db.Database.EnsureCreated();
        _sut = new OAuthService(_db, jwt: null!); // jwt unused by the method under test
    }

    private OAuthClient SeedClient(int orgId = 1, int projectId = 10)
    {
        EnsureOrg(orgId);
        EnsureProject(projectId, orgId);
        _db.SaveChanges();
        return new OAuthClient
        {
            Id = 100, OrganizationId = orgId, ProjectId = projectId,
            ClientId = "client-abc", Name = "Acme App",
        };
    }

    private void EnsureOrg(int orgId)
    {
        if (_db.Organizations.Local.Any(o => o.Id == orgId) || _db.Organizations.Any(o => o.Id == orgId)) return;
        _db.Organizations.Add(new Organization { Id = orgId, Name = $"Org{orgId}", Slug = $"org{orgId}", AdminEmail = $"admin{orgId}@x.test" });
    }

    private void EnsureProject(int projectId, int orgId)
    {
        EnsureOrg(orgId);
        if (_db.Projects.Local.Any(p => p.Id == projectId) || _db.Projects.Any(p => p.Id == projectId)) return;
        _db.Projects.Add(new Project { Id = projectId, OrganizationId = orgId, Name = $"Project{projectId}" });
    }

    private void EnsureUser(string userId)
    {
        if (_db.Users.Local.Any(u => u.Id == userId) || _db.Users.Any(u => u.Id == userId)) return;
        _db.Users.Add(new ApplicationUser { Id = userId, UserName = $"{userId}@x.test", Email = $"{userId}@x.test" });
    }

    private async Task AddMemberAsync(string userId, int orgId, string role, bool active = true)
    {
        EnsureOrg(orgId);
        EnsureUser(userId);
        _db.OrganizationUsers.Add(new OrganizationUser
        { OrganizationId = orgId, UserId = userId, Role = role, IsActive = active });
        await _db.SaveChangesAsync();
    }

    private async Task AssignToProjectAsync(string userId, int projectId, int orgId = 1)
    {
        EnsureProject(projectId, orgId);
        EnsureUser(userId);
        _db.ProjectUsers.Add(new ProjectUser { ProjectId = projectId, UserId = userId, Role = "developer" });
        await _db.SaveChangesAsync();
    }

    [Fact]
    public async Task ProjectMember_CanAccessClient()
    {
        var client = SeedClient();
        await AddMemberAsync("u-member", orgId: 1, role: "member");
        await AssignToProjectAsync("u-member", projectId: 10);

        Assert.True(await _sut.UserCanAccessClientAsync("u-member", client));
    }

    [Fact]
    public async Task OrgMember_NotAssignedToProject_CannotAccessClient()
    {
        var client = SeedClient();
        await AddMemberAsync("u-stranger", orgId: 1, role: "member");
        // No ProjectUser row.

        Assert.False(await _sut.UserCanAccessClientAsync("u-stranger", client));
    }

    [Fact]
    public async Task OrgAdmin_CanAccessClient_WithoutProjectMembership()
    {
        var client = SeedClient();
        await AddMemberAsync("u-admin", orgId: 1, role: "admin");

        Assert.True(await _sut.UserCanAccessClientAsync("u-admin", client));
    }

    [Fact]
    public async Task UserFromAnotherOrg_CannotAccessClient()
    {
        var client = SeedClient(orgId: 1, projectId: 10);
        await AddMemberAsync("u-other", orgId: 2, role: "admin");
        await AssignToProjectAsync("u-other", projectId: 10); // even if mis-assigned

        Assert.False(await _sut.UserCanAccessClientAsync("u-other", client));
    }

    [Fact]
    public async Task InactiveMembership_CannotAccessClient()
    {
        var client = SeedClient();
        await AddMemberAsync("u-disabled", orgId: 1, role: "member", active: false);
        await AssignToProjectAsync("u-disabled", projectId: 10);

        Assert.False(await _sut.UserCanAccessClientAsync("u-disabled", client));
    }

    public void Dispose()
    {
        _db.Dispose();
        _conn.Dispose();
    }
}
