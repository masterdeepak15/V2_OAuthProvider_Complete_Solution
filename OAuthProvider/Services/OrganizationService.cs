using System.Security.Cryptography;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using OAuthProviderV2.Data;
using OAuthProviderV2.Models;
using OAuthProviderV2.Services.Email;

namespace OAuthProviderV2.Services;

public interface IOrganizationService
{
    Task<Organization> CreateAsync(string name, string adminEmail, string ownerFirstName, string ownerLastName, string ownerPassword);
    Task<Organization?> GetByIdAsync(int id, string? requestingUserId = null);
    Task<List<Organization>> GetAllAsync();                             // SuperAdmin only
    Task<bool> BlockAsync(int id, string reason);
    Task<bool> UnblockAsync(int id);
    Task UpdateLimitsAsync(int id, int maxUsers, int maxProjects, int maxClients);

    // User management (org-scoped)
    Task<(bool ok, string? error)> InviteUserAsync(int orgId, string email, string firstName, string lastName, string role, string baseUrl);
    Task<bool> VerifyUserEmailAsync(string token);
    Task<string?> GetManualVerifyLinkAsync(int orgId, string userId, string baseUrl);
    Task<bool> RemoveUserAsync(int orgId, string userId);
    Task<List<ApplicationUser>> GetUsersAsync(int orgId);
    Task<ApplicationUser?> GetUserAsync(int orgId, string userId);
    Task UpdateUserRoleAsync(int orgId, string userId, string role);
    Task<bool> ToggleUserActiveAsync(int orgId, string userId);
}

public class OrganizationService : IOrganizationService
{
    private readonly ApplicationDbContext _db;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IEmailService _email;

    public OrganizationService(ApplicationDbContext db, UserManager<ApplicationUser> um, IEmailService email)
    {
        _db = db;
        _userManager = um;
        _email = email;
    }

    public async Task<Organization> CreateAsync(string name, string adminEmail, string ownerFirstName, string ownerLastName, string ownerPassword)
    {
        var slug = GenerateSlug(name);

        // Ensure unique slug
        var base_slug = slug;
        int suffix = 1;
        while (await _db.Organizations.AnyAsync(o => o.Slug == slug))
            slug = $"{base_slug}-{suffix++}";

        // Create the organization first
        var org = new Organization
        {
            Name       = name,
            Slug       = slug,
            AdminEmail = adminEmail.ToLowerInvariant(),
        };
        _db.Organizations.Add(org);
        await _db.SaveChangesAsync();

        // Create the owner user
        var owner = new ApplicationUser
        {
            UserName        = adminEmail.ToLowerInvariant(),
            Email           = adminEmail.ToLowerInvariant(),
            EmailConfirmed  = true,       // owner verified via OTP at signup
            FirstName       = ownerFirstName,
            LastName        = ownerLastName,
            OrganizationId  = org.Id,
            IsActive        = true,
            IsEmailVerified = true,
        };

        var result = await _userManager.CreateAsync(owner, ownerPassword);
        if (!result.Succeeded)
        {
            _db.Organizations.Remove(org);
            await _db.SaveChangesAsync();
            throw new InvalidOperationException(string.Join("; ", result.Errors.Select(e => e.Description)));
        }

        await _userManager.AddToRoleAsync(owner, "OrgAdmin");

        // Link owner to org
        org.OwnerId = owner.Id;
        _db.OrganizationUsers.Add(new OrganizationUser
        {
            OrganizationId = org.Id,
            UserId         = owner.Id,
            Role           = "owner",
        });

        // Default email config
        _db.OrganizationEmailConfigs.Add(new OrganizationEmailConfig
        {
            OrganizationId    = org.Id,
            UseDefaultProvider = true,
            AlertsEnabled     = true,
            LoginAlerts       = true,
            SecurityAlerts    = true,
            WafAlerts         = true,
        });

        await _db.SaveChangesAsync();
        return org;
    }

    public async Task<Organization?> GetByIdAsync(int id, string? requestingUserId = null)
    {
        var org = await _db.Organizations
            .Include(o => o.Members).ThenInclude(m => m.User)
            .Include(o => o.Projects)
            .Include(o => o.EmailConfig)
            .FirstOrDefaultAsync(o => o.Id == id);

        // Enforce isolation: non-super-admins can only see their own org
        if (org == null) return null;
        if (requestingUserId != null && org.Members.All(m => m.UserId != requestingUserId))
            return null;

        return org;
    }

    public async Task<List<Organization>> GetAllAsync() =>
        await _db.Organizations
            .Include(o => o.Members)
            .Include(o => o.Projects)
            .OrderByDescending(o => o.CreatedAt)
            .ToListAsync();

    public async Task<bool> BlockAsync(int id, string reason)
    {
        var org = await _db.Organizations.FindAsync(id);
        if (org == null) return false;
        org.IsBlocked = true;
        org.BlockReason = reason;
        await _db.SaveChangesAsync();
        return true;
    }

    public async Task<bool> UnblockAsync(int id)
    {
        var org = await _db.Organizations.FindAsync(id);
        if (org == null) return false;
        org.IsBlocked = false;
        org.BlockReason = null;
        await _db.SaveChangesAsync();
        return true;
    }

    public async Task UpdateLimitsAsync(int id, int maxUsers, int maxProjects, int maxClients)
    {
        var org = await _db.Organizations.FindAsync(id);
        if (org == null) return;
        org.MaxUsers    = maxUsers;
        org.MaxProjects = maxProjects;
        org.MaxClients  = maxClients;
        org.UpdatedAt   = DateTime.UtcNow;
        await _db.SaveChangesAsync();
    }

    public async Task<(bool ok, string? error)> InviteUserAsync(int orgId, string email, string firstName, string lastName, string role, string baseUrl)
    {
        var org = await _db.Organizations.FindAsync(orgId);
        if (org == null) return (false, "Organization not found");

        // Limit check
        var memberCount = await _db.OrganizationUsers.CountAsync(ou => ou.OrganizationId == orgId);
        if (memberCount >= org.MaxUsers)
            return (false, $"User limit reached ({org.MaxUsers})");

        // Check if user already exists globally
        var existing = await _userManager.FindByEmailAsync(email);
        if (existing != null && existing.OrganizationId != orgId)
            return (false, "Email is already registered in another organization");

        // Create or reuse user
        ApplicationUser user;
        bool isNew = false;
        if (existing == null)
        {
            // Generate a temporary password — user must set their own via email flow
            var tempPassword = GenerateTempPassword();
            user = new ApplicationUser
            {
                UserName        = email.ToLowerInvariant(),
                Email           = email.ToLowerInvariant(),
                FirstName       = firstName,
                LastName        = lastName,
                OrganizationId  = orgId,
                IsActive        = true,
                IsEmailVerified = false,
                EmailVerificationToken  = GenerateVerificationToken(),
                EmailVerificationTokenExpiry = DateTime.UtcNow.AddHours(48),
            };
            var result = await _userManager.CreateAsync(user, tempPassword);
            if (!result.Succeeded)
                return (false, string.Join("; ", result.Errors.Select(e => e.Description)));

            await _userManager.AddToRoleAsync(user, "OrgUser");
            isNew = true;
        }
        else
        {
            user = existing;
            // Refresh token
            user.EmailVerificationToken       = GenerateVerificationToken();
            user.EmailVerificationTokenExpiry = DateTime.UtcNow.AddHours(48);
            user.IsEmailVerified              = false;
            await _userManager.UpdateAsync(user);
        }

        // Add to org
        if (!await _db.OrganizationUsers.AnyAsync(ou => ou.OrganizationId == orgId && ou.UserId == user.Id))
        {
            _db.OrganizationUsers.Add(new OrganizationUser
            {
                OrganizationId = orgId,
                UserId         = user.Id,
                Role           = role,
            });
            await _db.SaveChangesAsync();
        }

        // Send verification email
        var verifyUrl = $"{baseUrl}/Account/VerifyEmail?token={Uri.EscapeDataString(user.EmailVerificationToken!)}";
        await _email.SendUserInviteAsync(email, $"{firstName} {lastName}", verifyUrl, org.Name);

        return (true, null);
    }

    public async Task<bool> VerifyUserEmailAsync(string token)
    {
        var user = await _db.Users
            .FirstOrDefaultAsync(u => u.EmailVerificationToken == token
                                  && u.EmailVerificationTokenExpiry > DateTime.UtcNow
                                  && !u.IsEmailVerified);
        if (user == null) return false;

        user.IsEmailVerified              = true;
        user.EmailConfirmed               = true;
        user.EmailVerificationToken       = null;
        user.EmailVerificationTokenExpiry = null;
        await _userManager.UpdateAsync(user);
        return true;
    }

    public async Task<string?> GetManualVerifyLinkAsync(int orgId, string userId, string baseUrl)
    {
        var user = await _db.Users
            .FirstOrDefaultAsync(u => u.Id == userId && u.OrganizationId == orgId);
        if (user == null) return null;

        // Regenerate token
        user.EmailVerificationToken       = GenerateVerificationToken();
        user.EmailVerificationTokenExpiry = DateTime.UtcNow.AddHours(48);
        await _userManager.UpdateAsync(user);

        return $"{baseUrl}/Account/VerifyEmail?token={Uri.EscapeDataString(user.EmailVerificationToken)}";
    }

    public async Task<bool> RemoveUserAsync(int orgId, string userId)
    {
        var ou = await _db.OrganizationUsers
            .FirstOrDefaultAsync(x => x.OrganizationId == orgId && x.UserId == userId);
        if (ou == null) return false;
        _db.OrganizationUsers.Remove(ou);
        await _db.SaveChangesAsync();
        return true;
    }

    public async Task<List<ApplicationUser>> GetUsersAsync(int orgId) =>
        await _db.OrganizationUsers
            .Where(ou => ou.OrganizationId == orgId)
            .Include(ou => ou.User)
            .Select(ou => ou.User)
            .ToListAsync();

    public async Task<ApplicationUser?> GetUserAsync(int orgId, string userId) =>
        await _db.OrganizationUsers
            .Where(ou => ou.OrganizationId == orgId && ou.UserId == userId)
            .Include(ou => ou.User)
            .Select(ou => ou.User)
            .FirstOrDefaultAsync();

    public async Task UpdateUserRoleAsync(int orgId, string userId, string role)
    {
        var ou = await _db.OrganizationUsers
            .FirstOrDefaultAsync(x => x.OrganizationId == orgId && x.UserId == userId);
        if (ou == null) return;
        ou.Role = role;
        await _db.SaveChangesAsync();
    }

    public async Task<bool> ToggleUserActiveAsync(int orgId, string userId)
    {
        var user = await GetUserAsync(orgId, userId);
        if (user == null) return false;
        user.IsActive = !user.IsActive;
        await _userManager.UpdateAsync(user);
        return user.IsActive;
    }

    private static string GenerateSlug(string name)
    {
        var slug = name.ToLowerInvariant();
        slug = Regex.Replace(slug, @"[^a-z0-9\s-]", "");
        slug = Regex.Replace(slug, @"\s+", "-");
        slug = slug.Trim('-');
        return slug.Length > 50 ? slug[..50] : slug;
    }

    private static string GenerateVerificationToken()
    {
        var bytes = new byte[48];
        RandomNumberGenerator.Fill(bytes);
        return Convert.ToBase64String(bytes).Replace("+", "-").Replace("/", "_").TrimEnd('=');
    }

    private static string GenerateTempPassword()
    {
        var bytes = new byte[16];
        RandomNumberGenerator.Fill(bytes);
        return "Tmp@" + Convert.ToBase64String(bytes)[..12] + "1";
    }
}
