using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using OAuthProviderV2.Data;
using OAuthProviderV2.Models;
using UAParser;

namespace OAuthProviderV2.Services.Audit;

public interface IAuditService
{
    Task LogAsync(AuditLogRequest req);
    Task<List<AuditLog>> GetLogsAsync(int? organizationId, int page = 1, int pageSize = 50, string? eventType = null, string? userId = null, DateTime? from = null, DateTime? to = null);
    Task<long> GetLogCountAsync(int? organizationId);
    SessionInfo ParseSession(HttpContext ctx);
}

public class AuditLogRequest
{
    public int? OrganizationId { get; set; }
    public string? UserId { get; set; }
    public string? UserEmail { get; set; }
    public string EventType { get; set; } = string.Empty;
    public string EventCategory { get; set; } = "system";
    public string? ResourceType { get; set; }
    public string? ResourceId { get; set; }
    public string? ResourceName { get; set; }
    public bool Success { get; set; } = true;
    public string? FailureReason { get; set; }
    public object? Details { get; set; }
    public HttpContext? HttpContext { get; set; }
}

public class SessionInfo
{
    public string? IpAddress { get; set; }
    public string? UserAgent { get; set; }
    public string? Browser { get; set; }
    public string? BrowserVersion { get; set; }
    public string? OperatingSystem { get; set; }
    public string? OsVersion { get; set; }
    public string? DeviceType { get; set; }
    public string? DeviceBrand { get; set; }
}

public class AuditService : IAuditService
{
    private readonly ApplicationDbContext _db;
    private static readonly Parser _uaParser = Parser.GetDefault();

    public AuditService(ApplicationDbContext db) => _db = db;

    public async Task LogAsync(AuditLogRequest req)
    {
        SessionInfo? session = null;
        if (req.HttpContext != null)
            session = ParseSession(req.HttpContext);

        var log = new AuditLog
        {
            OrganizationId = req.OrganizationId,
            UserId         = req.UserId,
            UserEmail      = req.UserEmail,
            EventType      = req.EventType,
            EventCategory  = req.EventCategory,
            ResourceType   = req.ResourceType,
            ResourceId     = req.ResourceId,
            ResourceName   = req.ResourceName,
            Success        = req.Success,
            FailureReason  = req.FailureReason,
            Details        = req.Details != null ? JsonSerializer.Serialize(req.Details) : null,
            IpAddress      = session?.IpAddress,
            UserAgent      = session?.UserAgent,
            Browser        = session?.Browser,
            BrowserVersion = session?.BrowserVersion,
            OperatingSystem = session?.OperatingSystem,
            OsVersion      = session?.OsVersion,
            DeviceType     = session?.DeviceType,
            DeviceBrand    = session?.DeviceBrand,
        };

        _db.AuditLogs.Add(log);
        await _db.SaveChangesAsync();
    }

    public async Task<List<AuditLog>> GetLogsAsync(int? organizationId, int page = 1, int pageSize = 50,
        string? eventType = null, string? userId = null, DateTime? from = null, DateTime? to = null)
    {
        var query = _db.AuditLogs.AsQueryable();

        if (organizationId.HasValue)
            query = query.Where(l => l.OrganizationId == organizationId);

        if (!string.IsNullOrEmpty(eventType))
            query = query.Where(l => l.EventType == eventType || l.EventCategory == eventType);

        if (!string.IsNullOrEmpty(userId))
            query = query.Where(l => l.UserId == userId);

        if (from.HasValue)
            query = query.Where(l => l.CreatedAt >= from.Value);

        if (to.HasValue)
            query = query.Where(l => l.CreatedAt <= to.Value);

        return await query
            .OrderByDescending(l => l.CreatedAt)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync();
    }

    public async Task<long> GetLogCountAsync(int? organizationId)
    {
        var query = _db.AuditLogs.AsQueryable();
        if (organizationId.HasValue)
            query = query.Where(l => l.OrganizationId == organizationId);
        return await query.LongCountAsync();
    }

    public SessionInfo ParseSession(HttpContext ctx)
    {
        var ua = ctx.Request.Headers["User-Agent"].ToString();
        var ip = ctx.Connection.RemoteIpAddress?.ToString();

        // Try X-Forwarded-For first (behind proxy/load balancer)
        var forwarded = ctx.Request.Headers["X-Forwarded-For"].FirstOrDefault();
        if (!string.IsNullOrEmpty(forwarded))
            ip = forwarded.Split(',')[0].Trim();

        string? browser = null, browserVersion = null, os = null, osVersion = null, deviceType = null, deviceBrand = null;

        if (!string.IsNullOrEmpty(ua))
        {
            try
            {
                var client = _uaParser.Parse(ua);
                browser        = client.UA.Family;
                browserVersion = $"{client.UA.Major}.{client.UA.Minor}".TrimEnd('.');
                os             = client.OS.Family;
                osVersion      = $"{client.OS.Major}.{client.OS.Minor}".TrimEnd('.');
                deviceType     = client.Device.IsSpider ? "Bot" :
                                 ua.Contains("Mobile", StringComparison.OrdinalIgnoreCase) ? "Mobile" :
                                 ua.Contains("Tablet", StringComparison.OrdinalIgnoreCase) ? "Tablet" : "Desktop";
                deviceBrand    = client.Device.Brand;
            }
            catch { /* graceful degradation */ }
        }

        return new SessionInfo
        {
            IpAddress      = ip,
            UserAgent      = ua,
            Browser        = browser,
            BrowserVersion = browserVersion,
            OperatingSystem = os,
            OsVersion      = osVersion,
            DeviceType     = deviceType,
            DeviceBrand    = deviceBrand,
        };
    }
}
