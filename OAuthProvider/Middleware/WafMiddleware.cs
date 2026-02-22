using System.Collections.Concurrent;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using OAuthProviderV2.Data;
using OAuthProviderV2.Models;

namespace OAuthProviderV2.Middleware;

public class WafMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<WafMiddleware> _logger;

    // In-memory rate limit tracker (supplement DB for performance)
    private static readonly ConcurrentDictionary<string, (int count, DateTime window, DateTime? blockedUntil)> _rateLimits = new();

    // Dangerous patterns
    // SQL injection: require URL-decoded value to contain attack patterns
    // Uses word boundaries and multi-token checks to avoid false positives on
    // normal OAuth query parameters (response_type=, redirect_uri=, etc.)
    private static readonly Regex[] _sqlPatterns = new[]
    {
        // Classic UNION-based injection: must have UNION followed by SELECT
        new Regex(@"\bunion\s+all\s+select\b|\bunion\s+select\b", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        // Stacked queries: semicolon followed immediately by a SQL keyword
        new Regex(@";\s*(drop|truncate|insert|update|delete|exec|execute)\b", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        // Comment-based termination used in injections (-- or /**/)
        new Regex(@"(-{2}\s*$|/\*[\s\S]*?\*/)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        // Boolean-based blind: 1=1 or 'x'='x' style (must have two sides to the equality)
        new Regex(@"'\s*=\s*'|1\s*=\s*1|0\s*=\s*0", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        // xp_ / sp_ stored procedure calls
        new Regex(@"\b(xp_|sp_)\w+", RegexOptions.IgnoreCase | RegexOptions.Compiled),
    };

    // XSS patterns — all require unambiguous injection context, not just isolated tokens.
    // Values like redirect_uri, code_challenge, state are safe because they never
    // contain literal < characters or javascript:/vbscript: schemes.
    private static readonly Regex[] _xssPatterns = new[]
    {
        // <script> opening tag — requires literal < so can't false-positive on plain param values
        new Regex(@"<\s*script[\s/>]", RegexOptions.IgnoreCase | RegexOptions.Compiled),

        // javascript: or vbscript: URI scheme — only dangerous in href/src/action contexts
        // Require it NOT be preceded by normal URL chars (http, https) to avoid false positives
        new Regex(@"(?<![a-z])javascript\s*:", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new Regex(@"(?<![a-z])vbscript\s*:", RegexOptions.IgnoreCase | RegexOptions.Compiled),

        // Event handlers: ONLY match when inside an HTML tag — requires a preceding <tag
        // e.g. <img onload= or <div onclick= — will NOT match response_type= or redirect_uri=
        new Regex(@"<\s*\w[^>]*\s\bon\w{2,}\s*=", RegexOptions.IgnoreCase | RegexOptions.Compiled),

        // Dangerous HTML tags that indicate injected markup
        new Regex(@"<\s*(script|iframe|object|embed|applet|svg|math)\b", RegexOptions.IgnoreCase | RegexOptions.Compiled),

        // data:text/html and data:application/javascript — requires the full scheme
        new Regex(@"\bdata\s*:\s*(text/html|application/javascript|text/javascript)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
    };

    private static readonly Regex[] _pathTraversalPatterns = new[]
    {
        new Regex(@"\.\./|\.\.\\", RegexOptions.Compiled),
        new Regex(@"%2e%2e[/\\]", RegexOptions.IgnoreCase | RegexOptions.Compiled),
    };

    private static readonly string[] _suspiciousUAs = new[]
    {
        "sqlmap", "nikto", "nmap", "masscan", "nessus", "burpsuite",
        "dirbuster", "gobuster", "wfuzz", "hydra", "medusa", "acunetix"
    };

    // Rate limits per endpoint type
    private static readonly Dictionary<string, (int max, int windowSec, int blockSec)> _limits = new()
    {
        ["/Account/Login"]       = (10, 60, 900),   // 10 req/min → block 15 min
        ["/Account/Signup"]      = (5, 300, 3600),  // 5 req/5min → block 1 hour
        ["/Account/VerifyOtp"]   = (5, 300, 3600),
        ["/token"]               = (30, 60, 300),
        ["/authorize"]           = (20, 60, 120),
        ["default"]              = (200, 60, 60),
    };

    public WafMiddleware(RequestDelegate next, ILogger<WafMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext ctx, ApplicationDbContext db)
    {
        var ip       = GetClientIp(ctx);
        var path     = ctx.Request.Path.Value?.ToLowerInvariant() ?? "/";
        var ua       = ctx.Request.Headers["User-Agent"].ToString();
        var method   = ctx.Request.Method;
        var qs       = ctx.Request.QueryString.Value;

        // ── 1. Check existing IP block rules ─────────────────────────────────
        var blockRule = await db.WafRules
            .Where(r => r.IsEnabled && r.IsBlock && r.RuleType == "ip_block" && r.Pattern == ip)
            .FirstOrDefaultAsync();

        if (blockRule != null)
        {
            await RecordWafEvent(db, ip, path, method, qs, ua, "ip_block", "critical", "IP Block Rule", blockRule.Name);
            ctx.Response.StatusCode = 403;
            await ctx.Response.WriteAsync("Access denied.");
            return;
        }

        // ── 2. Suspicious User-Agent ──────────────────────────────────────────
        if (!string.IsNullOrEmpty(ua))
        {
            var lowerUa = ua.ToLowerInvariant();
            var matchedTool = _suspiciousUAs.FirstOrDefault(t => lowerUa.Contains(t));
            if (matchedTool != null)
            {
                await RecordWafEvent(db, ip, path, method, qs, ua, "suspicious_ua", "high", "Suspicious User-Agent", matchedTool);
                ctx.Response.StatusCode = 403;
                await ctx.Response.WriteAsync("Access denied.");
                return;
            }
        }

        // ── 3. Path traversal ─────────────────────────────────────────────────
        var fullPath = ctx.Request.Path + ctx.Request.QueryString;
        foreach (var pattern in _pathTraversalPatterns)
        {
            if (pattern.IsMatch(fullPath))
            {
                await RecordWafEvent(db, ip, path, method, qs, ua, "path_traversal", "high", "Path Traversal", pattern.ToString());
                ctx.Response.StatusCode = 400;
                await ctx.Response.WriteAsync("Bad request.");
                return;
            }
        }

        // ── 4. SQL injection — scan decoded param VALUES only ─────────────────
        if (!string.IsNullOrEmpty(qs))
        {
            var paramValues = ExtractQueryValues(qs);
            foreach (var val in paramValues)
            {
                foreach (var pattern in _sqlPatterns)
                {
                    if (pattern.IsMatch(val))
                    {
                        _logger.LogWarning("[WAF] SQLi block — pattern: {Pattern} matched value: {Value} on {Path}",
                            pattern, val, path);
                        await RecordWafEvent(db, ip, path, method, qs, ua, "sql_injection", "critical", "SQL Injection Pattern", pattern.ToString());
                        ctx.Response.StatusCode = 400;
                        await ctx.Response.WriteAsync("Bad request.");
                        return;
                    }
                }
            }
        }

        // ── 5. XSS — scan decoded param VALUES only ───────────────────────────
        if (!string.IsNullOrEmpty(qs))
        {
            var paramValues = ExtractQueryValues(qs);
            foreach (var val in paramValues)
            {
                foreach (var pattern in _xssPatterns)
                {
                    if (pattern.IsMatch(val))
                    {
                        _logger.LogWarning("[WAF] XSS block — pattern: {Pattern} matched value: {Value} on {Path}",
                            pattern, val, path);
                        await RecordWafEvent(db, ip, path, method, qs, ua, "xss", "high", "XSS Pattern", pattern.ToString());
                        ctx.Response.StatusCode = 400;
                        await ctx.Response.WriteAsync("Bad request.");
                        return;
                    }
                }
            }
        }

        // ── 6. Rate limiting ──────────────────────────────────────────────────
        var limitKey = _limits.ContainsKey(path) ? path : "default";
        var (max, windowSec, blockSec) = _limits[limitKey];
        var rateKey = $"{ip}:{limitKey}";

        if (_rateLimits.TryGetValue(rateKey, out var state))
        {
            if (state.blockedUntil.HasValue && state.blockedUntil > DateTime.UtcNow)
            {
                await RecordWafEvent(db, ip, path, method, qs, ua, "rate_limit", "medium", "Rate Limit Block", $"{max}/{windowSec}s");
                ctx.Response.StatusCode = 429;
                ctx.Response.Headers["Retry-After"] = ((int)(state.blockedUntil.Value - DateTime.UtcNow).TotalSeconds).ToString();
                await ctx.Response.WriteAsync("Too many requests.");
                return;
            }

            var elapsed = (DateTime.UtcNow - state.window).TotalSeconds;
            if (elapsed > windowSec)
            {
                _rateLimits[rateKey] = (1, DateTime.UtcNow, null);
            }
            else if (state.count >= max)
            {
                var blockedUntil = DateTime.UtcNow.AddSeconds(blockSec);
                _rateLimits[rateKey] = (state.count + 1, state.window, blockedUntil);
                await RecordWafEvent(db, ip, path, method, qs, ua, "rate_limit", "high", "Rate Limit Exceeded", $"{max} req in {windowSec}s");
                ctx.Response.StatusCode = 429;
                await ctx.Response.WriteAsync("Too many requests.");
                return;
            }
            else
            {
                _rateLimits[rateKey] = (state.count + 1, state.window, null);
            }
        }
        else
        {
            _rateLimits[rateKey] = (1, DateTime.UtcNow, null);
        }

        // ── 7. Add security headers to response ───────────────────────────────
        ctx.Response.OnStarting(() =>
        {
            ctx.Response.Headers["X-Content-Type-Options"] = "nosniff";
            ctx.Response.Headers["X-Frame-Options"] = "SAMEORIGIN";
            ctx.Response.Headers["X-XSS-Protection"] = "1; mode=block";
            ctx.Response.Headers["Referrer-Policy"] = "strict-origin-when-cross-origin";
            ctx.Response.Headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()";
            if (!ctx.Response.Headers.ContainsKey("Content-Security-Policy"))
            {
                ctx.Response.Headers["Content-Security-Policy"] =
                    "default-src 'self'; script-src 'self' 'unsafe-inline' cdn.jsdelivr.net; " +
                    "style-src 'self' 'unsafe-inline' cdn.jsdelivr.net; img-src 'self' data:; " +
                    "connect-src 'self' wss:;";
            }
            return Task.CompletedTask;
        });

        await _next(ctx);
    }

    private static async Task RecordWafEvent(ApplicationDbContext db, string ip, string path, string method,
        string? qs, string? ua, string threatType, string level, string ruleName, string? pattern)
    {
        db.WafEvents.Add(new WafEvent
        {
            IpAddress     = ip,
            RequestPath   = path,
            RequestMethod = method,
            QueryString   = qs,
            UserAgent     = ua,
            ThreatType    = threatType,
            ThreatLevel   = level,
            WasBlocked    = true,
            RuleName      = ruleName,
            MatchedPattern = pattern,
        });
        await db.SaveChangesAsync();
    }

    private static string GetClientIp(HttpContext ctx)
    {
        var forwarded = ctx.Request.Headers["X-Forwarded-For"].FirstOrDefault();
        if (!string.IsNullOrEmpty(forwarded))
            return forwarded.Split(',')[0].Trim();
        return ctx.Connection.RemoteIpAddress?.ToString() ?? "0.0.0.0";
    }

    /// <summary>
    /// Extracts and URL-decodes only the VALUES from a query string,
    /// ignoring the parameter keys. This prevents false positives on
    /// key names like "response_type", "redirect_uri", "code_challenge".
    /// </summary>
    private static IEnumerable<string> ExtractQueryValues(string queryString)
    {
        // Strip leading '?'
        var qs = queryString.TrimStart('?');
        foreach (var pair in qs.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var eq = pair.IndexOf('=');
            if (eq >= 0 && eq < pair.Length - 1)
            {
                var raw = pair[(eq + 1)..];
                string decoded;
                try { decoded = Uri.UnescapeDataString(raw.Replace("+", " ")); }
                catch { decoded = raw; }
                yield return decoded;
            }
        }
    }
}
