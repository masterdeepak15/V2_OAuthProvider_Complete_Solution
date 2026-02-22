using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.WebUtilities;
using OAuthProviderV2.Data;
using OAuthProviderV2.Models;
using OAuthProviderV2.Services;
using OAuthProviderV2.Services.Audit;

namespace OAuthProviderV2.Pages.Account;

public class ScopeDetail
{
    public string Icon        { get; set; } = "📋";
    public string BgColor     { get; set; } = "#f3f4f6";
    public string Name        { get; set; } = "";
    public string Description { get; set; } = "";
}

public class ConsentModel : PageModel
{
    private readonly ApplicationDbContext          _db;
    private readonly UserManager<ApplicationUser>  _userMgr;
    private readonly IOAuthService                 _oauth;
    private readonly IAuditService                 _audit;
    private readonly IAccountSessionService        _sessions;

    public ConsentModel(ApplicationDbContext db, UserManager<ApplicationUser> userMgr,
        IOAuthService oauth, IAuditService audit, IAccountSessionService sessions)
    {
        _db = db; _userMgr = userMgr; _oauth = oauth; _audit = audit; _sessions = sessions;
    }

    public string  ClientName        { get; set; } = "";
    public string? ClientDescription { get; set; }
    public string  UserEmail         { get; set; } = "";
    public string  UserInitials      { get; set; } = "?";
    public string  UserColor         { get; set; } = "#6366f1";
    public string  DenyRedirect      { get; set; } = "/";
    public string  ReturnParams      { get; set; } = "";
    public List<ScopeDetail> ScopeDetails { get; set; } = new();

    public async Task<IActionResult> OnGetAsync(
        string client_id, string redirect_uri, string scope, string? state,
        string? code_challenge, string? code_challenge_method)
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (string.IsNullOrEmpty(userId))
            return Redirect("/Account/Login");

        var client = await _oauth.ValidateClientAsync(client_id);
        if (client == null) return BadRequest("Unknown client.");

        var user = await _userMgr.FindByIdAsync(userId);
        if (user == null) return Redirect("/Account/Login");

        // Stash all params encoded so we can reconstruct after consent
        var ps = new Dictionary<string, string?>
        {
            ["client_id"]             = client_id,
            ["redirect_uri"]          = redirect_uri,
            ["scope"]                 = scope,
            ["state"]                 = state ?? "",
            ["code_challenge"]        = code_challenge ?? "",
            ["code_challenge_method"] = code_challenge_method ?? "",
        };
        ReturnParams = Uri.EscapeDataString(QueryHelpers.AddQueryString("", ps).TrimStart('?'));

        ClientName        = client.Name;
        ClientDescription = client.Description;
        DenyRedirect      = $"{redirect_uri}?error=access_denied" +
            (!string.IsNullOrEmpty(state) ? $"&state={Uri.EscapeDataString(state)}" : "");
        UserEmail    = user.Email!;
        UserInitials = GetInitials(user);
        UserColor    = GetColor(user.Email!);
        ScopeDetails = BuildScopeDetails(scope ?? "openid");

        return Page();
    }

    public async Task<IActionResult> OnPostAllowAsync(string returnParams)
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (string.IsNullOrEmpty(userId)) return Redirect("/Account/Login");

        var qs   = Uri.UnescapeDataString(returnParams);
        var dict = QueryHelpers.ParseQuery(qs);

        var clientId            = dict["client_id"].ToString();
        var redirectUri         = dict["redirect_uri"].ToString();
        var scope               = dict["scope"].ToString();
        var state               = dict["state"].ToString();
        var codeChallenge       = dict["code_challenge"].ToString();
        var codeChallengeMethod = dict["code_challenge_method"].ToString();

        var client = await _oauth.ValidateClientAsync(clientId);
        if (client == null) return BadRequest("Invalid client.");

        var code = await _oauth.CreateAuthorizationCodeAsync(
            client.Id, client.OrganizationId, userId, redirectUri, scope,
            string.IsNullOrEmpty(codeChallenge) ? null : codeChallenge,
            string.IsNullOrEmpty(codeChallengeMethod) ? null : codeChallengeMethod);

        await _audit.LogAsync(new AuditLogRequest
        {
            OrganizationId = client.OrganizationId,
            UserId         = userId,
            EventType      = "ConsentGranted",
            EventCategory  = "oauth",
            ResourceType   = "OAuthClient",
            ResourceId     = client.Id.ToString(),
            ResourceName   = client.Name,
            HttpContext    = HttpContext,
        });

        var callback = $"{redirectUri}?code={Uri.EscapeDataString(code.Code)}";
        if (!string.IsNullOrEmpty(state)) callback += $"&state={Uri.EscapeDataString(state)}";
        return Redirect(callback);
    }

    public IActionResult OnPostSwitchAccount(string returnParams)
    {
        var qs      = Uri.UnescapeDataString(returnParams);
        var dict    = QueryHelpers.ParseQuery(qs);
        var authUrl = "/authorize?" + QueryHelpers.AddQueryString("", dict
            .ToDictionary(kv => kv.Key, kv => (string?)kv.Value.ToString())).TrimStart('?');
        return Redirect($"/Account/Login?ReturnUrl={Uri.EscapeDataString(authUrl)}&mode=new");
    }

    private static List<ScopeDetail> BuildScopeDetails(string scopeStr) =>
        scopeStr.Split(' ', StringSplitOptions.RemoveEmptyEntries)
            .Select(s => s.ToLowerInvariant() switch
            {
                "openid"         => new ScopeDetail { Icon = "🪪", BgColor = "#eef2ff",   Name = "Know who you are",         Description = "Access your unique account identifier" },
                "profile"        => new ScopeDetail { Icon = "👤", BgColor = "#f0fdf4",   Name = "View your profile",        Description = "Your name and account details" },
                "email"          => new ScopeDetail { Icon = "📧", BgColor = "#fef3c7",   Name = "Know your email",          Description = "Your email address and verification status" },
                "api"            => new ScopeDetail { Icon = "⚡", BgColor = "#fdf4ff",   Name = "Access the API",           Description = "Perform actions on your behalf via the API" },
                "offline_access" => new ScopeDetail { Icon = "🔄", BgColor = "#f0f9ff",   Name = "Stay signed in",           Description = "Access your data even when you're not using the app" },
                _                => new ScopeDetail { Icon = "📋", BgColor = "#f3f4f6",   Name = s,                          Description = "Custom application scope" },
            }).ToList();

    private static string GetInitials(ApplicationUser u)
    {
        var f = u.FirstName?.Trim() ?? ""; var l = u.LastName?.Trim() ?? "";
        if (f.Length > 0 && l.Length > 0) return $"{f[0]}{l[0]}".ToUpper();
        return (f.Length > 0 ? f : u.Email ?? "?")[0..1].ToUpper();
    }

    private static readonly string[] _colors =
        { "#6366f1","#8b5cf6","#ec4899","#14b8a6","#f59e0b","#10b981","#3b82f6","#ef4444" };

    private static string GetColor(string email) =>
        _colors[Math.Abs(email.GetHashCode()) % _colors.Length];
}
