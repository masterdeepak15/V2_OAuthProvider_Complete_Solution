using System.Security.Cryptography;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using OAuthProviderV2.Services;
using OAuthProviderV2.Services.Audit;
using OAuthProviderV2.Services.Otp;

namespace OAuthProviderV2.Pages.Account;

public class SignupModel : PageModel
{
    private readonly IOrganizationService _orgService;
    private readonly IOtpService _otp;
    private readonly IAuditService _audit;
    private readonly ILogger<SignupModel> _logger;

    // Temporary password store (session-based, never in hidden field)
    private static readonly Dictionary<string, (string password, DateTime expiry)> _pendingPasswords = new();

    public SignupModel(IOrganizationService orgService, IOtpService otp, IAuditService audit, ILogger<SignupModel> logger)
    {
        _orgService = orgService;
        _otp = otp;
        _audit = audit;
        _logger = logger;
    }

    public string Step { get; set; } = "details";
    public string? ErrorMessage { get; set; }
    public string? SuccessMessage { get; set; }

    // Form fields
    public string OrgName { get; set; } = string.Empty;
    public string? Website { get; set; }
    public string FirstName { get; set; } = string.Empty;
    public string LastName { get; set; } = string.Empty;
    public string AdminEmail { get; set; } = string.Empty;
    public string? PasswordToken { get; set; }  // reference to server-side password cache

    public void OnGet()
    {
        Step = "details";
    }

    public async Task<IActionResult> OnPostAsync(
        string step, string? orgName, string? website,
        string? firstName, string? lastName, string? adminEmail,
        string? password, string? confirmPassword,
        string? otp, string? passwordToken)
    {
        Step         = step ?? "details";
        OrgName      = orgName ?? string.Empty;
        Website      = website;
        FirstName    = firstName ?? string.Empty;
        LastName     = lastName ?? string.Empty;
        AdminEmail   = adminEmail ?? string.Empty;
        PasswordToken = passwordToken;

        switch (step)
        {
            case "details":
                return await HandleDetailsAsync(orgName, website, firstName, lastName, adminEmail, password, confirmPassword);

            case "otp":
                return await HandleOtpAsync(otp, passwordToken);

            case "resend":
                if (!string.IsNullOrEmpty(adminEmail))
                {
                    await _otp.GenerateAndSendAsync(adminEmail, "signup");
                    SuccessMessage = "A new code has been sent.";
                }
                Step = "otp";
                return Page();

            default:
                Step = "details";
                return Page();
        }
    }

    private async Task<IActionResult> HandleDetailsAsync(string? orgName, string? website,
        string? firstName, string? lastName, string? adminEmail, string? password, string? confirmPassword)
    {
        // Validate
        if (string.IsNullOrWhiteSpace(orgName) || string.IsNullOrWhiteSpace(adminEmail)
            || string.IsNullOrWhiteSpace(firstName) || string.IsNullOrWhiteSpace(lastName))
        {
            ErrorMessage = "All required fields must be filled.";
            Step = "details";
            return Page();
        }

        if (string.IsNullOrWhiteSpace(password) || password.Length < 8)
        {
            ErrorMessage = "Password must be at least 8 characters.";
            Step = "details";
            return Page();
        }

        if (password != confirmPassword)
        {
            ErrorMessage = "Passwords do not match.";
            Step = "details";
            return Page();
        }

        // Store password temporarily server-side (NOT in hidden field)
        var token = GeneratePasswordToken();
        lock (_pendingPasswords)
        {
            _pendingPasswords[token] = (password, DateTime.UtcNow.AddMinutes(15));
            // Cleanup old entries
            var expired = _pendingPasswords.Where(kv => kv.Value.expiry < DateTime.UtcNow).Select(kv => kv.Key).ToList();
            foreach (var k in expired) _pendingPasswords.Remove(k);
        }

        // Send OTP
        try
        {
            await _otp.GenerateAndSendAsync(adminEmail!, "signup");
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "OTP send failed for {Email}", adminEmail);
            // In dev, continue anyway
        }

        PasswordToken = token;
        Step = "otp";
        SuccessMessage = "A verification code has been sent to your email.";
        return Page();
    }

    private async Task<IActionResult> HandleOtpAsync(string? otp, string? passwordToken)
    {
        if (string.IsNullOrWhiteSpace(otp) || otp.Length != 6)
        {
            ErrorMessage = "Please enter the 6-digit code.";
            Step = "otp";
            return Page();
        }

        // Verify OTP
        var result = await _otp.VerifyAsync(AdminEmail, otp, "signup");
        if (result != OtpVerifyResult.Valid)
        {
            ErrorMessage = result switch
            {
                OtpVerifyResult.Expired         => "The code has expired. Request a new one.",
                OtpVerifyResult.TooManyAttempts => "Too many failed attempts. Request a new code.",
                OtpVerifyResult.NotFound        => "No active code found. Request a new one.",
                _                               => "Invalid code. Please try again.",
            };
            Step = "otp";
            return Page();
        }

        // Retrieve password from server-side cache
        string? password = null;
        if (!string.IsNullOrEmpty(passwordToken))
        {
            lock (_pendingPasswords)
            {
                if (_pendingPasswords.TryGetValue(passwordToken, out var entry) && entry.expiry > DateTime.UtcNow)
                {
                    password = entry.password;
                    _pendingPasswords.Remove(passwordToken);
                }
            }
        }

        if (string.IsNullOrEmpty(password))
        {
            ErrorMessage = "Session expired. Please start over.";
            Step = "details";
            return Page();
        }

        // Create organization
        try
        {
            var org = await _orgService.CreateAsync(OrgName, AdminEmail, FirstName, LastName, password);

            await _audit.LogAsync(new AuditLogRequest
            {
                OrganizationId = org.Id,
                UserEmail      = AdminEmail,
                EventType      = "OrgCreated",
                EventCategory  = "admin",
                ResourceType   = "Organization",
                ResourceId     = org.Id.ToString(),
                ResourceName   = OrgName,
                HttpContext    = HttpContext,
            });

            return Redirect("/Account/Login?registered=true");
        }
        catch (Exception ex)
        {
            ErrorMessage = $"Failed to create organization: {ex.Message}";
            Step = "otp";
            return Page();
        }
    }

    private static string GeneratePasswordToken()
    {
        var bytes = new byte[32];
        RandomNumberGenerator.Fill(bytes);
        return Convert.ToBase64String(bytes).Replace("+", "-").Replace("/", "_").TrimEnd('=');
    }
}
