using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using OAuthProviderV2.Components;
using OAuthProviderV2.Data;
using OAuthProviderV2.Middleware;
using OAuthProviderV2.Models;
using OAuthProviderV2.Services;
using OAuthProviderV2.Services.Audit;
using OAuthProviderV2.Services.Email;
using OAuthProviderV2.Services.Otp;

var builder = WebApplication.CreateBuilder(args);

// ── Database ──────────────────────────────────────────────────────────────────
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlite(
        builder.Configuration.GetConnectionString("DefaultConnection"),
        b => b.MigrationsAssembly(typeof(ApplicationDbContext).Assembly.FullName)
    )
);

// ── Identity ──────────────────────────────────────────────────────────────────
builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    options.Password.RequireDigit           = true;
    options.Password.RequireLowercase       = true;
    options.Password.RequireUppercase       = true;
    options.Password.RequireNonAlphanumeric = true;
    options.Password.RequiredLength         = 8;
    options.Lockout.DefaultLockoutTimeSpan  = TimeSpan.FromMinutes(15);
    options.Lockout.MaxFailedAccessAttempts = 5;
    options.SignIn.RequireConfirmedAccount  = false;
})
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders();

// ── Cookie auth (login/logout via static Razor Pages) ─────────────────────────
builder.Services.ConfigureApplicationCookie(options =>
{
    options.Cookie.HttpOnly     = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite     = SameSiteMode.Lax;
    options.Cookie.Name         = ".OAuthProvider.Auth";
    options.LoginPath           = "/Account/Login";
    options.LogoutPath          = "/Account/Logout";
    options.ExpireTimeSpan      = TimeSpan.FromDays(7);
    options.SlidingExpiration   = true;
});

// ── Authorization ─────────────────────────────────────────────────────────────
builder.Services.AddAuthorization();
builder.Services.AddCascadingAuthenticationState();
builder.Services.AddScoped<AuthenticationStateProvider,
    IdentityRevalidatingAuthenticationStateProvider>();

// ── Data Protection ───────────────────────────────────────────────────────────
builder.Services.AddDataProtection();

// ── Application Services ──────────────────────────────────────────────────────
builder.Services.AddScoped<IJwtService, JwtService>();
builder.Services.AddScoped<IOAuthService, OAuthService>();
builder.Services.AddScoped<IOrganizationService, OrganizationService>();
builder.Services.AddScoped<IAuditService, AuditService>();
builder.Services.AddScoped<IEmailService, EmailService>();
builder.Services.AddScoped<IOtpService, OtpService>();
builder.Services.AddScoped<IAccountSessionService, AccountSessionService>();

// ── Memory cache (PKCE state, OTP temp storage) ───────────────────────────────
builder.Services.AddMemoryCache();

// ── HTTP Context ──────────────────────────────────────────────────────────────
builder.Services.AddHttpContextAccessor();

// ── CORS — per-client dynamic policy ─────────────────────────────────────────
// Individual client CORS is enforced in OAuthController using ValidateCorsOriginAsync
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
        policy.AllowAnyOrigin().AllowAnyHeader().AllowAnyMethod());
});

// ── Razor Pages (static SSR auth pages) ──────────────────────────────────────
builder.Services.AddRazorPages();

// ── Blazor Server (interactive admin dashboard) ───────────────────────────────
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

// ── MVC Controllers (OAuth 2.0 endpoints) ────────────────────────────────────
builder.Services.AddControllers();

// ── HTTPS / HSTS ──────────────────────────────────────────────────────────────
builder.Services.AddHsts(options =>
{
    options.Preload          = true;
    options.IncludeSubDomains = true;
    options.MaxAge           = TimeSpan.FromDays(365);
});

// ─────────────────────────────────────────────────────────────────────────────
var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

// ── WAF Middleware (must be early in the pipeline) ────────────────────────────
app.UseMiddleware<WafMiddleware>();

app.UseRouting();
app.UseCors();
app.UseAuthentication();
app.UseAuthorization();
app.UseAntiforgery();

// Static SSR pages
app.MapRazorPages();

// OAuth REST endpoints
app.MapControllers();

// Interactive Blazor
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

// ── Seed ──────────────────────────────────────────────────────────────────────
await DbSeeder.SeedAsync(app.Services);

app.Run();
