using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using OAuthProvider.Components;
using OAuthProvider.Data;
using OAuthProvider.Models;
using OAuthProvider.Services;

var builder = WebApplication.CreateBuilder(args);

// ── Database ──────────────────────────────────────────────────────────────────
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlite(
        builder.Configuration.GetConnectionString("DefaultConnection"),
        b => b.MigrationsAssembly(typeof(ApplicationDbContext).Assembly.FullName)
    )
    // Switch to SQL Server: replace above with:
    // options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection"))
);

// ── Identity ──────────────────────────────────────────────────────────────────
builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    options.Password.RequireDigit = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireUppercase = true;
    options.Password.RequireNonAlphanumeric = true;
    options.Password.RequiredLength = 8;
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
    options.Lockout.MaxFailedAccessAttempts = 5;
    options.SignIn.RequireConfirmedAccount = false;
})
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders();

// Login/logout are static Razor Pages — cookie settings point there
builder.Services.ConfigureApplicationCookie(options =>
{
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Lax;
    options.Cookie.Name = ".OAuthProvider.Auth";
    options.LoginPath = "/Account/Login";
    options.LogoutPath = "/Account/Logout";
    options.ExpireTimeSpan = TimeSpan.FromDays(7);
    options.SlidingExpiration = true;
});

// ── Auth & Blazor Auth State ──────────────────────────────────────────────────
builder.Services.AddAuthorization();
builder.Services.AddCascadingAuthenticationState();
builder.Services.AddScoped<AuthenticationStateProvider,
    IdentityRevalidatingAuthenticationStateProvider>();

// ── Data Protection ───────────────────────────────────────────────────────────
builder.Services.AddDataProtection();

// ── Application Services ──────────────────────────────────────────────────────
builder.Services.AddScoped<IJwtService, JwtService>();
builder.Services.AddScoped<IOAuthService, OAuthService>();
builder.Services.AddScoped<IDashboardService, DashboardService>();

// ── HTTP Context ──────────────────────────────────────────────────────────────
builder.Services.AddHttpContextAccessor();

// ── Razor Pages (Login / Logout — must be static SSR so cookies are written) ─
builder.Services.AddRazorPages();

// ── Blazor Server ─────────────────────────────────────────────────────────────
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

// ── MVC Controllers (OAuth endpoints: /authorize, /token, /userinfo, /revoke) ─
builder.Services.AddControllers();

// ── HTTPS / HSTS ──────────────────────────────────────────────────────────────
builder.Services.AddHsts(options =>
{
    options.Preload = true;
    options.IncludeSubDomains = true;
    options.MaxAge = TimeSpan.FromDays(365);
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
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();

// Antiforgery for Blazor interactive components
app.UseAntiforgery();

// Static Razor Pages: /Account/Login  /Account/Logout
app.MapRazorPages();

// OAuth REST endpoints
app.MapControllers();

// Interactive Blazor Server app (dashboard, etc.)
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

// ── Seed ──────────────────────────────────────────────────────────────────────
await DbSeeder.SeedAsync(app.Services);

app.Run();
