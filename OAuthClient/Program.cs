using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.Extensions.Caching.Memory;
using OAuthClient.Components;
using OAuthClient.Models;
using OAuthClient.Services;

var builder = WebApplication.CreateBuilder(args);

// ── OAuth Provider Settings ───────────────────────────────────────────────────
var oauthSettings = builder.Configuration
    .GetSection("OAuthProvider")
    .Get<OAuthSettings>()
    ?? throw new InvalidOperationException("OAuthProvider settings missing in appsettings.json");

builder.Services.AddSingleton(oauthSettings);

// ── HTTP Client for calling the OAuth Provider ────────────────────────────────
builder.Services.AddHttpClient("provider", client =>
{
    client.BaseAddress = new Uri(oauthSettings.BaseUrl);
    client.Timeout = TimeSpan.FromSeconds(15);
})
.ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler
{
    // DEV ONLY: trust self-signed cert on localhost:5000
    // Remove this in production and use a real certificate
    ServerCertificateCustomValidationCallback =
        HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
});

// ── Cookie Authentication (app-side session) ──────────────────────────────────
// The app issues its OWN cookie after the OAuth callback.
// This is separate from the OAuth Provider's cookies.
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.Cookie.Name      = ".DemoApp.Auth";
        options.Cookie.HttpOnly  = true;
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        options.Cookie.SameSite  = SameSiteMode.Lax;
        options.LoginPath        = "/Account/Login";
        options.LogoutPath       = "/Account/Logout";
        options.ExpireTimeSpan   = TimeSpan.FromDays(7);
        options.SlidingExpiration = true;
    });

builder.Services.AddAuthorization();

// ── Blazor Auth Integration ───────────────────────────────────────────────────
builder.Services.AddCascadingAuthenticationState();
builder.Services.AddScoped<AuthenticationStateProvider,
    ServerSideAuthenticationStateProvider>();

// ── Application Services ──────────────────────────────────────────────────────
builder.Services.AddScoped<IOAuthFlowService, OAuthFlowService>();
builder.Services.AddSingleton<ITokenStore, InMemoryTokenStore>(); // server-side token cache
builder.Services.AddSingleton<IPkceService, PkceService>();

// ── In-Memory Cache (stores PKCE verifiers & state during the OAuth round-trip)
builder.Services.AddMemoryCache();

// ── Razor Pages (Login, Callback, Logout — must be static SSR) ───────────────
builder.Services.AddRazorPages();

// ── Blazor Server (Dashboard, Profile, Home) ──────────────────────────────────
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

// ── HTTPS ─────────────────────────────────────────────────────────────────────
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
app.UseAntiforgery();

// Static SSR: Login, Callback, Logout
app.MapRazorPages();

// Interactive Blazor Server: Home, Profile, Dashboard
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.Run();
