using System.Security.Claims;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Server;
using Microsoft.AspNetCore.Identity;
using OAuthProviderV2.Models;

namespace OAuthProviderV2.Services;

internal sealed class IdentityRevalidatingAuthenticationStateProvider
    : RevalidatingServerAuthenticationStateProvider
{
    private readonly IServiceScopeFactory _scopeFactory;

    public IdentityRevalidatingAuthenticationStateProvider(
        ILoggerFactory loggerFactory,
        IServiceScopeFactory scopeFactory)
        : base(loggerFactory)
    {
        _scopeFactory = scopeFactory;
    }

    protected override TimeSpan RevalidationInterval => TimeSpan.FromMinutes(30);

    protected override async Task<bool> ValidateAuthenticationStateAsync(
        AuthenticationState authState, CancellationToken ct)
    {
        await using var scope = _scopeFactory.CreateAsyncScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        return await ValidateSecurityStampAsync(userManager, authState.User);
    }

    private static async Task<bool> ValidateSecurityStampAsync(
        UserManager<ApplicationUser> mgr, System.Security.Claims.ClaimsPrincipal principal)
    {
        var user = await mgr.GetUserAsync(principal);
        if (user == null) return false;
        if (!mgr.SupportsUserSecurityStamp) return true;
        var stamp = principal.FindFirstValue(mgr.Options.ClaimsIdentity.SecurityStampClaimType);
        return stamp == await mgr.GetSecurityStampAsync(user);
    }
}
