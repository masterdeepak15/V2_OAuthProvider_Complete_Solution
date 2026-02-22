using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Server;

namespace OAuthClient.Services;

/// <summary>
/// Passes the authentication state from the HTTP context into the Blazor
/// interactive circuit. Required when using cookie auth + Blazor Server.
/// </summary>
internal sealed class ServerSideAuthenticationStateProvider
    : RevalidatingServerAuthenticationStateProvider
{
    private readonly IServiceScopeFactory _scopeFactory;

    public ServerSideAuthenticationStateProvider(
        ILoggerFactory loggerFactory,
        IServiceScopeFactory scopeFactory)
        : base(loggerFactory)
    {
        _scopeFactory = scopeFactory;
    }

    // Re-validate the session every 30 minutes
    protected override TimeSpan RevalidationInterval => TimeSpan.FromMinutes(30);

    protected override Task<bool> ValidateAuthenticationStateAsync(
        AuthenticationState authState,
        CancellationToken cancellationToken)
    {
        // For cookie auth the framework handles expiry automatically.
        // Return true to keep the session alive between revalidation ticks.
        return Task.FromResult(authState.User.Identity?.IsAuthenticated ?? false);
    }
}
