namespace OAuthClient.Models;

public class OAuthSettings
{
    public string BaseUrl { get; set; } = string.Empty;
    public string ClientId { get; set; } = string.Empty;
    public string ClientSecret { get; set; } = string.Empty;
    public string RedirectUri { get; set; } = string.Empty;
    public string Scopes { get; set; } = "openid profile email";

    public string AuthorizeEndpoint => $"{BaseUrl}/authorize";
    public string TokenEndpoint => $"{BaseUrl}/token";
    public string UserInfoEndpoint => $"{BaseUrl}/userinfo";
    public string RevokeEndpoint => $"{BaseUrl}/revoke";
}

public class UserProfile
{
    public string? Sub { get; set; }
    public string? Email { get; set; }
    public bool EmailVerified { get; set; }
    public string? GivenName { get; set; }
    public string? FamilyName { get; set; }
    public string? Name { get; set; }
}

public class TokenResponse
{
    public string? AccessToken { get; set; }
    public string? RefreshToken { get; set; }
    public int ExpiresIn { get; set; }
    public string? TokenType { get; set; }
    public string? Scope { get; set; }
    public string? Error { get; set; }
    public string? ErrorDescription { get; set; }
}
