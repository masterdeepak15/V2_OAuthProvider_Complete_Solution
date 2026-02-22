using System.Net.Http.Headers;
using System.Text.Json;
using OAuthClient.Models;

namespace OAuthClient.Services;

public interface IOAuthFlowService
{
    string BuildAuthorizeUrl(string state, string codeChallenge, string codeChallengeMethod);
    Task<TokenResponse> ExchangeCodeAsync(string code, string codeVerifier, string redirectUri);
    Task<TokenResponse> RefreshTokenAsync(string refreshToken);
    Task<UserProfile?> GetUserInfoAsync(string accessToken);
    Task RevokeTokenAsync(string token);
}

public class OAuthFlowService : IOAuthFlowService
{
    private readonly HttpClient _http;
    private readonly OAuthSettings _settings;

    private static readonly JsonSerializerOptions _json = new()
    {
        PropertyNameCaseInsensitive = true,
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower
    };

    public OAuthFlowService(IHttpClientFactory factory, OAuthSettings settings)
    {
        // Named client "provider" — configured in Program.cs to skip TLS validation in dev
        _http = factory.CreateClient("provider");
        _settings = settings;
    }

    public string BuildAuthorizeUrl(string state, string codeChallenge, string codeChallengeMethod)
    {
        var q = new Dictionary<string, string>
        {
            ["response_type"]          = "code",
            ["client_id"]              = _settings.ClientId,
            ["redirect_uri"]           = _settings.RedirectUri,
            ["scope"]                  = _settings.Scopes,
            ["state"]                  = state,
            ["code_challenge"]         = codeChallenge,
            ["code_challenge_method"]  = codeChallengeMethod,
        };

        var qs = string.Join("&", q.Select(kv =>
            $"{Uri.EscapeDataString(kv.Key)}={Uri.EscapeDataString(kv.Value)}"));

        return $"{_settings.AuthorizeEndpoint}?{qs}";
    }

    public async Task<TokenResponse> ExchangeCodeAsync(string code, string codeVerifier, string redirectUri)
    {
        var form = new Dictionary<string, string>
        {
            ["grant_type"]    = "authorization_code",
            ["code"]          = code,
            ["redirect_uri"]  = redirectUri,
            ["client_id"]     = _settings.ClientId,
            ["client_secret"] = _settings.ClientSecret,
            ["code_verifier"] = codeVerifier,
        };

        return await PostFormAsync<TokenResponse>(_settings.TokenEndpoint, form);
    }

    public async Task<TokenResponse> RefreshTokenAsync(string refreshToken)
    {
        var form = new Dictionary<string, string>
        {
            ["grant_type"]    = "refresh_token",
            ["refresh_token"] = refreshToken,
            ["client_id"]     = _settings.ClientId,
            ["client_secret"] = _settings.ClientSecret,
        };

        return await PostFormAsync<TokenResponse>(_settings.TokenEndpoint, form);
    }

    public async Task<UserProfile?> GetUserInfoAsync(string accessToken)
    {
        var req = new HttpRequestMessage(HttpMethod.Get, _settings.UserInfoEndpoint);
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

        var resp = await _http.SendAsync(req);
        if (!resp.IsSuccessStatusCode) return null;

        var json = await resp.Content.ReadAsStringAsync();
        return JsonSerializer.Deserialize<UserProfile>(json, _json);
    }

    public async Task RevokeTokenAsync(string token)
    {
        var form = new Dictionary<string, string> { ["token"] = token };
        var content = new FormUrlEncodedContent(form);
        await _http.PostAsync(_settings.RevokeEndpoint, content);
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    private async Task<T> PostFormAsync<T>(string url, Dictionary<string, string> fields)
        where T : new()
    {
        var content = new FormUrlEncodedContent(fields);
        var resp = await _http.PostAsync(url, content);
        var json = await resp.Content.ReadAsStringAsync();

        return JsonSerializer.Deserialize<T>(json, _json) ?? new T();
    }
}
