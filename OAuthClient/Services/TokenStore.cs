namespace OAuthClient.Services;

/// <summary>
/// Stores OAuth tokens in the server-side memory cache, keyed by a session ID
/// stored in the auth cookie. Tokens are never sent to the browser.
/// </summary>
public interface ITokenStore
{
    void Save(string sessionId, string accessToken, string? refreshToken, DateTime expiresAt);
    TokenEntry? Get(string sessionId);
    void Delete(string sessionId);
}

public record TokenEntry(
    string AccessToken,
    string? RefreshToken,
    DateTime ExpiresAt
)
{
    public bool IsExpired => DateTime.UtcNow >= ExpiresAt.AddSeconds(-30);
}

public class InMemoryTokenStore : ITokenStore
{
    // In production swap this for IDistributedCache / Redis
    private readonly Dictionary<string, TokenEntry> _store = new();
    private readonly object _lock = new();

    public void Save(string sessionId, string accessToken, string? refreshToken, DateTime expiresAt)
    {
        lock (_lock)
            _store[sessionId] = new TokenEntry(accessToken, refreshToken, expiresAt);
    }

    public TokenEntry? Get(string sessionId)
    {
        lock (_lock)
            return _store.TryGetValue(sessionId, out var e) ? e : null;
    }

    public void Delete(string sessionId)
    {
        lock (_lock)
            _store.Remove(sessionId);
    }
}
