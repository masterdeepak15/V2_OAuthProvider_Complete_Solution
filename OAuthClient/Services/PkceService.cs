using System.Security.Cryptography;
using System.Text;

namespace OAuthClient.Services;

/// <summary>
/// Generates and verifies PKCE (Proof Key for Code Exchange) challenge pairs.
/// Stored server-side in session/cache keyed by state, so no JS is needed.
/// </summary>
public interface IPkceService
{
    PkcePair Generate();
    string BuildChallenge(string verifier);
}

public class PkcePair
{
    public string Verifier { get; init; } = string.Empty;
    public string Challenge { get; init; } = string.Empty;
    public string Method => "S256";
}

public class PkceService : IPkceService
{
    public PkcePair Generate()
    {
        // verifier = 43-128 URL-safe random chars
        var bytes = new byte[64];
        RandomNumberGenerator.Fill(bytes);
        var verifier = Base64UrlEncode(bytes);
        var challenge = BuildChallenge(verifier);
        return new PkcePair { Verifier = verifier, Challenge = challenge };
    }

    public string BuildChallenge(string verifier)
    {
        var hash = SHA256.HashData(Encoding.ASCII.GetBytes(verifier));
        return Base64UrlEncode(hash);
    }

    private static string Base64UrlEncode(byte[] input) =>
        Convert.ToBase64String(input)
               .Replace("+", "-")
               .Replace("/", "_")
               .TrimEnd('=');
}
