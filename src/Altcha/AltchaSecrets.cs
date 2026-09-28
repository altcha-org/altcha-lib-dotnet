using System.Text;

namespace Altcha;

/// <summary>Helpers for deriving ALTCHA secrets.</summary>
public static class AltchaSecrets
{
    /// <summary>
    /// Derives a key-signature secret from a master secret:
    /// hex(HMAC-SHA256(key = "derived-secret", data = masterSecret)). Matches the JS <c>deriveHmacKeySecret</c>.
    /// </summary>
    public static string DeriveHmacKeySecret(string masterSecret)
    {
        ArgumentNullException.ThrowIfNull(masterSecret);
        return AltchaCrypto.HmacHex(AltchaHashAlgorithm.Sha256, Encoding.UTF8.GetBytes(masterSecret), "derived-secret");
    }
}
