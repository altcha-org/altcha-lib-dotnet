namespace Altcha;

/// <summary>Hash algorithms used for HMAC signatures and server-signature hashing.</summary>
public enum AltchaHashAlgorithm
{
    /// <summary>SHA-1.</summary>
    Sha1,

    /// <summary>SHA-256.</summary>
    Sha256,

    /// <summary>SHA-384.</summary>
    Sha384,

    /// <summary>SHA-512.</summary>
    Sha512,
}

internal static class AltchaHashAlgorithmExtensions
{
    public static string ToWireName(this AltchaHashAlgorithm algorithm) => algorithm switch
    {
        AltchaHashAlgorithm.Sha1 => "SHA-1",
        AltchaHashAlgorithm.Sha256 => "SHA-256",
        AltchaHashAlgorithm.Sha384 => "SHA-384",
        AltchaHashAlgorithm.Sha512 => "SHA-512",
        _ => throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm, null),
    };

    public static bool TryParse(string? name, out AltchaHashAlgorithm algorithm)
    {
        switch (name?.ToUpperInvariant())
        {
            case "SHA-1":
                algorithm = AltchaHashAlgorithm.Sha1;
                return true;
            case "SHA-256":
                algorithm = AltchaHashAlgorithm.Sha256;
                return true;
            case "SHA-384":
                algorithm = AltchaHashAlgorithm.Sha384;
                return true;
            case "SHA-512":
                algorithm = AltchaHashAlgorithm.Sha512;
                return true;
            default:
                algorithm = default;
                return false;
        }
    }
}
