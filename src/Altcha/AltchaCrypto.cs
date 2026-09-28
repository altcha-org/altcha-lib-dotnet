using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Altcha;

internal static class AltchaCrypto
{
    public static byte[] Hash(AltchaHashAlgorithm algorithm, byte[] data) => algorithm switch
    {
        AltchaHashAlgorithm.Sha1 => SHA1.HashData(data),
        AltchaHashAlgorithm.Sha256 => SHA256.HashData(data),
        AltchaHashAlgorithm.Sha384 => SHA384.HashData(data),
        AltchaHashAlgorithm.Sha512 => SHA512.HashData(data),
        _ => throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm, null),
    };

    public static byte[] Hmac(AltchaHashAlgorithm algorithm, byte[] data, string key)
    {
        var keyBytes = Encoding.UTF8.GetBytes(key);
        return algorithm switch
        {
            AltchaHashAlgorithm.Sha1 => HMACSHA1.HashData(keyBytes, data),
            AltchaHashAlgorithm.Sha256 => HMACSHA256.HashData(keyBytes, data),
            AltchaHashAlgorithm.Sha384 => HMACSHA384.HashData(keyBytes, data),
            AltchaHashAlgorithm.Sha512 => HMACSHA512.HashData(keyBytes, data),
            _ => throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm, null),
        };
    }

    public static string HmacHex(AltchaHashAlgorithm algorithm, byte[] data, string key) =>
        ToHex(Hmac(algorithm, data, key));

    public static string ToHex(ReadOnlySpan<byte> bytes) => Convert.ToHexString(bytes).ToLowerInvariant();

    public static bool TryFromHex(string? hex, out byte[] bytes)
    {
        if (hex is null)
        {
            bytes = [];
            return false;
        }

        try
        {
            bytes = Convert.FromHexString(hex);
            return true;
        }
        catch (FormatException)
        {
            bytes = [];
            return false;
        }
    }

    /// <summary>Compares two strings in constant time by comparing their SHA-256 digests.</summary>
    public static bool ConstantTimeEquals(string? a, string? b) =>
        CryptographicOperations.FixedTimeEquals(
            SHA256.HashData(Encoding.UTF8.GetBytes(a ?? string.Empty)),
            SHA256.HashData(Encoding.UTF8.GetBytes(b ?? string.Empty)));

    /// <summary>Returns the nonce followed by the counter as a big-endian uint32.</summary>
    public static byte[] PasswordWithCounter(byte[] nonce, int counter)
    {
        var password = new byte[nonce.Length + 4];
        nonce.CopyTo(password, 0);
        BinaryPrimitives.WriteUInt32BigEndian(password.AsSpan(nonce.Length), (uint)counter);
        return password;
    }
}
