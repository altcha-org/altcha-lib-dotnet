using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;

namespace Altcha;

/// <summary>Key-derivation functions for the v2 proof-of-work, compatible with the JS and Go libraries.</summary>
public static class KeyDerivation
{
    private const int DefaultKeyLength = 32;

    /// <summary>The canonical algorithm spellings accepted by the widget, used when issuing challenges.</summary>
    public static readonly IReadOnlyList<string> CanonicalAlgorithms = Array.AsReadOnly(new[]
    {
        "PBKDF2/SHA-256",
        "PBKDF2/SHA-384",
        "PBKDF2/SHA-512",
        "SHA-256",
        "SHA-384",
        "SHA-512",
        "SCRYPT",
        "ARGON2ID",
    });

    /// <summary>
    /// Iterated SHA hashing: the first round hashes <c>salt || password</c>, each further round re-hashes
    /// the previous digest. <c>Cost</c> is the number of rounds (minimum 1).
    /// </summary>
    public static byte[] Sha(ChallengeParameters parameters, byte[] salt, byte[] password)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        Func<byte[], byte[]> hash = (parameters.Algorithm ?? string.Empty).ToUpperInvariant() switch
        {
            "" or "SHA-256" => SHA256.HashData,
            "SHA-384" => SHA384.HashData,
            "SHA-512" => SHA512.HashData,
            _ => throw new AltchaException($"Unsupported SHA algorithm: {parameters.Algorithm}"),
        };

        var iterations = Math.Max(1, parameters.Cost);
        var data = new byte[salt.Length + password.Length];
        salt.CopyTo(data, 0);
        password.CopyTo(data, salt.Length);
        for (var i = 0; i < iterations; i++)
        {
            data = hash(data);
        }

        var keyLength = Math.Min(KeyLength(parameters), data.Length);
        return keyLength == data.Length ? data : data[..keyLength];
    }

    /// <summary>PBKDF2 with the hash selected by the algorithm (<c>PBKDF2/SHA-256|384|512</c>); <c>Cost</c> is the iteration count.</summary>
    public static byte[] Pbkdf2(ChallengeParameters parameters, byte[] salt, byte[] password)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        var hashName = (parameters.Algorithm ?? string.Empty).ToUpperInvariant() switch
        {
            "" or "PBKDF2/SHA-256" => HashAlgorithmName.SHA256,
            "PBKDF2/SHA-384" => HashAlgorithmName.SHA384,
            "PBKDF2/SHA-512" => HashAlgorithmName.SHA512,
            _ => throw new AltchaException($"Unsupported PBKDF2 algorithm: {parameters.Algorithm}"),
        };

        if (parameters.Cost < 1)
        {
            throw new AltchaException("PBKDF2 cost must be >= 1.");
        }

        return Rfc2898DeriveBytes.Pbkdf2(password, salt, parameters.Cost, hashName, KeyLength(parameters));
    }

    /// <summary>scrypt: <c>Cost</c> is N (default 16384), <c>MemoryCost</c> is r (default 8), <c>Parallelism</c> is p (default 1).</summary>
    public static byte[] Scrypt(ChallengeParameters parameters, byte[] salt, byte[] password)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        var n = parameters.Cost > 0 ? parameters.Cost : 16384;
        var r = parameters.MemoryCost is > 0 ? parameters.MemoryCost.Value : 8;
        var p = parameters.Parallelism is > 0 ? parameters.Parallelism.Value : 1;
        return SCrypt.Generate(password, salt, n, r, p, KeyLength(parameters));
    }

    /// <summary>
    /// Argon2id (v1.3): <c>Cost</c> is the time cost (default 1), <c>MemoryCost</c> is memory in KiB (default 65536),
    /// <c>Parallelism</c> is the lane count (default 1).
    /// </summary>
    public static byte[] Argon2id(ChallengeParameters parameters, byte[] salt, byte[] password)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        var t = parameters.Cost > 0 ? parameters.Cost : 1;
        var m = parameters.MemoryCost is > 0 ? parameters.MemoryCost.Value : 65536;
        var p = parameters.Parallelism is > 0 ? parameters.Parallelism.Value : 1;
        var argon2Parameters = new Argon2Parameters.Builder(Argon2Parameters.Argon2id)
            .WithVersion(Argon2Parameters.Version13)
            .WithIterations(t)
            .WithMemoryAsKB(m)
            .WithParallelism(p)
            .WithSalt(salt)
            .Build();
        var generator = new Argon2BytesGenerator();
        generator.Init(argon2Parameters);
        var output = new byte[KeyLength(parameters)];
        generator.GenerateBytes(password, output);
        return output;
    }

    /// <summary>Returns the derivation function for an algorithm name (case-insensitive).</summary>
    /// <exception cref="AltchaException">The algorithm is not supported.</exception>
    public static DeriveKeyFunc Resolve(string algorithm) =>
        TryResolve(algorithm, out var deriveKey)
            ? deriveKey
            : throw new AltchaException($"Unsupported algorithm: {algorithm}");

    /// <summary>Returns the derivation function for an algorithm name (case-insensitive) without throwing.</summary>
    public static bool TryResolve(string? algorithm, [System.Diagnostics.CodeAnalysis.NotNullWhen(true)] out DeriveKeyFunc? deriveKey)
    {
        deriveKey = algorithm?.ToUpperInvariant() switch
        {
            "PBKDF2/SHA-256" or "PBKDF2/SHA-384" or "PBKDF2/SHA-512" => Pbkdf2,
            "SHA-256" or "SHA-384" or "SHA-512" => Sha,
            "SCRYPT" => Scrypt,
            "ARGON2ID" => Argon2id,
            _ => null,
        };
        return deriveKey is not null;
    }

    private static int KeyLength(ChallengeParameters parameters) =>
        parameters.KeyLength > 0 ? parameters.KeyLength : DefaultKeyLength;
}
