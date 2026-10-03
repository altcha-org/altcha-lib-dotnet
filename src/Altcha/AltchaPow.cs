using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Altcha;

/// <summary>Options for <see cref="AltchaPow.CreateChallenge"/>.</summary>
public sealed class CreateChallengeOptions
{
    /// <summary>KDF algorithm, e.g. <c>PBKDF2/SHA-256</c>. Required.</summary>
    public string Algorithm { get; set; } = string.Empty;

    /// <summary>KDF cost. Must be greater than zero.</summary>
    public int Cost { get; set; }

    /// <summary>
    /// Deterministic counter. When set, the server derives the key itself and uses its prefix as
    /// <c>keyPrefix</c>, so the solver must find exactly this counter (starting from 0).
    /// </summary>
    public int? Counter { get; set; }

    /// <summary>Arbitrary data to attach to (and sign with) the challenge.</summary>
    public IDictionary<string, object?>? Data { get; set; }

    /// <summary>Custom key derivation; defaults to <see cref="KeyDerivation.Resolve"/> of <see cref="Algorithm"/>.</summary>
    public DeriveKeyFunc? DeriveKey { get; set; }

    /// <summary>Challenge expiry.</summary>
    public DateTimeOffset? ExpiresAt { get; set; }

    /// <summary>HMAC algorithm for signatures.</summary>
    public AltchaHashAlgorithm HmacAlgorithm { get; set; } = AltchaHashAlgorithm.Sha256;

    /// <summary>Secret for the challenge signature. Without it the challenge is unsigned.</summary>
    public string? HmacSignatureSecret { get; set; }

    /// <summary>Secret for the key signature (deterministic challenges only), enabling fast verification.</summary>
    public string? HmacKeySignatureSecret { get; set; }

    /// <summary>Derived key length in bytes; 0 means 32.</summary>
    public int KeyLength { get; set; }

    /// <summary>Length in bytes of the key prefix for deterministic challenges; 0 means half the key length.</summary>
    public int KeyPrefixLength { get; set; }

    /// <summary>Memory cost; 0 means unset.</summary>
    public int MemoryCost { get; set; }

    /// <summary>Parallelism; 0 means unset.</summary>
    public int Parallelism { get; set; }

    /// <summary>Hex key prefix for random (non-deterministic) challenges; defaults to <c>00</c>.</summary>
    public string? KeyPrefix { get; set; }
}

/// <summary>Options for <see cref="AltchaPow.SolveChallenge"/>.</summary>
public sealed class SolveChallengeOptions
{
    /// <summary>The challenge to solve.</summary>
    public Challenge Challenge { get; set; } = new();

    /// <summary>First counter to try.</summary>
    public int CounterStart { get; set; }

    /// <summary>Counter increment; values below 1 are treated as 1.</summary>
    public int CounterStep { get; set; } = 1;

    /// <summary>Custom key derivation; defaults to <see cref="KeyDerivation.Resolve"/> of the challenge algorithm.</summary>
    public DeriveKeyFunc? DeriveKey { get; set; }
}

/// <summary>Options for <see cref="AltchaPow.VerifySolution"/>.</summary>
public sealed class VerifySolutionOptions
{
    /// <summary>The challenge as submitted by the client.</summary>
    public Challenge Challenge { get; set; } = new();

    /// <summary>The solution as submitted by the client.</summary>
    public Solution Solution { get; set; } = new();

    /// <summary>Custom key derivation; defaults to <see cref="KeyDerivation.Resolve"/> of the challenge algorithm.</summary>
    public DeriveKeyFunc? DeriveKey { get; set; }

    /// <summary>HMAC algorithm for signatures.</summary>
    public AltchaHashAlgorithm HmacAlgorithm { get; set; } = AltchaHashAlgorithm.Sha256;

    /// <summary>Secret for the challenge signature. Required: verification never skips the signature check.</summary>
    public string? HmacSignatureSecret { get; set; }

    /// <summary>Secret for the key signature, enabling verification without re-deriving the key.</summary>
    public string? HmacKeySignatureSecret { get; set; }
}

/// <summary>Creates, solves and verifies ALTCHA v2 proof-of-work challenges.</summary>
public static class AltchaPow
{
    private const int DefaultKeyLength = 32;
    private const string DefaultKeyPrefix = "00";

    /// <summary>Creates a new challenge.</summary>
    /// <exception cref="ArgumentException">The algorithm is missing.</exception>
    /// <exception cref="ArgumentOutOfRangeException">The cost or counter is out of range.</exception>
    /// <exception cref="AltchaException">The key prefix is invalid or the algorithm is unsupported.</exception>
    public static Challenge CreateChallenge(CreateChallengeOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (string.IsNullOrEmpty(options.Algorithm))
        {
            throw new ArgumentException("Algorithm is required.", nameof(options));
        }

        if (options.Cost <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(options), options.Cost, "Cost must be greater than zero.");
        }

        if (options.Counter < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(options), options.Counter, "Counter must not be negative.");
        }

        var keyLength = options.KeyLength > 0 ? options.KeyLength : DefaultKeyLength;
        var prefixLength = options.KeyPrefixLength > 0 ? options.KeyPrefixLength : keyLength / 2;

        var saltBytes = RandomNumberGenerator.GetBytes(12);
        var nonceBytes = RandomNumberGenerator.GetBytes(12);

        var keyPrefix = string.IsNullOrEmpty(options.KeyPrefix) ? DefaultKeyPrefix : options.KeyPrefix;
        KeyPrefix.Parse(keyPrefix);

        var parameters = new ChallengeParameters
        {
            Algorithm = options.Algorithm,
            Nonce = AltchaCrypto.ToHex(nonceBytes),
            Salt = AltchaCrypto.ToHex(saltBytes),
            Cost = options.Cost,
            KeyLength = keyLength,
            KeyPrefix = keyPrefix,
            MemoryCost = options.MemoryCost > 0 ? options.MemoryCost : null,
            Parallelism = options.Parallelism > 0 ? options.Parallelism : null,
            ExpiresAt = options.ExpiresAt?.ToUnixTimeSeconds(),
            Data = ToJsonData(options.Data),
        };

        byte[]? derivedKey = null;
        if (options.Counter is { } counter)
        {
            var deriveKey = options.DeriveKey ?? KeyDerivation.Resolve(options.Algorithm);
            derivedKey = deriveKey(parameters, saltBytes, AltchaCrypto.PasswordWithCounter(nonceBytes, counter));
            parameters.KeyPrefix = AltchaCrypto.ToHex(derivedKey.AsSpan(0, Math.Min(prefixLength, derivedKey.Length)));
        }

        if (derivedKey is { Length: > 0 } && !string.IsNullOrEmpty(options.HmacKeySignatureSecret))
        {
            parameters.KeySignature = AltchaCrypto.HmacHex(options.HmacAlgorithm, derivedKey, options.HmacKeySignatureSecret);
        }

        var challenge = new Challenge { Parameters = parameters };
        if (!string.IsNullOrEmpty(options.HmacSignatureSecret))
        {
            challenge.Signature = Sign(options.HmacAlgorithm, parameters, options.HmacSignatureSecret);
        }

        return challenge;
    }

    /// <summary>Brute-forces the counter until the derived key matches the challenge's key prefix.</summary>
    /// <exception cref="OperationCanceledException">The token was cancelled.</exception>
    /// <exception cref="AltchaException">The challenge is malformed or no solution exists in the counter range.</exception>
    public static Solution SolveChallenge(SolveChallengeOptions options, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        var parameters = options.Challenge.Parameters;
        var deriveKey = options.DeriveKey ?? KeyDerivation.Resolve(parameters.Algorithm);
        var step = options.CounterStep > 0 ? options.CounterStep : 1;
        var prefix = KeyPrefix.Parse(parameters.KeyPrefix);
        var salt = DecodeHex(parameters.Salt, "salt");
        var nonce = DecodeHex(parameters.Nonce, "nonce");

        var start = Stopwatch.GetTimestamp();
        for (long n = options.CounterStart; n <= int.MaxValue; n += step)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var derivedKey = deriveKey(parameters, salt, AltchaCrypto.PasswordWithCounter(nonce, (int)n));
            if (prefix.Matches(derivedKey))
            {
                return new Solution
                {
                    Counter = (int)n,
                    DerivedKey = AltchaCrypto.ToHex(derivedKey),
                    Time = Math.Floor(Stopwatch.GetElapsedTime(start).TotalMilliseconds * 10) / 10,
                };
            }
        }

        throw new AltchaException("No solution found.");
    }

    /// <summary>
    /// Verifies a solution: expiry, then the challenge signature, then either the key signature (fast path)
    /// or a re-derivation of the key (slow path).
    /// </summary>
    /// <exception cref="ArgumentException"><see cref="VerifySolutionOptions.HmacSignatureSecret"/> is null or empty.</exception>
    /// <exception cref="AltchaException">The challenge parameters are malformed or the algorithm is unsupported.</exception>
    public static VerifySolutionResult VerifySolution(VerifySolutionOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        var hmacSignatureSecret = options.HmacSignatureSecret;
        ArgumentException.ThrowIfNullOrEmpty(hmacSignatureSecret, $"{nameof(options)}.{nameof(options.HmacSignatureSecret)}");
        var start = Stopwatch.GetTimestamp();
        var result = new VerifySolutionResult();
        // Deserialized parameters are verified exactly as received, and the key is derived from the same JSON.
        var received = options.Challenge?.Parameters?.ReceivedJson;
        var parameters = received is { } json ? ParseReceived(json) : options.Challenge?.Parameters ?? new ChallengeParameters();
        var solution = options.Solution ?? new Solution();

        try
        {
            // JS: `expiresAt && expiresAt < Date.now() / 1000` — 0 means no expiry, current time is fractional.
            if (parameters.ExpiresAt is { } expiresAt and not 0
                && expiresAt < DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() / 1000.0)
            {
                result.Expired = true;
                return result;
            }

            result.InvalidSignature = true;
            var signature = options.Challenge?.Signature;
            var signedJson = received is { } signedParameters ? CanonicalJson.Serialize(signedParameters) : CanonicalJson.Serialize(parameters);
            if (string.IsNullOrEmpty(signature)
                || !AltchaCrypto.ConstantTimeEquals(AltchaCrypto.HmacHex(options.HmacAlgorithm, Encoding.UTF8.GetBytes(signedJson), hmacSignatureSecret), signature))
            {
                return result;
            }

            result.InvalidSignature = false;

            if (!string.IsNullOrEmpty(parameters.KeySignature) && !string.IsNullOrEmpty(options.HmacKeySignatureSecret))
            {
                result.InvalidSolution = true;
                if (!AltchaCrypto.TryFromHex(solution.DerivedKey, out var derivedKeyBytes))
                {
                    return result;
                }

                var expected = AltchaCrypto.HmacHex(options.HmacAlgorithm, derivedKeyBytes, options.HmacKeySignatureSecret);
                if (AltchaCrypto.ConstantTimeEquals(expected, parameters.KeySignature))
                {
                    result.InvalidSolution = false;
                    result.Verified = true;
                }

                return result;
            }

            result.InvalidSolution = true;
            if (solution.Counter < 0)
            {
                return result;
            }

            var deriveKey = options.DeriveKey ?? KeyDerivation.Resolve(parameters.Algorithm);
            var prefix = KeyPrefix.Parse(parameters.KeyPrefix);
            var salt = DecodeHex(parameters.Salt, "salt");
            var nonce = DecodeHex(parameters.Nonce, "nonce");
            var derivedKey = deriveKey(parameters, salt, AltchaCrypto.PasswordWithCounter(nonce, solution.Counter));
            if (AltchaCrypto.ConstantTimeEquals(AltchaCrypto.ToHex(derivedKey), solution.DerivedKey) && prefix.Matches(derivedKey))
            {
                result.InvalidSolution = false;
                result.Verified = true;
            }

            return result;
        }
        finally
        {
            result.Time = (long)Stopwatch.GetElapsedTime(start).TotalMilliseconds;
        }
    }

    private static string Sign(AltchaHashAlgorithm algorithm, ChallengeParameters parameters, string secret) =>
        AltchaCrypto.HmacHex(algorithm, Encoding.UTF8.GetBytes(CanonicalJson.Serialize(parameters)), secret);

    private static ChallengeParameters ParseReceived(JsonElement json)
    {
        try
        {
            return json.Deserialize<ChallengeParameters>(AltchaJson.SerializerOptions)!;
        }
        catch (JsonException e)
        {
            throw new AltchaException("Invalid challenge parameters.", e);
        }
    }

    private static byte[] DecodeHex(string? hex, string name) =>
        AltchaCrypto.TryFromHex(hex, out var bytes) ? bytes : throw new AltchaException($"Invalid {name} hex.");

    private static Dictionary<string, JsonElement>? ToJsonData(IDictionary<string, object?>? data)
    {
        if (data is null || data.Count == 0)
        {
            return null;
        }

        var result = new Dictionary<string, JsonElement>(data.Count, StringComparer.Ordinal);
        foreach (var (key, value) in data)
        {
            result[key] = JsonSerializer.SerializeToElement(value);
        }

        return result;
    }
}
