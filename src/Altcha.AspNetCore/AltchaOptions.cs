using Microsoft.AspNetCore.Http;

namespace Altcha.AspNetCore;

/// <summary>Well-known names used by the ALTCHA ASP.NET Core integration.</summary>
public static class AltchaDefaults
{
    /// <summary>Default configuration section name.</summary>
    public const string ConfigurationSection = "Altcha";

    /// <summary>Name of the <see cref="System.Net.Http.IHttpClientFactory"/> client used for Sentinel requests.</summary>
    public const string SentinelHttpClientName = "Altcha.Sentinel";

    /// <summary>Endpoint name of the challenge endpoint, used for link generation.</summary>
    public const string ChallengeEndpointName = "AltchaChallenge";

    /// <summary>Default route pattern of the challenge endpoint.</summary>
    public const string ChallengePattern = "/altcha/challenge";
}

/// <summary>How Sentinel server-signature payloads are verified.</summary>
public enum SentinelVerifyMode
{
    /// <summary>Verify the HMAC signature locally with <see cref="AltchaSentinelOptions.ApiSecret"/>.</summary>
    Local,

    /// <summary>Call Sentinel's <c>/v1/verify/signature</c> API at <see cref="AltchaSentinelOptions.VerifyUrl"/>.</summary>
    Remote,
}

/// <summary>ALTCHA configuration. Bindable from the <c>Altcha</c> configuration section, except delegates.</summary>
public sealed class AltchaOptions
{
    /// <summary>Secret for challenge signatures. Required to create and verify self-hosted proof-of-work challenges.</summary>
    public string? HmacSignatureSecret { get; set; }

    /// <summary>Secret for key signatures, enabling verification without re-deriving the key.</summary>
    public string? HmacKeySignatureSecret { get; set; }

    /// <summary>HMAC algorithm for challenge and key signatures.</summary>
    public AltchaHashAlgorithm HmacAlgorithm { get; set; } = AltchaHashAlgorithm.Sha256;

    /// <summary>Form field carrying the payload; also the widget's <c>name</c>.</summary>
    public string FieldName { get; set; } = "altcha";

    /// <summary>HTTP status returned when verification fails and the request is rejected.</summary>
    public int FailureStatusCode { get; set; } = StatusCodes.Status403Forbidden;

    /// <summary>Whether each verified payload may only be used once.</summary>
    public bool ReplayProtection { get; set; } = true;

    /// <summary>Custom key derivation; defaults to the built-in function for the challenge algorithm.</summary>
    public DeriveKeyFunc? DeriveKey { get; set; }

    /// <summary>Hook to adjust each challenge before it is created (e.g. to attach <c>Data</c>).</summary>
    public Action<HttpContext?, CreateChallengeOptions>? ConfigureChallenge { get; set; }

    /// <summary>Challenge settings.</summary>
    public AltchaChallengeOptions Challenge { get; set; } = new();

    /// <summary>Sentinel settings.</summary>
    public AltchaSentinelOptions Sentinel { get; set; } = new();
}

/// <summary>Settings for issued proof-of-work challenges.</summary>
public sealed class AltchaChallengeOptions
{
    /// <summary>KDF algorithm; one of <see cref="KeyDerivation.CanonicalAlgorithms"/>.</summary>
    public string Algorithm { get; set; } = "PBKDF2/SHA-256";

    /// <summary>KDF cost.</summary>
    public int Cost { get; set; } = 5000;

    /// <summary>Derived key length in bytes.</summary>
    public int KeyLength { get; set; } = 32;

    /// <summary>Hex key prefix for random challenges (used only when <see cref="Deterministic"/> is false).</summary>
    public string KeyPrefix { get; set; } = "00";

    /// <summary>Key prefix length in bytes for deterministic challenges; defaults to half the key length.</summary>
    public int? KeyPrefixLength { get; set; }

    /// <summary>Memory cost (scrypt r, Argon2 KiB).</summary>
    public int? MemoryCost { get; set; }

    /// <summary>Parallelism (scrypt p, Argon2 lanes).</summary>
    public int? Parallelism { get; set; }

    /// <summary>How long a challenge stays valid.</summary>
    public TimeSpan Expires { get; set; } = TimeSpan.FromMinutes(10);

    /// <summary>Whether challenges use a server-chosen counter (with a key signature) instead of a random prefix.</summary>
    public bool Deterministic { get; set; } = true;

    /// <summary>Inclusive lower bound of the deterministic counter.</summary>
    public int CounterMin { get; set; } = 5000;

    /// <summary>Exclusive upper bound of the deterministic counter.</summary>
    public int CounterMax { get; set; } = 10000;
}

/// <summary>Settings for ALTCHA Sentinel payloads.</summary>
public sealed class AltchaSentinelOptions
{
    /// <summary>Local signature verification or remote API verification.</summary>
    public SentinelVerifyMode Mode { get; set; } = SentinelVerifyMode.Local;

    /// <summary>API secret: the HMAC key in <see cref="SentinelVerifyMode.Local"/> mode, the <c>secret</c> in remote mode.</summary>
    public string? ApiSecret { get; set; }

    /// <summary>Full <c>/v1/verify/signature</c> URL for remote mode.</summary>
    public string? VerifyUrl { get; set; }

    /// <summary>Sentinel challenge URL, rendered by the tag helper instead of the local challenge endpoint.</summary>
    public string? ChallengeUrl { get; set; }

    /// <summary>Timeout per remote attempt.</summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(10);

    /// <summary>Retries after the first remote attempt.</summary>
    public int Retries { get; set; } = 1;

    /// <summary>Base delay between remote retries.</summary>
    public TimeSpan RetryDelay { get; set; } = TimeSpan.FromMilliseconds(300);

    /// <summary>How the retry delay grows.</summary>
    public RetryBackoff RetryBackoff { get; set; } = RetryBackoff.Exponential;

    /// <summary>Additional headers for remote requests.</summary>
    public Dictionary<string, string> Headers { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Classifications that fail verification (case-insensitive). <c>null</c> (the default) means
    /// <see cref="DefaultRejectClassifications"/>. It is null rather than pre-populated because configuration
    /// binding appends to existing arrays instead of replacing them.
    /// </summary>
    public string[]? RejectClassifications { get; set; }

    /// <summary>Classifications rejected when <see cref="RejectClassifications"/> is null: <c>BAD</c>.</summary>
    public static IReadOnlyList<string> DefaultRejectClassifications { get; } = Array.AsReadOnly(new[] { "BAD" });

    /// <summary>Whether to check <c>fieldsHash</c> against the submitted form fields when present.</summary>
    public bool VerifyFieldsHash { get; set; } = true;
}
