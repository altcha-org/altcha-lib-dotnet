namespace Altcha.AspNetCore;

/// <summary>Why ALTCHA verification failed.</summary>
public enum AltchaErrorCode
{
    /// <summary>No payload was submitted.</summary>
    Missing,

    /// <summary>The payload could not be decoded or parsed.</summary>
    Malformed,

    /// <summary>A secret or URL required for this payload type is not configured.</summary>
    Misconfigured,

    /// <summary>The challenge or verification data has expired.</summary>
    Expired,

    /// <summary>The signature does not match.</summary>
    InvalidSignature,

    /// <summary>The proof-of-work solution is wrong.</summary>
    InvalidSolution,

    /// <summary>Sentinel did not verify the payload.</summary>
    Unverified,

    /// <summary>The payload was already used.</summary>
    Replayed,

    /// <summary>Sentinel's classification is in the reject list.</summary>
    ClassificationRejected,

    /// <summary>The submitted fields do not match Sentinel's <c>fieldsHash</c>.</summary>
    FieldsHashMismatch,

    /// <summary>The remote Sentinel API is unavailable.</summary>
    BackendError,
}

/// <summary>Kind of payload that was verified.</summary>
public enum AltchaPayloadType
{
    /// <summary>Unknown or undetermined.</summary>
    None,

    /// <summary>A self-hosted proof-of-work payload.</summary>
    ProofOfWork,

    /// <summary>A Sentinel payload verified locally.</summary>
    SentinelLocal,

    /// <summary>A Sentinel payload verified by the remote API.</summary>
    SentinelRemote,
}

/// <summary>String codes for <see cref="AltchaErrorCode"/>, used in problem details.</summary>
public static class AltchaErrorCodeExtensions
{
    /// <summary>Returns the snake_case code, e.g. <c>invalid_signature</c>.</summary>
    public static string ToCode(this AltchaErrorCode code) => code switch
    {
        AltchaErrorCode.Missing => "missing",
        AltchaErrorCode.Malformed => "malformed",
        AltchaErrorCode.Misconfigured => "misconfigured",
        AltchaErrorCode.Expired => "expired",
        AltchaErrorCode.InvalidSignature => "invalid_signature",
        AltchaErrorCode.InvalidSolution => "invalid_solution",
        AltchaErrorCode.Unverified => "unverified",
        AltchaErrorCode.Replayed => "replayed",
        AltchaErrorCode.ClassificationRejected => "classification_rejected",
        AltchaErrorCode.FieldsHashMismatch => "fields_hash_mismatch",
        AltchaErrorCode.BackendError => "backend_error",
        _ => throw new ArgumentOutOfRangeException(nameof(code), code, null),
    };
}

/// <summary>Outcome of <see cref="IAltchaService.VerifyAsync"/>.</summary>
public sealed class AltchaVerificationResult
{
    /// <summary>True when the payload was verified (and not replayed).</summary>
    public bool Verified { get; init; }

    /// <summary>Failure reason; null when verified.</summary>
    public AltchaErrorCode? ErrorCode { get; init; }

    /// <summary>Human-readable failure message; null when verified.</summary>
    public string? Error { get; init; }

    /// <summary>Detected payload type.</summary>
    public AltchaPayloadType PayloadType { get; init; }

    /// <summary>The proof-of-work payload, when applicable.</summary>
    public Payload? Payload { get; init; }

    /// <summary>The Sentinel payload, when applicable.</summary>
    public ServerSignaturePayload? ServerPayload { get; init; }

    /// <summary>Proof-of-work verification details.</summary>
    public VerifySolutionResult? Solution { get; init; }

    /// <summary>Local Sentinel verification details.</summary>
    public VerifyServerSignatureResult? ServerSignature { get; init; }

    /// <summary>Remote Sentinel verification details.</summary>
    public VerifyServerResult? SentinelResult { get; init; }

    /// <summary>Sentinel verification data (classification, fields, etc.).</summary>
    public ServerSignatureVerificationData? VerificationData { get; init; }
}
