using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Altcha.AspNetCore;

/// <summary>Creates challenges and verifies ALTCHA payloads (proof-of-work and Sentinel).</summary>
public interface IAltchaService
{
    /// <summary>Creates a signed challenge from the configured options.</summary>
    /// <exception cref="InvalidOperationException"><see cref="AltchaOptions.HmacSignatureSecret"/> is not configured.</exception>
    Challenge CreateChallenge(HttpContext? httpContext = null);

    /// <summary>
    /// Verifies a base64 payload submitted by the widget, applying classification, fields-hash and replay policies.
    /// <paramref name="getFieldValue"/> supplies form values for Sentinel <c>fieldsHash</c> checks.
    /// </summary>
    Task<AltchaVerificationResult> VerifyAsync(
        string? payload,
        Func<string, string?>? getFieldValue = null,
        CancellationToken cancellationToken = default);
}

/// <summary>Default <see cref="IAltchaService"/>.</summary>
public sealed partial class AltchaService : IAltchaService
{
    private const int MaxPayloadLength = 16384;
    private const string VerificationFailed = "ALTCHA verification failed.";
    private const string InvalidPayload = "ALTCHA payload is invalid.";
    private const string PayloadAlreadyUsed = "PAYLOAD_ALREADY_USED";

    // Latest expiry DateTimeOffset can represent once the 30 s claim margin is added.
    private static readonly double MaxClaimUnixSeconds = DateTimeOffset.MaxValue.ToUnixTimeSeconds() - 60;

    private readonly IOptionsMonitor<AltchaOptions> _options;
    private readonly IAltchaReplayStore _replayStore;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<AltchaService> _logger;

    /// <summary>Creates the service.</summary>
    public AltchaService(
        IOptionsMonitor<AltchaOptions> options,
        IAltchaReplayStore replayStore,
        IHttpClientFactory httpClientFactory,
        ILogger<AltchaService> logger)
    {
        _options = options;
        _replayStore = replayStore;
        _httpClientFactory = httpClientFactory;
        _logger = logger;
    }

    /// <inheritdoc />
    public Challenge CreateChallenge(HttpContext? httpContext = null)
    {
        var options = _options.CurrentValue;
        if (string.IsNullOrEmpty(options.HmacSignatureSecret))
        {
            throw new InvalidOperationException("Altcha:HmacSignatureSecret is required to create challenges.");
        }

        var challenge = options.Challenge;
        var createOptions = new CreateChallengeOptions
        {
            Algorithm = challenge.Algorithm,
            Cost = challenge.Cost,
            KeyLength = challenge.KeyLength,
            KeyPrefixLength = challenge.KeyPrefixLength ?? 0,
            MemoryCost = challenge.MemoryCost ?? 0,
            Parallelism = challenge.Parallelism ?? 0,
            ExpiresAt = DateTimeOffset.UtcNow + challenge.Expires,
            Counter = challenge.Deterministic ? RandomNumberGenerator.GetInt32(challenge.CounterMin, challenge.CounterMax) : null,
            KeyPrefix = challenge.Deterministic ? null : challenge.KeyPrefix,
            HmacAlgorithm = options.HmacAlgorithm,
            HmacSignatureSecret = options.HmacSignatureSecret,
            HmacKeySignatureSecret = options.HmacKeySignatureSecret,
            DeriveKey = options.DeriveKey,
        };
        options.ConfigureChallenge?.Invoke(httpContext, createOptions);
        return AltchaPow.CreateChallenge(createOptions);
    }

    /// <inheritdoc />
    public async Task<AltchaVerificationResult> VerifyAsync(
        string? payload,
        Func<string, string?>? getFieldValue = null,
        CancellationToken cancellationToken = default)
    {
        var result = await VerifyCoreAsync(payload, getFieldValue, cancellationToken).ConfigureAwait(false);
        if (!result.Verified)
        {
            LogVerificationFailed(result.ErrorCode?.ToCode(), result.PayloadType);
        }

        return result;
    }

    private async Task<AltchaVerificationResult> VerifyCoreAsync(
        string? payload,
        Func<string, string?>? getFieldValue,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(payload))
        {
            return Fail(AltchaErrorCode.Missing, "ALTCHA payload is missing.");
        }

        var trimmed = payload.Trim();
        using var document = TryParsePayload(trimmed);
        if (document is null)
        {
            return Fail(AltchaErrorCode.Malformed, InvalidPayload);
        }

        var root = document.RootElement;
        var options = _options.CurrentValue;
        if (root.TryGetProperty("verificationData", out _))
        {
            return await VerifyServerPayloadAsync(root, trimmed, options, getFieldValue, cancellationToken).ConfigureAwait(false);
        }

        if (root.TryGetProperty("challenge", out _) && root.TryGetProperty("solution", out _))
        {
            return await VerifyProofOfWorkAsync(root, options, cancellationToken).ConfigureAwait(false);
        }

        return Fail(AltchaErrorCode.Malformed, InvalidPayload);
    }

    private async Task<AltchaVerificationResult> VerifyProofOfWorkAsync(
        JsonElement root,
        AltchaOptions options,
        CancellationToken cancellationToken)
    {
        const AltchaPayloadType type = AltchaPayloadType.ProofOfWork;
        if (string.IsNullOrEmpty(options.HmacSignatureSecret))
        {
            return Fail(AltchaErrorCode.Misconfigured, "HmacSignatureSecret is required to verify self-hosted ALTCHA challenges.", type);
        }

        Payload? payload;
        VerifySolutionResult solution;
        try
        {
            payload = root.Deserialize<Payload>(AltchaJson.SerializerOptions);
            if (payload?.Challenge?.Parameters is null || payload.Solution is null)
            {
                return Fail(AltchaErrorCode.Malformed, InvalidPayload, type);
            }

            solution = AltchaPow.VerifySolution(new VerifySolutionOptions
            {
                Challenge = payload.Challenge,
                Solution = payload.Solution,
                DeriveKey = options.DeriveKey,
                HmacAlgorithm = options.HmacAlgorithm,
                HmacSignatureSecret = options.HmacSignatureSecret,
                HmacKeySignatureSecret = options.HmacKeySignatureSecret,
            });
        }
        catch (Exception e) when (e is JsonException or AltchaException)
        {
            return Fail(AltchaErrorCode.Malformed, InvalidPayload, type);
        }

        if (solution.Expired)
        {
            return Fail(AltchaErrorCode.Expired, "ALTCHA challenge has expired.", type, payload, solution);
        }

        if (solution.InvalidSignature == true)
        {
            return Fail(AltchaErrorCode.InvalidSignature, VerificationFailed, type, payload, solution);
        }

        if (!solution.Verified)
        {
            return Fail(AltchaErrorCode.InvalidSolution, VerificationFailed, type, payload, solution);
        }

        var parameters = payload.Challenge.Parameters;
        var replayId = GetChallengeId(parameters) ?? parameters.Nonce;
        if (!await TryClaimAsync(options, "pow", replayId, parameters.ExpiresAt, cancellationToken).ConfigureAwait(false))
        {
            return Fail(AltchaErrorCode.Replayed, "ALTCHA payload has been already used.", type, payload, solution);
        }

        return new AltchaVerificationResult { Verified = true, PayloadType = type, Payload = payload, Solution = solution };
    }

    private async Task<AltchaVerificationResult> VerifyServerPayloadAsync(
        JsonElement root,
        string rawPayload,
        AltchaOptions options,
        Func<string, string?>? getFieldValue,
        CancellationToken cancellationToken)
    {
        var sentinel = options.Sentinel;
        var type = sentinel.Mode == SentinelVerifyMode.Remote ? AltchaPayloadType.SentinelRemote : AltchaPayloadType.SentinelLocal;

        ServerSignaturePayload? payload;
        try
        {
            payload = root.Deserialize<ServerSignaturePayload>(AltchaJson.SerializerOptions);
        }
        catch (JsonException)
        {
            payload = null;
        }

        if (payload is null)
        {
            return Fail(AltchaErrorCode.Malformed, InvalidPayload, type);
        }

        VerifyServerSignatureResult? serverSignature = null;
        VerifyServerResult? sentinelResult = null;
        ServerSignatureVerificationData? vd;

        if (sentinel.Mode == SentinelVerifyMode.Local)
        {
            if (string.IsNullOrEmpty(sentinel.ApiSecret))
            {
                return Fail(AltchaErrorCode.Misconfigured, "Sentinel ApiSecret is required to verify Sentinel payloads locally.", type, serverPayload: payload);
            }

            try
            {
                serverSignature = ServerSignature.Verify(payload, sentinel.ApiSecret);
            }
            catch (AltchaException)
            {
                return Fail(AltchaErrorCode.Malformed, InvalidPayload, type, serverPayload: payload);
            }

            vd = serverSignature.VerificationData;
            if (serverSignature.Expired)
            {
                return Fail(AltchaErrorCode.Expired, "ALTCHA verification has expired.", type, serverPayload: payload, serverSignature: serverSignature, vd: vd);
            }

            if (serverSignature.InvalidSignature)
            {
                return Fail(AltchaErrorCode.InvalidSignature, VerificationFailed, type, serverPayload: payload, serverSignature: serverSignature, vd: vd);
            }

            if (!serverSignature.Verified)
            {
                return Fail(AltchaErrorCode.Unverified, VerificationFailed, type, serverPayload: payload, serverSignature: serverSignature, vd: vd);
            }
        }
        else
        {
            if (!AltchaOptionsValidator.IsHttpUrl(sentinel.VerifyUrl))
            {
                return Fail(AltchaErrorCode.Misconfigured, "Sentinel VerifyUrl is required to verify Sentinel payloads remotely.", type, serverPayload: payload);
            }

            try
            {
                var client = new SentinelClient(_httpClientFactory.CreateClient(AltchaDefaults.SentinelHttpClientName));
                sentinelResult = await client.VerifyAsync(
                    new VerifyServerOptions
                    {
                        Url = new Uri(sentinel.VerifyUrl!),
                        Payload = rawPayload,
                        Secret = sentinel.ApiSecret,
                        Headers = sentinel.Headers,
                        Timeout = sentinel.Timeout,
                        Retries = sentinel.Retries,
                        RetryDelay = sentinel.RetryDelay,
                        RetryBackoff = sentinel.RetryBackoff,
                    },
                    cancellationToken).ConfigureAwait(false);
            }
            catch (AltchaSentinelException e)
            {
                LogSentinelUnavailable(e);
                return Fail(AltchaErrorCode.BackendError, "ALTCHA verification service is unavailable.", type, serverPayload: payload);
            }

            vd = sentinelResult.VerificationData;
            if (!sentinelResult.Verified)
            {
                return sentinelResult.Reason == PayloadAlreadyUsed
                    ? Fail(AltchaErrorCode.Replayed, "ALTCHA payload has been already used.", type, serverPayload: payload, sentinelResult: sentinelResult, vd: vd)
                    : Fail(AltchaErrorCode.Unverified, sentinelResult.Reason ?? VerificationFailed, type, serverPayload: payload, sentinelResult: sentinelResult, vd: vd);
            }
        }

        AltchaVerificationResult PolicyFail(AltchaErrorCode code, string error) =>
            Fail(code, error, type, serverPayload: payload, serverSignature: serverSignature, sentinelResult: sentinelResult, vd: vd);

        if (vd?.Classification is { } classification
            && (sentinel.RejectClassifications ?? AltchaSentinelOptions.DefaultRejectClassifications).Contains(classification, StringComparer.OrdinalIgnoreCase))
        {
            return PolicyFail(AltchaErrorCode.ClassificationRejected, "ALTCHA verification rejected by classification.");
        }

        if (sentinel.VerifyFieldsHash && !string.IsNullOrEmpty(vd?.FieldsHash))
        {
            if (getFieldValue is null)
            {
                return PolicyFail(AltchaErrorCode.FieldsHashMismatch, "ALTCHA fieldsHash is present but no form fields are available.");
            }

            if (!ServerSignature.VerifyFieldsHash(getFieldValue, vd.Fields ?? [], vd.FieldsHash))
            {
                return PolicyFail(AltchaErrorCode.FieldsHashMismatch, "ALTCHA fields hash mismatch.");
            }
        }

        var replayId = vd?.Id ?? payload.Id ?? payload.Signature;
        if (!await TryClaimAsync(options, "sentinel", replayId, vd?.Expire, cancellationToken).ConfigureAwait(false))
        {
            return PolicyFail(AltchaErrorCode.Replayed, "ALTCHA payload has been already used.");
        }

        return new AltchaVerificationResult
        {
            Verified = true,
            PayloadType = type,
            ServerPayload = payload,
            ServerSignature = serverSignature,
            SentinelResult = sentinelResult,
            VerificationData = vd,
        };
    }

    private async ValueTask<bool> TryClaimAsync(AltchaOptions options, string scope, string? id, double? expiry, CancellationToken cancellationToken)
    {
        if (!options.ReplayProtection || string.IsNullOrEmpty(id))
        {
            return true;
        }

        var now = DateTimeOffset.UtcNow;
        var expiresAt = expiry > 0
            ? DateTimeOffset.UnixEpoch.AddSeconds(Math.Min(expiry.Value, MaxClaimUnixSeconds)).AddSeconds(30)
            : now.AddHours(1);
        var minimum = now.AddSeconds(1);
        if (expiresAt < minimum)
        {
            expiresAt = minimum;
        }

        return await _replayStore.TryClaimAsync($"altcha:{scope}:{id}", expiresAt, cancellationToken).ConfigureAwait(false);
    }

    private static string? GetChallengeId(ChallengeParameters parameters)
    {
        if (parameters.Data is null || !parameters.Data.TryGetValue("challengeId", out var value))
        {
            return null;
        }

        return value.ValueKind switch
        {
            JsonValueKind.String => value.GetString(),
            JsonValueKind.Number => value.GetRawText(),
            _ => null,
        };
    }

    private static JsonDocument? TryParsePayload(string trimmed)
    {
        if (trimmed.Length > MaxPayloadLength)
        {
            return null;
        }

        var padded = (trimmed.Length % 4) switch
        {
            2 => trimmed + "==",
            3 => trimmed + "=",
            _ => trimmed,
        };
        var buffer = new byte[padded.Length * 3 / 4];
        if (!Convert.TryFromBase64String(padded, buffer, out var written))
        {
            return null;
        }

        try
        {
            var document = JsonDocument.Parse(buffer.AsMemory(0, written));
            if (document.RootElement.ValueKind == JsonValueKind.Object)
            {
                return document;
            }

            document.Dispose();
            return null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static AltchaVerificationResult Fail(
        AltchaErrorCode code,
        string error,
        AltchaPayloadType type = AltchaPayloadType.None,
        Payload? payload = null,
        VerifySolutionResult? solution = null,
        ServerSignaturePayload? serverPayload = null,
        VerifyServerSignatureResult? serverSignature = null,
        VerifyServerResult? sentinelResult = null,
        ServerSignatureVerificationData? vd = null) =>
        new()
        {
            Verified = false,
            ErrorCode = code,
            Error = error,
            PayloadType = type,
            Payload = payload,
            Solution = solution,
            ServerPayload = serverPayload,
            ServerSignature = serverSignature,
            SentinelResult = sentinelResult,
            VerificationData = vd,
        };

    [LoggerMessage(EventId = 1, Level = LogLevel.Debug, Message = "ALTCHA verification failed: {ErrorCode} ({PayloadType}).")]
    private partial void LogVerificationFailed(string? errorCode, AltchaPayloadType payloadType);

    [LoggerMessage(EventId = 2, Level = LogLevel.Warning, Message = "ALTCHA Sentinel verification service is unavailable.")]
    private partial void LogSentinelUnavailable(Exception exception);
}
