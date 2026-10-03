using System.Text.Json;
using System.Text.Json.Serialization;
using Altcha.Serialization;

namespace Altcha;

/// <summary>
/// Key-derivation parameters of a v2 challenge. These are what the challenge signature covers.
/// Null optional properties are never written, whatever the serializer options, so the wire form always matches
/// the signed form.
/// </summary>
public sealed class ChallengeParameters
{
    /// <summary>KDF algorithm, e.g. <c>PBKDF2/SHA-256</c>, <c>SHA-256</c>, <c>SCRYPT</c> or <c>ARGON2ID</c>.</summary>
    [JsonPropertyName("algorithm")]
    public string Algorithm { get; set; } = string.Empty;

    /// <summary>Hex-encoded random nonce.</summary>
    [JsonPropertyName("nonce")]
    public string Nonce { get; set; } = string.Empty;

    /// <summary>Hex-encoded random salt.</summary>
    [JsonPropertyName("salt")]
    public string Salt { get; set; } = string.Empty;

    /// <summary>KDF cost (iterations, N or time cost depending on the algorithm).</summary>
    [JsonPropertyName("cost")]
    public int Cost { get; set; }

    /// <summary>Derived key length in bytes.</summary>
    [JsonPropertyName("keyLength")]
    public int KeyLength { get; set; }

    /// <summary>Hex prefix the derived key must start with. Odd lengths are allowed.</summary>
    [JsonPropertyName("keyPrefix")]
    public string KeyPrefix { get; set; } = string.Empty;

    /// <summary>HMAC of the expected derived key, enabling verification without re-deriving.</summary>
    [JsonPropertyName("keySignature")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? KeySignature { get; set; }

    /// <summary>Memory cost (scrypt r, Argon2 memory in KiB).</summary>
    [JsonPropertyName("memoryCost")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public int? MemoryCost { get; set; }

    /// <summary>Parallelism (scrypt p, Argon2 lanes).</summary>
    [JsonPropertyName("parallelism")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public int? Parallelism { get; set; }

    /// <summary>Expiry as unix seconds; may be fractional (JS issuers sign any number). 0 means no expiry.</summary>
    [JsonPropertyName("expiresAt")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public double? ExpiresAt { get; set; }

    /// <summary>Arbitrary signed data attached to the challenge.</summary>
    [JsonPropertyName("data")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Dictionary<string, JsonElement>? Data { get; set; }

    /// <summary>
    /// The JSON object these parameters were deserialized from, when read through <see cref="Challenge.Parameters"/>.
    /// <see cref="AltchaPow.VerifySolution"/> verifies the signature over it and derives the key from it.
    /// </summary>
    internal JsonElement? ReceivedJson { get; set; }
}

/// <summary>A v2 challenge: parameters plus their HMAC signature.</summary>
public sealed class Challenge
{
    /// <summary>
    /// The challenge parameters. When deserialized, the received JSON is kept and verified exactly as received
    /// (unknown keys, JSON types and key casing are all covered by the signature); later property changes are ignored
    /// by <see cref="AltchaPow.VerifySolution"/>.
    /// </summary>
    [JsonPropertyName("parameters")]
    [JsonConverter(typeof(ReceivedParametersConverter))]
    public ChallengeParameters Parameters { get; set; } = new();

    /// <summary>Hex HMAC of the canonical JSON of <see cref="Parameters"/>.</summary>
    [JsonPropertyName("signature")]
    public string? Signature { get; set; }
}

/// <summary>A solution to a v2 challenge.</summary>
public sealed class Solution
{
    /// <summary>The counter that produced a derived key matching the prefix.</summary>
    [JsonPropertyName("counter")]
    public int Counter { get; set; }

    /// <summary>Hex-encoded derived key.</summary>
    [JsonPropertyName("derivedKey")]
    public string DerivedKey { get; set; } = string.Empty;

    /// <summary>Solve time in milliseconds.</summary>
    [JsonPropertyName("time")]
    public double? Time { get; set; }
}

/// <summary>The payload submitted by the widget: a challenge and its solution.</summary>
public sealed class Payload
{
    /// <summary>The challenge.</summary>
    [JsonPropertyName("challenge")]
    public Challenge Challenge { get; set; } = new();

    /// <summary>The solution.</summary>
    [JsonPropertyName("solution")]
    public Solution Solution { get; set; } = new();
}

/// <summary>A Sentinel server-signature payload.</summary>
public sealed class ServerSignaturePayload
{
    /// <summary>Hash algorithm, e.g. <c>SHA-256</c>.</summary>
    [JsonPropertyName("algorithm")]
    public string Algorithm { get; set; } = string.Empty;

    /// <summary>Hex HMAC of the hash of <see cref="VerificationData"/>.</summary>
    [JsonPropertyName("signature")]
    public string Signature { get; set; } = string.Empty;

    /// <summary>URL-encoded verification data.</summary>
    [JsonPropertyName("verificationData")]
    public string VerificationData { get; set; } = string.Empty;

    /// <summary>Whether Sentinel verified the client.</summary>
    [JsonPropertyName("verified")]
    public bool Verified { get; set; }

    /// <summary>The Sentinel API key, if present.</summary>
    [JsonPropertyName("apiKey")]
    public string? ApiKey { get; set; }

    /// <summary>The payload id, if present.</summary>
    [JsonPropertyName("id")]
    public string? Id { get; set; }
}

/// <summary>
/// Parsed Sentinel verification data. Local verification parses the URL-encoded form, where groups use
/// dotted keys (<c>location.countryCode=id</c>); remote verification returns the same data as nested JSON
/// (<c>"location": { "countryCode": "id" }</c>). Both populate the same properties.
/// </summary>
public sealed class ServerSignatureVerificationData
{
    /// <summary>Algorithm used to generate the challenge, e.g. <c>PBKDF2/SHA-256</c>.</summary>
    [JsonPropertyName("challengeAlgorithm")]
    [JsonConverter(typeof(LenientStringConverter))]
    public string? ChallengeAlgorithm { get; set; }

    /// <summary>Overall classification: <c>GOOD</c>, <c>NEUTRAL</c> or <c>BAD</c>.</summary>
    [JsonPropertyName("classification")]
    [JsonConverter(typeof(LenientStringConverter))]
    public string? Classification { get; set; }

    /// <summary>Device detection (<c>device.*</c>).</summary>
    [JsonPropertyName("device")]
    [JsonConverter(typeof(LenientObjectConverter<SentinelDevice>))]
    public SentinelDevice? Device { get; set; }

    /// <summary>Email address classification (<c>email.*</c>), when an email field was submitted.</summary>
    [JsonPropertyName("email")]
    [JsonConverter(typeof(LenientObjectConverter<SentinelCheck>))]
    public SentinelCheck? Email { get; set; }

    /// <summary>Expiry as unix seconds; may be fractional. 0 means no expiry.</summary>
    [JsonPropertyName("expire")]
    [JsonConverter(typeof(LenientDoubleConverter))]
    public double? Expire { get; set; }

    /// <summary>Names of the fields covered by <see cref="FieldsHash"/>.</summary>
    [JsonPropertyName("fields")]
    [JsonConverter(typeof(LenientStringListConverter))]
    public IReadOnlyList<string>? Fields { get; set; }

    /// <summary>Hex hash of the newline-joined field values.</summary>
    [JsonPropertyName("fieldsHash")]
    [JsonConverter(typeof(LenientStringConverter))]
    public string? FieldsHash { get; set; }

    /// <summary>Verification id, used for replay protection.</summary>
    [JsonPropertyName("id")]
    [JsonConverter(typeof(LenientStringConverter))]
    public string? Id { get; set; }

    /// <summary>IP address classification (<c>ip.*</c>).</summary>
    [JsonPropertyName("ip")]
    [JsonConverter(typeof(LenientObjectConverter<SentinelCheck>))]
    public SentinelCheck? Ip { get; set; }

    /// <summary>Client IP address.</summary>
    [JsonPropertyName("ipAddress")]
    [JsonConverter(typeof(LenientStringConverter))]
    public string? IpAddress { get; set; }

    /// <summary>Location classification (<c>location.*</c>), including the country code.</summary>
    [JsonPropertyName("location")]
    [JsonConverter(typeof(LenientObjectConverter<SentinelLocation>))]
    public SentinelLocation? Location { get; set; }

    /// <summary>Request origin URL.</summary>
    [JsonPropertyName("origin")]
    [JsonConverter(typeof(LenientStringConverter))]
    public string? Origin { get; set; }

    /// <summary>Custom parameters passed to the challenge (<c>params.*</c>).</summary>
    [JsonPropertyName("params")]
    [JsonConverter(typeof(LenientStringDictionaryConverter))]
    public IReadOnlyDictionary<string, string>? Params { get; set; }

    /// <summary>Internal penalty associated with the client.</summary>
    [JsonPropertyName("penalty")]
    [JsonConverter(typeof(LenientDoubleConverter))]
    public double? Penalty { get; set; }

    /// <summary>Rules triggered during overall classification.</summary>
    [JsonPropertyName("reasons")]
    [JsonConverter(typeof(LenientStringListConverter))]
    public IReadOnlyList<string>? Reasons { get; set; }

    /// <summary>Overall classification score.</summary>
    [JsonPropertyName("score")]
    [JsonConverter(typeof(LenientDoubleConverter))]
    public double? Score { get; set; }

    /// <summary>Text classification (<c>text.*</c>), including the detected language.</summary>
    [JsonPropertyName("text")]
    [JsonConverter(typeof(LenientObjectConverter<SentinelText>))]
    public SentinelText? Text { get; set; }

    /// <summary>Verification time as unix seconds.</summary>
    [JsonPropertyName("time")]
    [JsonConverter(typeof(LenientInt64Converter))]
    public long? Time { get; set; }

    /// <summary>Whether the client was verified.</summary>
    [JsonPropertyName("verified")]
    [JsonConverter(typeof(LenientBooleanConverter))]
    public bool Verified { get; set; }

    /// <summary>Any additional, unrecognized properties.</summary>
    [JsonExtensionData]
    public Dictionary<string, JsonElement>? Extra { get; set; }
}

/// <summary>A Sentinel classifier result: score and triggered rules (<c>email.*</c>, <c>ip.*</c>).</summary>
public sealed class SentinelCheck
{
    /// <summary>Classification score.</summary>
    [JsonPropertyName("score")]
    [JsonConverter(typeof(LenientDoubleConverter))]
    public double? Score { get; set; }

    /// <summary>Rules triggered during classification.</summary>
    [JsonPropertyName("triggeredRules")]
    [JsonConverter(typeof(LenientStringListConverter))]
    public IReadOnlyList<string>? TriggeredRules { get; set; }

    /// <summary>Any additional, unrecognized properties.</summary>
    [JsonExtensionData]
    public Dictionary<string, JsonElement>? Extra { get; set; }
}

/// <summary>Sentinel location classification (<c>location.*</c>).</summary>
public sealed class SentinelLocation
{
    /// <summary>Two-letter country code detected from the IP address or time zone, e.g. <c>id</c>.</summary>
    [JsonPropertyName("countryCode")]
    [JsonConverter(typeof(LenientStringConverter))]
    public string? CountryCode { get; set; }

    /// <summary>Location classification score.</summary>
    [JsonPropertyName("score")]
    [JsonConverter(typeof(LenientDoubleConverter))]
    public double? Score { get; set; }

    /// <summary>The client's time zone, e.g. <c>Asia/Makassar</c>.</summary>
    [JsonPropertyName("timeZone")]
    [JsonConverter(typeof(LenientStringConverter))]
    public string? TimeZone { get; set; }

    /// <summary>Rules triggered during location classification.</summary>
    [JsonPropertyName("triggeredRules")]
    [JsonConverter(typeof(LenientStringListConverter))]
    public IReadOnlyList<string>? TriggeredRules { get; set; }

    /// <summary>Any additional, unrecognized properties.</summary>
    [JsonExtensionData]
    public Dictionary<string, JsonElement>? Extra { get; set; }
}

/// <summary>Sentinel text classification (<c>text.*</c>).</summary>
public sealed class SentinelText
{
    /// <summary>Language detected from the submitted text.</summary>
    [JsonPropertyName("language")]
    [JsonConverter(typeof(LenientStringConverter))]
    public string? Language { get; set; }

    /// <summary>Text classification score.</summary>
    [JsonPropertyName("score")]
    [JsonConverter(typeof(LenientDoubleConverter))]
    public double? Score { get; set; }

    /// <summary>Rules triggered during text classification.</summary>
    [JsonPropertyName("triggeredRules")]
    [JsonConverter(typeof(LenientStringListConverter))]
    public IReadOnlyList<string>? TriggeredRules { get; set; }

    /// <summary>Any additional, unrecognized properties.</summary>
    [JsonExtensionData]
    public Dictionary<string, JsonElement>? Extra { get; set; }
}

/// <summary>Sentinel device detection (<c>device.*</c>).</summary>
public sealed class SentinelDevice
{
    /// <summary>Browser name, e.g. <c>Chrome</c>, <c>Firefox</c>, <c>Safari</c>.</summary>
    [JsonPropertyName("browser")]
    [JsonConverter(typeof(LenientStringConverter))]
    public string? Browser { get; set; }

    /// <summary>Device identifier (EDK).</summary>
    [JsonPropertyName("edk")]
    [JsonConverter(typeof(LenientStringConverter))]
    public string? Edk { get; set; }

    /// <summary>Device type, e.g. <c>desktop</c>, <c>mobile</c>, <c>tablet</c>, <c>bot</c>.</summary>
    [JsonPropertyName("type")]
    [JsonConverter(typeof(LenientStringConverter))]
    public string? Type { get; set; }

    /// <summary>Any additional, unrecognized properties.</summary>
    [JsonExtensionData]
    public Dictionary<string, JsonElement>? Extra { get; set; }
}

/// <summary>Result of <see cref="AltchaPow.VerifySolution"/>.</summary>
public sealed class VerifySolutionResult
{
    /// <summary>True when the solution is valid, unexpired and correctly signed.</summary>
    public bool Verified { get; set; }

    /// <summary>True when the challenge has expired.</summary>
    public bool Expired { get; set; }

    /// <summary>Whether the challenge signature is invalid; null when not checked.</summary>
    public bool? InvalidSignature { get; set; }

    /// <summary>Whether the solution is invalid; null when not checked.</summary>
    public bool? InvalidSolution { get; set; }

    /// <summary>Verification time in milliseconds.</summary>
    public long Time { get; set; }
}

/// <summary>Result of <see cref="ServerSignature.Verify(ServerSignaturePayload, string)"/>.</summary>
public sealed class VerifyServerSignatureResult
{
    /// <summary>True when the signature is valid, unexpired and the client was verified.</summary>
    public bool Verified { get; set; }

    /// <summary>True when the verification data has expired.</summary>
    public bool Expired { get; set; }

    /// <summary>True when the signature does not match.</summary>
    public bool InvalidSignature { get; set; }

    /// <summary>True when the payload or verification data reports an unverified client.</summary>
    public bool InvalidSolution { get; set; }

    /// <summary>Verification time in milliseconds.</summary>
    public long Time { get; set; }

    /// <summary>The parsed verification data.</summary>
    public ServerSignatureVerificationData? VerificationData { get; set; }
}

/// <summary>Result of remote Sentinel verification (<c>POST /v1/verify/signature</c>).</summary>
public sealed class VerifyServerResult
{
    /// <summary>True when Sentinel verified the payload.</summary>
    [JsonPropertyName("verified")]
    public bool Verified { get; set; }

    /// <summary>Rejection reason, e.g. <c>PAYLOAD_ALREADY_USED</c>.</summary>
    [JsonPropertyName("reason")]
    public string? Reason { get; set; }

    /// <summary>The API key the payload belongs to.</summary>
    [JsonPropertyName("apiKey")]
    public string? ApiKey { get; set; }

    /// <summary>The verification data reported by Sentinel.</summary>
    [JsonPropertyName("verificationData")]
    public ServerSignatureVerificationData? VerificationData { get; set; }
}

/// <summary>Derives a key from challenge parameters, a salt and a password (nonce || counter).</summary>
public delegate byte[] DeriveKeyFunc(ChallengeParameters parameters, byte[] salt, byte[] password);
