using System.Diagnostics;
using System.Globalization;
using System.Text;
using System.Text.Json;

namespace Altcha;

/// <summary>Local verification of ALTCHA Sentinel server signatures.</summary>
public static class ServerSignature
{
    /// <summary>
    /// Parses URL-encoded verification data. Known keys populate typed properties; dotted Sentinel keys
    /// (<c>location.countryCode</c>, <c>device.browser</c>, <c>params.*</c>, ...) populate the matching group.
    /// Unknown keys go to the <c>Extra</c> dictionary of their group, or of the root. For duplicate keys the first value wins.
    /// </summary>
    public static ServerSignatureVerificationData ParseVerificationData(string data)
    {
        var vd = new ServerSignatureVerificationData();
        if (string.IsNullOrEmpty(data))
        {
            return vd;
        }

        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var pair in data.Split('&'))
        {
            if (pair.Length == 0)
            {
                continue;
            }

            var eq = pair.IndexOf('=');
            var key = Decode(eq >= 0 ? pair[..eq] : pair);
            var value = eq >= 0 ? Decode(pair[(eq + 1)..]) : string.Empty;
            if (!seen.Add(key))
            {
                continue;
            }

            switch (key)
            {
                case "challengeAlgorithm":
                    vd.ChallengeAlgorithm = value;
                    break;
                case "classification":
                    vd.Classification = value;
                    break;
                case "expire":
                    vd.Expire = ParseInt64(value);
                    break;
                case "fields":
                    vd.Fields = ParseList(value);
                    break;
                case "fieldsHash":
                    vd.FieldsHash = value;
                    break;
                case "id":
                    vd.Id = value;
                    break;
                case "ipAddress":
                    vd.IpAddress = value;
                    break;
                case "origin":
                    vd.Origin = value;
                    break;
                case "penalty":
                    vd.Penalty = ParseDouble(value);
                    break;
                case "reasons":
                    vd.Reasons = ParseList(value);
                    break;
                case "score":
                    vd.Score = ParseDouble(value);
                    break;
                case "time":
                    vd.Time = ParseInt64(value);
                    break;
                case "verified":
                    vd.Verified = value == "true";
                    break;
                default:
                    var dot = key.IndexOf('.');
                    if (dot <= 0 || !SetGroupValue(vd, key[..dot], key[(dot + 1)..], value))
                    {
                        vd.Extra = AddExtra(vd.Extra, key, value);
                    }

                    break;
            }
        }

        return vd;
    }

    /// <summary>Sets <c>group.name</c>; returns false when <paramref name="group"/> is not a Sentinel group.</summary>
    private static bool SetGroupValue(ServerSignatureVerificationData vd, string group, string name, string value)
    {
        switch (group)
        {
            case "location":
                var location = vd.Location ??= new SentinelLocation();
                switch (name)
                {
                    case "countryCode":
                        location.CountryCode = value;
                        break;
                    case "score":
                        location.Score = ParseDouble(value);
                        break;
                    case "timeZone":
                        location.TimeZone = value;
                        break;
                    case "triggeredRules":
                        location.TriggeredRules = ParseList(value);
                        break;
                    default:
                        location.Extra = AddExtra(location.Extra, name, value);
                        break;
                }

                return true;
            case "device":
                var device = vd.Device ??= new SentinelDevice();
                switch (name)
                {
                    case "browser":
                        device.Browser = value;
                        break;
                    case "edk":
                        device.Edk = value;
                        break;
                    case "type":
                        device.Type = value;
                        break;
                    default:
                        device.Extra = AddExtra(device.Extra, name, value);
                        break;
                }

                return true;
            case "text":
                var text = vd.Text ??= new SentinelText();
                switch (name)
                {
                    case "language":
                        text.Language = value;
                        break;
                    case "score":
                        text.Score = ParseDouble(value);
                        break;
                    case "triggeredRules":
                        text.TriggeredRules = ParseList(value);
                        break;
                    default:
                        text.Extra = AddExtra(text.Extra, name, value);
                        break;
                }

                return true;
            case "email":
                vd.Email = SetCheckValue(vd.Email ?? new SentinelCheck(), name, value);
                return true;
            case "ip":
                vd.Ip = SetCheckValue(vd.Ip ?? new SentinelCheck(), name, value);
                return true;
            case "params":
                var parameters = vd.Params as Dictionary<string, string> ?? new Dictionary<string, string>(StringComparer.Ordinal);
                parameters.TryAdd(name, value);
                vd.Params = parameters;
                return true;
            default:
                return false;
        }
    }

    private static SentinelCheck SetCheckValue(SentinelCheck check, string name, string value)
    {
        switch (name)
        {
            case "score":
                check.Score = ParseDouble(value);
                break;
            case "triggeredRules":
                check.TriggeredRules = ParseList(value);
                break;
            default:
                check.Extra = AddExtra(check.Extra, name, value);
                break;
        }

        return check;
    }

    private static Dictionary<string, JsonElement> AddExtra(Dictionary<string, JsonElement>? extra, string key, string value)
    {
        extra ??= new Dictionary<string, JsonElement>(StringComparer.Ordinal);
        extra[key] = JsonSerializer.SerializeToElement(value);
        return extra;
    }

    private static string[] ParseList(string value) => value.Length > 0 ? value.Split(',') : [];

    private static long? ParseInt64(string value) =>
        long.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var result) ? result : null;

    private static double? ParseDouble(string value) =>
        double.TryParse(value, NumberStyles.Float, CultureInfo.InvariantCulture, out var result) ? result : null;

    /// <summary>Verifies a server-signature payload with the Sentinel API secret.</summary>
    /// <exception cref="AltchaException">The payload's algorithm is unsupported.</exception>
    public static VerifyServerSignatureResult Verify(ServerSignaturePayload payload, string hmacSecret)
    {
        ArgumentNullException.ThrowIfNull(payload);
        ArgumentNullException.ThrowIfNull(hmacSecret);
        var start = Stopwatch.GetTimestamp();
        if (!AltchaHashAlgorithmExtensions.TryParse(payload.Algorithm, out var algorithm))
        {
            throw new AltchaException($"Unsupported algorithm: {payload.Algorithm}");
        }

        var verificationData = payload.VerificationData ?? string.Empty;
        var expected = AltchaCrypto.HmacHex(algorithm, AltchaCrypto.Hash(algorithm, Encoding.UTF8.GetBytes(verificationData)), hmacSecret);
        var vd = ParseVerificationData(verificationData);

        var expired = vd.Expire > 0 && vd.Expire < DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var invalidSignature = !AltchaCrypto.ConstantTimeEquals(payload.Signature, expected);
        var invalidSolution = !vd.Verified || !payload.Verified;

        return new VerifyServerSignatureResult
        {
            Verified = !expired && !invalidSignature && !invalidSolution,
            Expired = expired,
            InvalidSignature = invalidSignature,
            InvalidSolution = invalidSolution,
            Time = (long)Stopwatch.GetElapsedTime(start).TotalMilliseconds,
            VerificationData = vd,
        };
    }

    /// <summary>Verifies a base64-encoded JSON server-signature payload with the Sentinel API secret.</summary>
    /// <exception cref="AltchaException">The payload is not valid base64 JSON, or its algorithm is unsupported.</exception>
    public static VerifyServerSignatureResult Verify(string base64Payload, string hmacSecret)
    {
        ArgumentNullException.ThrowIfNull(base64Payload);
        ServerSignaturePayload? payload;
        try
        {
            payload = JsonSerializer.Deserialize<ServerSignaturePayload>(Convert.FromBase64String(base64Payload), AltchaJson.SerializerOptions);
        }
        catch (Exception e) when (e is FormatException or JsonException)
        {
            throw new AltchaException("Invalid server signature payload.", e);
        }

        return Verify(payload ?? throw new AltchaException("Invalid server signature payload."), hmacSecret);
    }

    /// <summary>
    /// Verifies <c>fieldsHash</c>: the hex hash of the listed fields' values joined with <c>\n</c>
    /// (missing fields contribute an empty line).
    /// </summary>
    public static bool VerifyFieldsHash(
        Func<string, string?> getFieldValue,
        IEnumerable<string> fields,
        string fieldsHash,
        AltchaHashAlgorithm algorithm = AltchaHashAlgorithm.Sha256)
    {
        ArgumentNullException.ThrowIfNull(getFieldValue);
        ArgumentNullException.ThrowIfNull(fields);
        var joined = string.Join("\n", fields.Select(f => getFieldValue(f) ?? string.Empty));
        return AltchaCrypto.ConstantTimeEquals(AltchaCrypto.ToHex(AltchaCrypto.Hash(algorithm, Encoding.UTF8.GetBytes(joined))), fieldsHash);
    }

    /// <summary>Verifies <c>fieldsHash</c> against a dictionary of form values.</summary>
    public static bool VerifyFieldsHash(
        IReadOnlyDictionary<string, string?> formData,
        IEnumerable<string> fields,
        string fieldsHash,
        AltchaHashAlgorithm algorithm = AltchaHashAlgorithm.Sha256)
    {
        ArgumentNullException.ThrowIfNull(formData);
        return VerifyFieldsHash(f => formData.TryGetValue(f, out var v) ? v : null, fields, fieldsHash, algorithm);
    }

    private static string Decode(string s) => Uri.UnescapeDataString(s.Replace('+', ' '));
}
