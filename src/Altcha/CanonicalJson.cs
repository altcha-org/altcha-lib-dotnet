using System.Globalization;
using System.Text;
using System.Text.Json;

namespace Altcha;

/// <summary>
/// Serializes challenge parameters byte-compatibly with the JS <c>canonicalJSON</c>
/// (<c>JSON.stringify(sortKeys(obj))</c>): object keys are sorted recursively, except below arrays, where
/// document order is kept. This string is what challenge signatures cover.
/// </summary>
internal static class CanonicalJson
{
    // Largest integer a JS number represents exactly; beyond it JS would round, so format as a double.
    private const long MaxSafeInteger = 9007199254740991;

    public static string Serialize(ChallengeParameters p)
    {
        var sb = new StringBuilder(256);
        sb.Append('{');
        WriteKey(sb, "algorithm", first: true);
        WriteString(sb, p.Algorithm);
        WriteKey(sb, "cost");
        sb.Append(p.Cost.ToString(CultureInfo.InvariantCulture));
        if (p.Data is { Count: > 0 })
        {
            WriteKey(sb, "data");
            try
            {
                WriteObject(sb, p.Data, sortKeys: true);
            }
            catch (InvalidOperationException e)
            {
                // JsonElement refuses to decode strings containing lone surrogate escapes.
                throw new AltchaException("Invalid challenge data.", e);
            }
        }

        if (p.ExpiresAt is { } expiresAt and not 0)
        {
            WriteKey(sb, "expiresAt");
            sb.Append(double.IsFinite(expiresAt) ? JsNumber.Format(expiresAt) : "null");
        }

        WriteKey(sb, "keyLength");
        sb.Append(p.KeyLength.ToString(CultureInfo.InvariantCulture));
        WriteKey(sb, "keyPrefix");
        WriteString(sb, p.KeyPrefix ?? string.Empty);
        if (!string.IsNullOrEmpty(p.KeySignature))
        {
            WriteKey(sb, "keySignature");
            WriteString(sb, p.KeySignature);
        }

        if (p.MemoryCost is { } memoryCost and not 0)
        {
            WriteKey(sb, "memoryCost");
            sb.Append(memoryCost.ToString(CultureInfo.InvariantCulture));
        }

        WriteKey(sb, "nonce");
        WriteString(sb, p.Nonce);
        if (p.Parallelism is { } parallelism and not 0)
        {
            WriteKey(sb, "parallelism");
            sb.Append(parallelism.ToString(CultureInfo.InvariantCulture));
        }

        WriteKey(sb, "salt");
        WriteString(sb, p.Salt);
        sb.Append('}');
        return sb.ToString();
    }

    /// <summary>Serializes a received parameters object exactly as JS signs its parsed form.</summary>
    public static string Serialize(JsonElement parameters)
    {
        var sb = new StringBuilder(256);
        try
        {
            WriteElement(sb, parameters, sortKeys: true);
        }
        catch (InvalidOperationException e)
        {
            // JsonElement refuses to decode strings containing lone surrogate escapes.
            throw new AltchaException("Invalid challenge parameters.", e);
        }

        return sb.ToString();
    }

    private static void WriteKey(StringBuilder sb, string key, bool first = false)
    {
        if (!first)
        {
            sb.Append(',');
        }

        WriteString(sb, key);
        sb.Append(':');
    }

    /// <summary>
    /// Writes an object's properties in the order a JS object enumerates them: array-index keys first in ascending
    /// numeric order, then all other keys, sorted by UTF-16 code units when <paramref name="sortKeys"/> is true,
    /// otherwise in document order. JS <c>sortKeys</c> leaves everything below an array unsorted, but
    /// <c>JSON.stringify</c> still hoists index keys there. Duplicate keys collapse like <c>JSON.parse</c>:
    /// the last value wins at the position of the first occurrence.
    /// </summary>
    private static void WriteObject(StringBuilder sb, IEnumerable<KeyValuePair<string, JsonElement>> properties, bool sortKeys)
    {
        var unique = new List<KeyValuePair<string, JsonElement>>();
        var positions = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (var property in properties)
        {
            if (positions.TryGetValue(property.Key, out var position))
            {
                unique[position] = property;
            }
            else
            {
                positions.Add(property.Key, unique.Count);
                unique.Add(property);
            }
        }

        // OrderBy is stable, so non-index keys (all mapped to uint.MaxValue, never a valid index) keep document order.
        var ordered = unique.OrderBy(static p => TryGetArrayIndex(p.Key, out var index) ? index : uint.MaxValue);
        if (sortKeys)
        {
            ordered = ordered.ThenBy(static p => p.Key, StringComparer.Ordinal);
        }

        sb.Append('{');
        var first = true;
        foreach (var (key, value) in ordered)
        {
            WriteKey(sb, key, first);
            first = false;
            WriteElement(sb, value, sortKeys);
        }

        sb.Append('}');
    }

    private static bool TryGetArrayIndex(string key, out uint index)
    {
        index = 0;
        if (key.Length is 0 or > 10 || (key.Length > 1 && key[0] == '0'))
        {
            return false;
        }

        foreach (var c in key)
        {
            if (c is < '0' or > '9')
            {
                return false;
            }
        }

        return uint.TryParse(key, NumberStyles.None, CultureInfo.InvariantCulture, out index) && index != uint.MaxValue;
    }

    private static void WriteElement(StringBuilder sb, JsonElement element, bool sortKeys)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                WriteObject(sb, element.EnumerateObject().Select(static p => new KeyValuePair<string, JsonElement>(p.Name, p.Value)), sortKeys);
                break;
            case JsonValueKind.Array:
                sb.Append('[');
                var first = true;
                foreach (var item in element.EnumerateArray())
                {
                    if (!first)
                    {
                        sb.Append(',');
                    }

                    first = false;
                    WriteElement(sb, item, sortKeys: false);
                }

                sb.Append(']');
                break;
            case JsonValueKind.String:
                WriteString(sb, element.GetString());
                break;
            case JsonValueKind.Number:
                if (element.TryGetInt64(out var l) && l is >= -MaxSafeInteger and <= MaxSafeInteger)
                {
                    sb.Append(l.ToString(CultureInfo.InvariantCulture));
                }
                else
                {
                    sb.Append(JsNumber.Format(element.GetDouble()));
                }

                break;
            case JsonValueKind.True:
                sb.Append("true");
                break;
            case JsonValueKind.False:
                sb.Append("false");
                break;
            default:
                sb.Append("null");
                break;
        }
    }

    /// <summary>Writes a JSON string escaped exactly like JS <c>JSON.stringify</c>.</summary>
    private static void WriteString(StringBuilder sb, string? value)
    {
        if (value is null)
        {
            sb.Append("null");
            return;
        }

        sb.Append('"');
        for (var i = 0; i < value.Length; i++)
        {
            var c = value[i];
            switch (c)
            {
                case '"':
                    sb.Append("\\\"");
                    break;
                case '\\':
                    sb.Append("\\\\");
                    break;
                case '\b':
                    sb.Append("\\b");
                    break;
                case '\f':
                    sb.Append("\\f");
                    break;
                case '\n':
                    sb.Append("\\n");
                    break;
                case '\r':
                    sb.Append("\\r");
                    break;
                case '\t':
                    sb.Append("\\t");
                    break;
                default:
                    if (c < 0x20)
                    {
                        AppendUnicodeEscape(sb, c);
                    }
                    else if (char.IsHighSurrogate(c))
                    {
                        if (i + 1 < value.Length && char.IsLowSurrogate(value[i + 1]))
                        {
                            sb.Append(c).Append(value[++i]);
                        }
                        else
                        {
                            AppendUnicodeEscape(sb, c);
                        }
                    }
                    else if (char.IsLowSurrogate(c))
                    {
                        AppendUnicodeEscape(sb, c);
                    }
                    else
                    {
                        sb.Append(c);
                    }

                    break;
            }
        }

        sb.Append('"');
    }

    private static void AppendUnicodeEscape(StringBuilder sb, char c) =>
        sb.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
}
