using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Altcha.Serialization;

/// <summary>Reads strings, and numbers or booleans as their raw JSON text.</summary>
internal sealed class LenientStringConverter : JsonConverter<string?>
{
    public override string? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) =>
        LenientReader.ReadScalarAsString(ref reader);

    public override void Write(Utf8JsonWriter writer, string? value, JsonSerializerOptions options)
    {
        if (value is null)
        {
            writer.WriteNullValue();
        }
        else
        {
            writer.WriteStringValue(value);
        }
    }
}

/// <summary>Reads a JSON array of scalars, or a comma-separated string.</summary>
internal sealed class LenientStringListConverter : JsonConverter<IReadOnlyList<string>?>
{
    public override IReadOnlyList<string>? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        switch (reader.TokenType)
        {
            case JsonTokenType.StartArray:
                var list = new List<string>();
                while (reader.Read() && reader.TokenType != JsonTokenType.EndArray)
                {
                    var item = LenientReader.ReadScalarAsString(ref reader);
                    if (item is not null)
                    {
                        list.Add(item);
                    }
                }

                return list;
            case JsonTokenType.String:
                var s = reader.GetString();
                return string.IsNullOrEmpty(s) ? [] : s.Split(',');
            default:
                reader.Skip();
                return null;
        }
    }

    public override void Write(Utf8JsonWriter writer, IReadOnlyList<string>? value, JsonSerializerOptions options)
    {
        if (value is null)
        {
            writer.WriteNullValue();
            return;
        }

        writer.WriteStartArray();
        foreach (var item in value)
        {
            writer.WriteStringValue(item);
        }

        writer.WriteEndArray();
    }
}

/// <summary>Reads a number (fractional values truncated) or a numeric string.</summary>
internal sealed class LenientInt64Converter : JsonConverter<long?>
{
    public override long? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        switch (reader.TokenType)
        {
            case JsonTokenType.Number:
                return reader.TryGetInt64(out var l) ? l : Truncate(reader.GetDouble());
            case JsonTokenType.String:
                var s = reader.GetString();
                if (long.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out l))
                {
                    return l;
                }

                return double.TryParse(s, NumberStyles.Float, CultureInfo.InvariantCulture, out var d) ? Truncate(d) : null;
            default:
                reader.Skip();
                return null;
        }
    }

    public override void Write(Utf8JsonWriter writer, long? value, JsonSerializerOptions options)
    {
        if (value is null)
        {
            writer.WriteNullValue();
        }
        else
        {
            writer.WriteNumberValue(value.Value);
        }
    }

    private static long? Truncate(double d) =>
        double.IsFinite(d) && d >= long.MinValue && d <= long.MaxValue ? (long)Math.Truncate(d) : null;
}

/// <summary>Reads a number or a numeric string.</summary>
internal sealed class LenientDoubleConverter : JsonConverter<double?>
{
    public override double? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        switch (reader.TokenType)
        {
            case JsonTokenType.Number:
                return reader.GetDouble();
            case JsonTokenType.String:
                return double.TryParse(reader.GetString(), NumberStyles.Float, CultureInfo.InvariantCulture, out var d) ? d : null;
            default:
                reader.Skip();
                return null;
        }
    }

    public override void Write(Utf8JsonWriter writer, double? value, JsonSerializerOptions options)
    {
        if (value is null)
        {
            writer.WriteNullValue();
        }
        else
        {
            writer.WriteNumberValue(value.Value);
        }
    }
}

/// <summary>Reads <c>true</c> or <c>"true"</c> as true; anything else as false.</summary>
internal sealed class LenientBooleanConverter : JsonConverter<bool>
{
    public override bool HandleNull => true;

    public override bool Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        switch (reader.TokenType)
        {
            case JsonTokenType.True:
                return true;
            case JsonTokenType.String:
                return reader.ValueTextEquals("true"u8);
            default:
                reader.Skip();
                return false;
        }
    }

    public override void Write(Utf8JsonWriter writer, bool value, JsonSerializerOptions options) =>
        writer.WriteBooleanValue(value);
}

/// <summary>Reads a JSON object as <typeparamref name="T"/>; any other token (e.g. a legacy string value) yields null.</summary>
internal sealed class LenientObjectConverter<T> : JsonConverter<T?>
    where T : class
{
    public override T? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType == JsonTokenType.StartObject)
        {
            // Applied per property, not per type, so this does not recurse into this converter.
            return JsonSerializer.Deserialize<T>(ref reader, options);
        }

        reader.Skip();
        return null;
    }

    public override void Write(Utf8JsonWriter writer, T? value, JsonSerializerOptions options) =>
        JsonSerializer.Serialize(writer, value, options);
}

/// <summary>Reads a JSON object of scalars as a string dictionary; nested containers are skipped.</summary>
internal sealed class LenientStringDictionaryConverter : JsonConverter<IReadOnlyDictionary<string, string>?>
{
    public override IReadOnlyDictionary<string, string>? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType != JsonTokenType.StartObject)
        {
            reader.Skip();
            return null;
        }

        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        while (reader.Read() && reader.TokenType != JsonTokenType.EndObject)
        {
            var name = reader.GetString()!;
            reader.Read();
            if (LenientReader.ReadScalarAsString(ref reader) is { } value)
            {
                result.TryAdd(name, value);
            }
        }

        return result;
    }

    public override void Write(Utf8JsonWriter writer, IReadOnlyDictionary<string, string>? value, JsonSerializerOptions options)
    {
        if (value is null)
        {
            writer.WriteNullValue();
            return;
        }

        writer.WriteStartObject();
        foreach (var (name, item) in value)
        {
            writer.WriteString(name, item);
        }

        writer.WriteEndObject();
    }
}

internal static class LenientReader
{
    /// <summary>Reads a scalar as a string; numbers and booleans become their raw JSON text. Containers are skipped.</summary>
    public static string? ReadScalarAsString(ref Utf8JsonReader reader)
    {
        switch (reader.TokenType)
        {
            case JsonTokenType.String:
                return reader.GetString();
            case JsonTokenType.Number:
                using (var doc = JsonDocument.ParseValue(ref reader))
                {
                    return doc.RootElement.GetRawText();
                }

            case JsonTokenType.True:
                return "true";
            case JsonTokenType.False:
                return "false";
            default:
                reader.Skip();
                return null;
        }
    }
}
