using System.Text.Json;
using System.Text.Json.Serialization;

namespace Altcha;

/// <summary>Shared JSON settings for ALTCHA wire formats.</summary>
public static class AltchaJson
{
    /// <summary>Web defaults (camelCase, case-insensitive) that omit null values. Read-only.</summary>
    public static JsonSerializerOptions SerializerOptions { get; } = CreateOptions();

    private static JsonSerializerOptions CreateOptions()
    {
        var options = new JsonSerializerOptions(JsonSerializerDefaults.Web)
        {
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        };
        options.MakeReadOnly(populateMissingResolver: true);
        return options;
    }
}
