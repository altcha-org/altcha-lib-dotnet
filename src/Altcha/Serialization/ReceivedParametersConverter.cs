using System.Text.Json;
using System.Text.Json.Serialization;

namespace Altcha.Serialization;

/// <summary>
/// Reads <see cref="ChallengeParameters"/> and keeps the received JSON object, which is what the signature is
/// verified against (JS signs the parameters exactly as parsed, including unknown keys and their JSON types).
/// </summary>
internal sealed class ReceivedParametersConverter : JsonConverter<ChallengeParameters>
{
    public override ChallengeParameters Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        var json = JsonElement.ParseValue(ref reader);
        if (json.ValueKind != JsonValueKind.Object)
        {
            throw new JsonException("Challenge parameters must be a JSON object.");
        }

        var parameters = json.Deserialize<ChallengeParameters>(options)!;
        parameters.ReceivedJson = json;
        return parameters;
    }

    public override void Write(Utf8JsonWriter writer, ChallengeParameters value, JsonSerializerOptions options) =>
        JsonSerializer.Serialize(writer, value, options);
}
