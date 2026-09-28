using System.Text.Json;

namespace Altcha.Tests;

/// <summary>
/// Verifies a payload created, signed and solved by altcha-lib (JS) v2: PBKDF2/SHA-256, cost 100, counter 321,
/// secret "js-secret", data {z:1, list:[{z:1, a:{y:2,b:3}, 10:0, 2:0, arr:[{d:1,c:2}]}, "s", 3], a:{q:[{y:1,x:2}], b:1}}.
/// The arrays hold objects whose keys JS signs unsorted.
/// </summary>
public class JsCompatTests
{
    private const string JsPayload =
        "eyJjaGFsbGVuZ2UiOnsicGFyYW1ldGVycyI6eyJhbGdvcml0aG0iOiJQQktERjIvU0hBLTI1NiIsImNvc3QiOjEwMCwiZGF0YSI6eyJhIjp7ImIiOjEsInEiOlt7InkiOjEsIngiOjJ9XX0sImxpc3QiOlt7IjIiOjAsIjEwIjowLCJ6IjoxLCJhIjp7InkiOjIsImIiOjN9LCJhcnIiOlt7ImQiOjEsImMiOjJ9XX0sInMiLDNdLCJ6IjoxfSwia2V5TGVuZ3RoIjozMiwia2V5UHJlZml4IjoiMTY0YmViZDM5ZjU4NTUyYzQ0ZTViNGQzZWFhOGY4MTQiLCJub25jZSI6ImViNTc2NmViZDRmMjMwMTQ2MjhhN2Y1NTQyODcxZThiIiwic2FsdCI6IjY1YzRiMjdkMTYwODM3NzI1ZjRiNmIzZGM3ZWFjMWFlIn0sInNpZ25hdHVyZSI6Ijc5YTc0ZThhMTMxOTIxZTkwYWNkYzRjZjFlNWIwYjQ2YzY0NTkwYzVjOGExNzY4NjY1ODQyZGUzNGM3MzdkYTcifSwic29sdXRpb24iOnsiY291bnRlciI6MzIxLCJkZXJpdmVkS2V5IjoiMTY0YmViZDM5ZjU4NTUyYzQ0ZTViNGQzZWFhOGY4MTRmNTc4NDZiNmIwNWZkOWFhMGVhNjAzYTBiM2NiYjY1MCIsInRpbWUiOjUuN319";

    [Fact]
    public void VerifiesJsSignedChallengeWithArrayData()
    {
        var payload = JsonSerializer.Deserialize<Payload>(Convert.FromBase64String(JsPayload), AltchaJson.SerializerOptions)!;

        var result = AltchaPow.VerifySolution(new VerifySolutionOptions
        {
            Challenge = payload.Challenge,
            Solution = payload.Solution,
            HmacSignatureSecret = "js-secret",
        });

        Assert.False(result.InvalidSignature);
        Assert.True(result.Verified);
    }
}
