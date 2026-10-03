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

    // altcha-lib (JS) v2: PBKDF2/SHA-256, cost 100, counter 7, secret "js-secret", expiresAt 4102444800.123.
    private const string JsFractionalExpiresAtPayload =
        "eyJjaGFsbGVuZ2UiOnsicGFyYW1ldGVycyI6eyJhbGdvcml0aG0iOiJQQktERjIvU0hBLTI1NiIsImNvc3QiOjEwMCwiZXhwaXJlc0F0Ijo0MTAyNDQ0ODAwLjEyMywia2V5TGVuZ3RoIjozMiwia2V5UHJlZml4IjoiYzY4NjY1MzFmZjM0NWI4M2JmNjdlOTkxYWEwNTk1MGEiLCJub25jZSI6ImY2OTNiMTNiZmI3ZjYyNTNjOGIyZjhkMGNhMGFhMDlmIiwic2FsdCI6ImM3NGQ3YzQ1MjU1Y2JkMWM2ZDdkM2ZmYjg4YWVkY2E5In0sInNpZ25hdHVyZSI6IjRkNzQ1MDA1ODY2MjcyOGVhYjZlNDFiZDE3MTFkOTI5NTdhNTYzYWZkMTBjNGMxMjJjYjliZmMyOTc1MTJkODAifSwic29sdXRpb24iOnsiY291bnRlciI6NywiZGVyaXZlZEtleSI6ImM2ODY2NTMxZmYzNDViODNiZjY3ZTk5MWFhMDU5NTBhYzI0ZTM4OTBhMDNiMmRmZmFmYzIyNTU4YTZkYzg1MTIiLCJ0aW1lIjowLjJ9fQ==";

    [Theory]
    [InlineData(JsPayload)]
    [InlineData(JsFractionalExpiresAtPayload)]
    public void VerifiesJsSignedChallenge(string base64)
    {
        var payload = JsonSerializer.Deserialize<Payload>(Convert.FromBase64String(base64), AltchaJson.SerializerOptions)!;

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
