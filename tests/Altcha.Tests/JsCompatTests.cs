using System.Text;
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

    // altcha-lib (JS) v2: PBKDF2/SHA-256, cost 100, counter 7, secret "js-secret"; a custom deriveKey merged the
    // unknown parameters region:"eu" and z:{b:1,a:null} into the signed parameters.
    private const string JsExtraKeysPayload =
        "eyJjaGFsbGVuZ2UiOnsicGFyYW1ldGVycyI6eyJhbGdvcml0aG0iOiJQQktERjIvU0hBLTI1NiIsImNvc3QiOjEwMCwia2V5TGVuZ3RoIjozMiwia2V5UHJlZml4IjoiOGQ3NDk0OWZkODg1MzhkYjUwZGMyMmJhMjlmZWM2YmUiLCJub25jZSI6ImVhODcxMDJmMzFlNjdiMTRmMzJkNThmYWE0MjNmZmYxIiwicmVnaW9uIjoiZXUiLCJzYWx0IjoiYWI1NzAyNjk5NjAxNzU3MTUyYzZjZTZkMjEyMjljMjgiLCJ6Ijp7ImEiOm51bGwsImIiOjF9fSwic2lnbmF0dXJlIjoiOTM2NzcxMzAwNjI1Y2EyNzdhYzQzZWE1OTQ2ZTkyMjAyY2E1NzAzMTdmZGQ2YzViNTFjYzJjNDg3M2IxZTQ2MSJ9LCJzb2x1dGlvbiI6eyJjb3VudGVyIjo3LCJkZXJpdmVkS2V5IjoiOGQ3NDk0OWZkODg1MzhkYjUwZGMyMmJhMjlmZWM2YmU0MTE4NTRiZWQxZGMxYTc5N2UyNDE0MmY2YTBjNWQ3OCIsInRpbWUiOjAuMn19";

    [Theory]
    [InlineData(JsPayload)]
    [InlineData(JsFractionalExpiresAtPayload)]
    [InlineData(JsExtraKeysPayload)]
    public void VerifiesJsSignedChallenge(string base64)
    {
        var result = Verify(Encoding.UTF8.GetString(Convert.FromBase64String(base64)));

        Assert.False(result.InvalidSignature);
        Assert.True(result.Verified);
    }

    [Theory]
    [InlineData(JsFractionalExpiresAtPayload, "\"cost\":100", "\"cost\":\"100\"")]
    [InlineData(JsFractionalExpiresAtPayload, "\"cost\":100", "\"cost\":100,\"foo\":\"bar\"")]
    [InlineData(JsFractionalExpiresAtPayload, "\"keyLength\"", "\"KeyLength\"")]
    [InlineData(JsFractionalExpiresAtPayload, "\"cost\":100", "\"cost\":100,\"cost\":1")]
    [InlineData(JsExtraKeysPayload, "\"region\":\"eu\",", "")]
    [InlineData(JsExtraKeysPayload, "\"a\":null", "\"a\":0")]
    public void WireChangesToSignedParametersInvalidateSignature(string base64, string find, string replace)
    {
        var json = Encoding.UTF8.GetString(Convert.FromBase64String(base64));
        Assert.Contains(find, json);

        var result = Verify(json.Replace(find, replace));

        Assert.True(result.InvalidSignature);
        Assert.False(result.Verified);
    }

    [Fact]
    public void DuplicateKeyResolvesToLastValueLikeJsonParse()
    {
        var json = Encoding.UTF8.GetString(Convert.FromBase64String(JsFractionalExpiresAtPayload));

        var result = Verify(json.Replace("\"cost\":100", "\"cost\":1,\"cost\":100"));

        Assert.True(result.Verified);
    }

    private static VerifySolutionResult Verify(string json)
    {
        var payload = JsonSerializer.Deserialize<Payload>(json, AltchaJson.SerializerOptions)!;
        return AltchaPow.VerifySolution(new VerifySolutionOptions
        {
            Challenge = payload.Challenge,
            Solution = payload.Solution,
            HmacSignatureSecret = "js-secret",
        });
    }
}
