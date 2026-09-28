using System.Text.Json;

namespace Altcha.Tests;

public class CanonicalJsonTests
{
    [Fact]
    public void SerializesJsVector()
    {
        var parameters = new ChallengeParameters
        {
            Algorithm = "PBKDF2/SHA-256",
            Nonce = "39baf91a19d671f8231217f9e28342a6",
            Salt = "5e00d5d152e1a5db7d44fb6404a40a5e",
            KeyPrefix = "00",
            Cost = 1000,
            KeyLength = 32,
        };

        Assert.Equal(
            """{"algorithm":"PBKDF2/SHA-256","cost":1000,"keyLength":32,"keyPrefix":"00","nonce":"39baf91a19d671f8231217f9e28342a6","salt":"5e00d5d152e1a5db7d44fb6404a40a5e"}""",
            CanonicalJson.Serialize(parameters));
    }

    [Fact]
    public void OmitsEmptyOptionalFieldsButKeepsEmptyKeyPrefix()
    {
        var parameters = new ChallengeParameters
        {
            Algorithm = "SHA-256",
            Nonce = "aa",
            Salt = "bb",
            KeyPrefix = "",
            Cost = 1,
            KeyLength = 32,
            KeySignature = "",
            MemoryCost = 0,
            Parallelism = 0,
            ExpiresAt = 0,
            Data = [],
        };

        Assert.Equal(
            """{"algorithm":"SHA-256","cost":1,"keyLength":32,"keyPrefix":"","nonce":"aa","salt":"bb"}""",
            CanonicalJson.Serialize(parameters));
    }

    [Fact]
    public void SortsNestedDataAndEscapesLikeJavaScript()
    {
        var parameters = new ChallengeParameters
        {
            Algorithm = "SHA-256",
            Nonce = "aa",
            Salt = "bb",
            KeyPrefix = "00",
            Cost = 1,
            KeyLength = 32,
            Data = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>("""{"z":1,"a":{"y":"<&>é","b":"\u0001"}}"""),
        };

        var json = CanonicalJson.Serialize(parameters);

        Assert.Contains("""
            "data":{"a":{"b":"\u0001","y":"<&>é"},"z":1}
            """, json, StringComparison.Ordinal);
    }

    [Fact]
    public void EscapesControlCharactersAndLoneSurrogates()
    {
        var parameters = new ChallengeParameters
        {
            Nonce = "\ud800x\U0001F600\udc00",
            Data = new Dictionary<string, JsonElement>
            {
                ["s"] = JsonSerializer.SerializeToElement("q\"\\\b\f\n\r\t\u001f/'x\U0001F600"),
            },
        };

        var json = CanonicalJson.Serialize(parameters);

        Assert.Contains("""
            "data":{"s":"q\"\\\b\f\n\r\t\u001f/'x😀"}
            """, json, StringComparison.Ordinal);
        Assert.Contains("""
            "nonce":"\ud800x😀\udc00"
            """, json, StringComparison.Ordinal);
    }

    [Fact]
    public void UndecodableDataStringIsAnAltchaException()
    {
        var parameters = new ChallengeParameters
        {
            Data = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>("""{"s":"\ud800"}"""),
        };

        Assert.Throws<AltchaException>(() => CanonicalJson.Serialize(parameters));
    }

    [Fact]
    public void OrdersArrayIndexKeysFirstLikeJavaScriptObjects()
    {
        var parameters = new ChallengeParameters
        {
            Data = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>("""{"b":1,"10":2,"a":3,"9":4,"01":5}"""),
        };

        Assert.Contains("""
            "data":{"9":4,"10":2,"01":5,"a":3,"b":1}
            """, CanonicalJson.Serialize(parameters), StringComparison.Ordinal);
    }

    [Fact]
    public void KeepsDocumentOrderBelowArraysLikeJavaScript()
    {
        // Wire JSON and expected output produced by altcha-lib's canonicalJSON: nothing below an array is sorted,
        // but JSON.stringify still emits array-index keys first.
        var parameters = new ChallengeParameters
        {
            Data = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(
                """{"7":"n","z":1,"list":[{"2":0,"10":0,"z":1,"a":{"y":2,"b":3},"arr":[{"d":1,"c":2}]},"s",3],"a":{"q":[{"y":1,"x":2}],"b":1}}"""),
        };

        Assert.Contains("""
            "data":{"7":"n","a":{"b":1,"q":[{"y":1,"x":2}]},"list":[{"2":0,"10":0,"z":1,"a":{"y":2,"b":3},"arr":[{"d":1,"c":2}]},"s",3],"z":1}
            """, CanonicalJson.Serialize(parameters), StringComparison.Ordinal);
    }

    [Fact]
    public void HoistsIndexKeysBelowArraysEvenWhenOutOfDocumentOrder()
    {
        var parameters = new ChallengeParameters
        {
            Data = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>("""{"list":[{"b":1,"10":2,"a":3,"2":4}]}"""),
        };

        Assert.Contains("""
            "data":{"list":[{"2":4,"10":2,"b":1,"a":3}]}
            """, CanonicalJson.Serialize(parameters), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(1e21, "1e+21")]
    [InlineData(1e20, "100000000000000000000")]
    [InlineData(0.1, "0.1")]
    [InlineData(1.5e-7, "1.5e-7")]
    [InlineData(123.456, "123.456")]
    [InlineData(-1e-7, "-1e-7")]
    [InlineData(0.000001, "0.000001")]
    [InlineData(-0.0, "0")]
    [InlineData(1.7976931348623157e308, "1.7976931348623157e+308")]
    [InlineData(5e-324, "5e-324")]
    public void FormatsNumbersLikeJavaScript(double input, string expected) =>
        Assert.Equal(expected, JsNumber.Format(input));
}
