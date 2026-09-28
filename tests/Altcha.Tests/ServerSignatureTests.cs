using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Altcha.Tests;

public class ServerSignatureTests
{
    private const string Key = "test-key";

    private static long Now => DateTimeOffset.UtcNow.ToUnixTimeSeconds();

    [Fact]
    public void ValidSignatureVerifiesAndParsesData()
    {
        var data = $"expire={Now + 600}&fields=field1,field2&reasons=reason1,reason2&score=3&time={Now}&verified=true&abc=123&id=v1";

        var result = ServerSignature.Verify(Sign(data), Key);

        Assert.True(result.Verified);
        Assert.False(result.Expired);
        Assert.False(result.InvalidSignature);
        Assert.False(result.InvalidSolution);
        var vd = result.VerificationData!;
        Assert.Equal("123", vd.Extra!["abc"].GetString());
        Assert.Equal("v1", vd.Id);
        Assert.False(vd.Extra.ContainsKey("id"));
        Assert.Equal(["field1", "field2"], vd.Fields);
        Assert.Equal(2, vd.Reasons!.Count);
        Assert.Equal(3, vd.Score);
    }

    [Fact]
    public void InvalidSignatureIsRejected()
    {
        var payload = Sign($"expire={Now + 600}&verified=true");
        payload.Signature = "invalidSignature";

        var result = ServerSignature.Verify(payload, Key);

        Assert.True(result.InvalidSignature);
        Assert.False(result.Verified);
    }

    [Fact]
    public void ExpiredPayloadIsRejected()
    {
        var result = ServerSignature.Verify(Sign($"expire={Now - 600}&verified=true"), Key);

        Assert.True(result.Expired);
        Assert.False(result.Verified);
    }

    [Fact]
    public void UnverifiedSolutionIsRejected()
    {
        var payload = Sign($"expire={Now + 600}&verified=false");
        payload.Verified = false;

        var result = ServerSignature.Verify(payload, Key);

        Assert.True(result.InvalidSolution);
        Assert.False(result.Verified);
    }

    [Fact]
    public void Base64OverloadVerifies()
    {
        var json = JsonSerializer.SerializeToUtf8Bytes(Sign($"expire={Now + 600}&verified=true"), AltchaJson.SerializerOptions);

        Assert.True(ServerSignature.Verify(Convert.ToBase64String(json), Key).Verified);
        Assert.Throws<AltchaException>(() => ServerSignature.Verify("!!not base64", Key));
    }

    [Fact]
    public void UnsupportedAlgorithmThrows()
    {
        var payload = Sign("verified=true");
        payload.Algorithm = "MD5";

        Assert.Throws<AltchaException>(() => ServerSignature.Verify(payload, Key));
    }

    [Fact]
    public void ParsesRealSentinelVerificationData()
    {
        const string data =
            "location.countryCode=id&location.score=0&location.timeZone=Asia%2FMakassar&location.triggeredRules=&id=1k38phtgs00b1u0d28n&classification=GOOD&challengeAlgorithm=PBKDF2%2FSHA-256&device.browser=Firefox&device.edk=655a58a14d7ece290c57f62ac03d18f4&device.type=desktop&expire=1790224057&ipAddress=38.86.221.134&penalty=0&origin=http%3A%2F%2Flocalhost%3A5081&reasons=&score=0&time=1790222859&verified=true";

        var vd = ServerSignature.ParseVerificationData(data);

        Assert.Equal("id", vd.Location!.CountryCode);
        Assert.Equal("Asia/Makassar", vd.Location.TimeZone);
        Assert.Equal(0, vd.Location.Score);
        Assert.Empty(vd.Location.TriggeredRules!);
        Assert.Equal("Firefox", vd.Device!.Browser);
        Assert.Equal("desktop", vd.Device.Type);
        Assert.Equal("655a58a14d7ece290c57f62ac03d18f4", vd.Device.Edk);
        Assert.Equal("PBKDF2/SHA-256", vd.ChallengeAlgorithm);
        Assert.Equal("http://localhost:5081", vd.Origin);
        Assert.Equal(0, vd.Penalty);
        Assert.Empty(vd.Reasons!);
        Assert.Equal("1k38phtgs00b1u0d28n", vd.Id);
        Assert.Equal(1790224057, vd.Expire);
        Assert.True(vd.Verified);
        Assert.Null(vd.Extra);
    }

    [Fact]
    public void ParsesOptionalGroupsAndUnknownKeys()
    {
        var vd = ServerSignature.ParseVerificationData(
            "text.language=en&text.triggeredRules=a,b&email.score=1.5&ip.triggeredRules=vpn&params.plan=pro&location.future=x&misc.key=y&flag");

        Assert.Equal("en", vd.Text!.Language);
        Assert.Equal(["a", "b"], vd.Text.TriggeredRules!);
        Assert.Equal(1.5, vd.Email!.Score);
        Assert.Equal(["vpn"], vd.Ip!.TriggeredRules!);
        Assert.Equal("pro", vd.Params!["plan"]);
        Assert.Equal("x", vd.Location!.Extra!["future"].GetString());
        Assert.Equal("y", vd.Extra!["misc.key"].GetString());
        Assert.Equal("", vd.Extra["flag"].GetString());
    }

    [Fact]
    public void ParseDecodesAndKeepsFirstDuplicate()
    {
        var vd = ServerSignature.ParseVerificationData("origin=a%40b.c&location.timeZone=Europe%2FPrague&location.timeZone=XX&classification=C+Z");

        Assert.Equal("a@b.c", vd.Origin);
        Assert.Equal("Europe/Prague", vd.Location!.TimeZone);
        Assert.Equal("C Z", vd.Classification);
    }

    [Fact]
    public void VerifyFieldsHashMatchesGoVector()
    {
        var hash = Convert.ToHexString(SHA256.HashData("John Doe\njohn@example.com"u8)).ToLowerInvariant();
        var form = new Dictionary<string, string?> { ["name"] = "John Doe", ["email"] = "john@example.com" };

        Assert.True(ServerSignature.VerifyFieldsHash(form, ["name", "email"], hash));
        Assert.False(ServerSignature.VerifyFieldsHash(form, ["email", "name"], hash));
    }

    private static ServerSignaturePayload Sign(string verificationData)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(verificationData));
        var signature = Convert.ToHexString(HMACSHA256.HashData(Encoding.UTF8.GetBytes(Key), hash)).ToLowerInvariant();
        return new ServerSignaturePayload
        {
            Algorithm = "SHA-256",
            VerificationData = verificationData,
            Signature = signature,
            Verified = true,
        };
    }
}
