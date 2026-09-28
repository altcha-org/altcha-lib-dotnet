using System.Text.Json;

namespace Altcha.Tests;

/// <summary>Verifies a payload created and solved by altcha-lib-go v2 (PBKDF2/SHA-256, cost 100, counter 1234, data {foo:"bar",n:42}).</summary>
public class GoCompatTests
{
    private const string GoPayload =
        "eyJjaGFsbGVuZ2UiOnsicGFyYW1ldGVycyI6eyJhbGdvcml0aG0iOiJQQktERjIvU0hBLTI1NiIsIm5vbmNlIjoiNmE1MGQ1NjRmNGE2YjIyZGJhOGFiMTMwIiwic2FsdCI6ImRkZDJhY2Y0YTE4MmU2OGEzYjMxNzM2ZiIsImNvc3QiOjEwMCwia2V5TGVuZ3RoIjozMiwia2V5UHJlZml4IjoiY2RjNzA4YzI2ZDU4YzFjOGI5NzMwYjFhNmY0ODM3ZTYiLCJrZXlTaWduYXR1cmUiOiJkY2MwNmQwYzllZTAyOTE4OWQ0ZThmYjY0MDYyNTYxMjc0YWRjNzZkM2U1NjYzY2I0MGI0M2Y0NzE2MDA1NDlkIiwiZGF0YSI6eyJmb28iOiJiYXIiLCJuIjo0Mn19LCJzaWduYXR1cmUiOiIzMWYwZTNlNzllYzRlYzNkYWI1YzhkZWU1OGZlZjM3MTM4Y2U3YTM3ZmRhNDk0M2E1Yzg1M2I4Yzg0MDgyODUyIn0sInNvbHV0aW9uIjp7ImNvdW50ZXIiOjEyMzQsImRlcml2ZWRLZXkiOiJjZGM3MDhjMjZkNThjMWM4Yjk3MzBiMWE2ZjQ4MzdlNjA0YTY3YWQyZGU2M2Y5ZjE1N2Q3MThkZWNjZDQ2ZmVjIiwidGltZSI6MTJ9fQ==";

    private static readonly Payload Payload =
        JsonSerializer.Deserialize<Payload>(Convert.FromBase64String(GoPayload), AltchaJson.SerializerOptions)!;

    [Fact]
    public void VerifiesViaKeySignatureFastPath()
    {
        var result = Verify("go-secret", "go-key-secret");

        Assert.True(result.Verified);
        Assert.False(result.InvalidSignature);
    }

    [Fact]
    public void VerifiesViaDerivationSlowPath()
    {
        var result = Verify("go-secret", null);

        Assert.True(result.Verified);
        Assert.Equal(1234, Payload.Solution.Counter);
    }

    [Fact]
    public void WrongSecretInvalidatesSignature() =>
        Assert.True(Verify("wrong", null).InvalidSignature);

    private static VerifySolutionResult Verify(string secret, string? keySecret) =>
        AltchaPow.VerifySolution(new VerifySolutionOptions
        {
            Challenge = Payload.Challenge,
            Solution = Payload.Solution,
            HmacSignatureSecret = secret,
            HmacKeySignatureSecret = keySecret,
        });
}
