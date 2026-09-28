using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Altcha.AspNetCore.Tests;

public class PipelineTests
{
    [Fact]
    public async Task ChallengeEndpointReturnsSignedUncachedChallenge()
    {
        await using var app = await TestApp.StartAsync();
        var response = await app.GetTestClient().GetAsync("/altcha/challenge");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(response.Headers.CacheControl?.NoStore);
        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.False(string.IsNullOrEmpty(doc.RootElement.GetProperty("signature").GetString()));
        var parameters = doc.RootElement.GetProperty("parameters");
        Assert.False(parameters.TryGetProperty("keySignature", out _));
        Assert.Equal(32, parameters.GetProperty("keyPrefix").GetString()!.Length);
    }

    [Fact]
    public async Task SolvedPayloadVerifiesOnceThenIsReplayed()
    {
        await using var app = await TestApp.StartAsync();
        var client = app.GetTestClient();
        var payload = await TestApp.SolveFromEndpointAsync(client);

        var first = await client.PostFormAsync("/minimal", ("altcha", payload));
        var second = await client.PostFormAsync("/minimal", ("altcha", payload));

        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        Assert.Equal("\"ProofOfWork\"", await first.Content.ReadAsStringAsync());
        Assert.Equal(HttpStatusCode.Forbidden, second.StatusCode);
        Assert.Equal("replayed", await TestApp.ProblemCodeAsync(second));
    }

    [Fact]
    public async Task KeySignatureFastPathVerifies()
    {
        await using var app = await TestApp.StartAsync(o => o.HmacKeySignatureSecret = "key-secret");
        var client = app.GetTestClient();
        var payload = await TestApp.SolveFromEndpointAsync(client);

        var response = await client.PostFormAsync("/minimal", ("altcha", payload));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task MissingAndMalformedPayloadsAreRejected()
    {
        await using var app = await TestApp.StartAsync();
        var client = app.GetTestClient();

        var missing = await client.PostFormAsync("/minimal", ("other", "x"));
        var garbage = await client.PostFormAsync("/minimal", ("altcha", "garbage!!"));
        var notAnObject = await client.PostFormAsync("/minimal", ("altcha", Convert.ToBase64String("[1]"u8)));

        Assert.Equal(HttpStatusCode.Forbidden, missing.StatusCode);
        Assert.Equal("missing", await TestApp.ProblemCodeAsync(missing));
        Assert.Equal("malformed", await TestApp.ProblemCodeAsync(garbage));
        Assert.Equal("malformed", await TestApp.ProblemCodeAsync(notAnObject));
    }

    [Fact]
    public async Task TamperedPayloadIsInvalidSignature()
    {
        await using var app = await TestApp.StartAsync();
        var client = app.GetTestClient();
        var payload = JsonSerializer.Deserialize<Payload>(Convert.FromBase64String(await TestApp.SolveFromEndpointAsync(client)), AltchaJson.SerializerOptions)!;
        payload.Challenge.Parameters.Cost = 1;
        var tampered = Convert.ToBase64String(JsonSerializer.SerializeToUtf8Bytes(payload, AltchaJson.SerializerOptions));

        var response = await client.PostFormAsync("/minimal", ("altcha", tampered));

        Assert.Equal("invalid_signature", await TestApp.ProblemCodeAsync(response));
    }

    [Fact]
    public async Task JsonBodyCarrierVerifies()
    {
        await using var app = await TestApp.StartAsync();
        var client = app.GetTestClient();
        var payload = await TestApp.SolveFromEndpointAsync(client);

        var response = await client.PostAsJsonAsync("/json", new { altcha = payload });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task MvcAttributeRejectsOrRecordsModelError()
    {
        await using var app = await TestApp.StartAsync();
        var client = app.GetTestClient();
        var payload = await TestApp.SolveFromEndpointAsync(client);

        var valid = await client.PostFormAsync("/mvc", ("altcha", payload));
        var invalid = await client.PostFormAsync("/mvc", ("altcha", "garbage"));
        var soft = await client.PostFormAsync("/mvc-soft", ("altcha", "garbage"));

        Assert.Equal(HttpStatusCode.OK, valid.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, invalid.StatusCode);
        Assert.Equal("malformed", await TestApp.ProblemCodeAsync(invalid));
        Assert.Equal(HttpStatusCode.BadRequest, soft.StatusCode);
        using var doc = JsonDocument.Parse(await soft.Content.ReadAsStringAsync());
        Assert.True(doc.RootElement.GetProperty("errors").TryGetProperty("altcha", out _));
    }

    [Fact]
    public async Task SentinelLocalVerifiesAndAppliesPolicies()
    {
        await using var app = await TestApp.StartAsync(o =>
        {
            o.HmacSignatureSecret = null;
            o.Sentinel.ApiSecret = "api-secret";
        });
        var client = app.GetTestClient();
        var expire = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 600;
        var bobHash = Convert.ToHexString(SHA256.HashData("Bob"u8)).ToLowerInvariant();

        var good = await client.PostFormAsync("/minimal", ("altcha", TestApp.SentinelPayload($"classification=GOOD&expire={expire}&id=v1&verified=true")));
        var bad = await client.PostFormAsync("/minimal", ("altcha", TestApp.SentinelPayload($"classification=BAD&expire={expire}&id=v2&verified=true")));
        var fieldsPayload = TestApp.SentinelPayload($"expire={expire}&fields=name&fieldsHash={bobHash}&id=v3&verified=true");
        var eve = await client.PostFormAsync("/minimal", ("altcha", fieldsPayload), ("name", "Eve"));
        var bob = await client.PostFormAsync("/minimal", ("altcha", fieldsPayload), ("name", "Bob"));
        var wrongKey = await client.PostFormAsync("/minimal", ("altcha", TestApp.SentinelPayload($"expire={expire}&id=v4&verified=true", "other")));

        Assert.Equal(HttpStatusCode.OK, good.StatusCode);
        Assert.Equal("\"SentinelLocal\"", await good.Content.ReadAsStringAsync());
        Assert.Equal("classification_rejected", await TestApp.ProblemCodeAsync(bad));
        Assert.Equal("fields_hash_mismatch", await TestApp.ProblemCodeAsync(eve));
        Assert.Equal(HttpStatusCode.OK, bob.StatusCode);
        Assert.Equal("invalid_signature", await TestApp.ProblemCodeAsync(wrongKey));
    }

    [Fact]
    public async Task ProofOfWorkWithoutSecretIsMisconfigured()
    {
        await using var app = await TestApp.StartAsync();
        var client = app.GetTestClient();
        var payload = await TestApp.SolveFromEndpointAsync(client);
        app.Services.GetRequiredService<IOptionsMonitor<AltchaOptions>>().CurrentValue.HmacSignatureSecret = null;

        var response = await client.PostFormAsync("/minimal", ("altcha", payload));

        Assert.Equal("misconfigured", await TestApp.ProblemCodeAsync(response));
    }

    [Fact]
    public async Task SentinelRemoteForwardsRawPayload()
    {
        var stub = new StubHttpMessageHandler().Enqueue(HttpStatusCode.OK, """{"verified":true,"verificationData":{"id":"r1","classification":"GOOD"}}""");
        await using var app = await StartRemoteAsync(stub);
        var payload = TestApp.SentinelPayload("id=r1&verified=true");

        var response = await app.GetTestClient().PostFormAsync("/minimal", ("altcha", payload));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("\"SentinelRemote\"", await response.Content.ReadAsStringAsync());
        using var body = JsonDocument.Parse(stub.RequestBodies.Single());
        Assert.Equal(payload, body.RootElement.GetProperty("payload").GetString());
    }

    [Fact]
    public async Task SentinelRemoteMapsReplayAndBackendErrors()
    {
        var stub = new StubHttpMessageHandler()
            .Enqueue(HttpStatusCode.OK, """{"verified":false,"reason":"PAYLOAD_ALREADY_USED"}""")
            .Enqueue(HttpStatusCode.InternalServerError, "");
        await using var app = await StartRemoteAsync(stub);
        var client = app.GetTestClient();
        var payload = TestApp.SentinelPayload("id=r1&verified=true");

        var replayed = await client.PostFormAsync("/minimal", ("altcha", payload));
        var backend = await client.PostFormAsync("/minimal", ("altcha", payload));

        Assert.Equal("replayed", await TestApp.ProblemCodeAsync(replayed));
        Assert.Equal("backend_error", await TestApp.ProblemCodeAsync(backend));
    }

    [Fact]
    public async Task InvalidOptionsFailOnStart()
    {
        await Assert.ThrowsAsync<OptionsValidationException>(() => TestApp.StartAsync(o => o.Challenge.Algorithm = "Scrypt"));
    }

    [Fact]
    public void ConfigurationBindingReplacesRejectClassifications()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Altcha:HmacSignatureSecret"] = "s",
                ["Altcha:Sentinel:RejectClassifications:0"] = "NEUTRAL",
            })
            .Build();
        using var services = new ServiceCollection()
            .AddLogging()
            .AddAltcha(configuration.GetSection(AltchaDefaults.ConfigurationSection))
            .BuildServiceProvider();

        var options = services.GetRequiredService<IOptions<AltchaOptions>>().Value;

        Assert.Equal("s", options.HmacSignatureSecret);
        Assert.Equal(["NEUTRAL"], options.Sentinel.RejectClassifications!);
    }

    private static Task<Microsoft.AspNetCore.Builder.WebApplication> StartRemoteAsync(StubHttpMessageHandler stub) =>
        TestApp.StartAsync(
            o =>
            {
                o.Sentinel.Mode = SentinelVerifyMode.Remote;
                o.Sentinel.VerifyUrl = "https://sentinel.test/v1/verify/signature";
                o.Sentinel.Retries = 0;
            },
            s => s.AddHttpClient(AltchaDefaults.SentinelHttpClientName).ConfigurePrimaryHttpMessageHandler(() => stub));
}
