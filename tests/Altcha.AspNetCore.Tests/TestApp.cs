using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Altcha.AspNetCore.Tests;

public sealed class TestsMarker;

public sealed class JsonBody : IAltchaPayloadCarrier
{
    [JsonPropertyName("altcha")]
    public string? AltchaPayload { get; set; }
}

[ApiExplorerSettings(IgnoreApi = true)]
public sealed class AltchaTestController : ControllerBase
{
    [HttpPost("/mvc")]
    [AltchaVerify]
    public IActionResult Strict() => Ok();

    [HttpPost("/mvc-soft")]
    [AltchaVerify(RejectOnFailure = false)]
    public IActionResult Soft() => ModelState.IsValid ? Ok() : ValidationProblem(ModelState);
}

internal static class TestApp
{
    public static async Task<WebApplication> StartAsync(
        Action<AltchaOptions>? configure = null,
        Action<IServiceCollection>? configureServices = null)
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Logging.ClearProviders();
        builder.Services.AddAltcha(o =>
        {
            o.HmacSignatureSecret = "secret";
            o.Challenge.Cost = 100;
            o.Challenge.CounterMin = 1;
            o.Challenge.CounterMax = 50;
            configure?.Invoke(o);
        });
        builder.Services.AddControllers().AddApplicationPart(typeof(TestsMarker).Assembly);
        configureServices?.Invoke(builder.Services);

        var app = builder.Build();
        app.MapAltchaChallenge();
        app.MapPost("/minimal", (HttpContext c) => Results.Ok(c.GetAltchaResult()!.PayloadType.ToString())).RequireAltcha();
        app.MapPost("/json", (JsonBody b) => Results.Ok()).RequireAltcha();
        app.MapControllers();
        await app.StartAsync();
        return app;
    }

    public static async Task<string> SolveFromEndpointAsync(HttpClient client)
    {
        var challenge = await client.GetFromJsonAsync<Challenge>("/altcha/challenge", AltchaJson.SerializerOptions);
        var solution = AltchaPow.SolveChallenge(new SolveChallengeOptions { Challenge = challenge! });
        var json = JsonSerializer.SerializeToUtf8Bytes(new Payload { Challenge = challenge!, Solution = solution }, AltchaJson.SerializerOptions);
        return Convert.ToBase64String(json);
    }

    public static string SentinelPayload(string verificationData, string secret = "api-secret")
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(verificationData));
        var signature = Convert.ToHexString(HMACSHA256.HashData(Encoding.UTF8.GetBytes(secret), hash)).ToLowerInvariant();
        var json = JsonSerializer.SerializeToUtf8Bytes(new
        {
            algorithm = "SHA-256",
            verificationData,
            signature,
            verified = true,
        });
        return Convert.ToBase64String(json);
    }

    public static Task<HttpResponseMessage> PostFormAsync(this HttpClient client, string path, params (string Name, string Value)[] fields) =>
        client.PostAsync(path, new FormUrlEncodedContent(fields.Select(f => new KeyValuePair<string, string>(f.Name, f.Value))));

    public static async Task<string?> ProblemCodeAsync(HttpResponseMessage response)
    {
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return doc.RootElement.GetProperty("code").GetString();
    }
}

internal sealed class StubHttpMessageHandler : HttpMessageHandler
{
    private readonly Queue<(HttpStatusCode Status, string Body)> _responses = new();

    public List<string> RequestBodies { get; } = [];

    public StubHttpMessageHandler Enqueue(HttpStatusCode status, string body)
    {
        _responses.Enqueue((status, body));
        return this;
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        RequestBodies.Add(await request.Content!.ReadAsStringAsync(cancellationToken));
        var (status, body) = _responses.Dequeue();
        return new HttpResponseMessage(status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
    }
}
