using System.Net;
using System.Text;

namespace Altcha.Tests;

public class SentinelClientTests
{
    private static readonly Uri Url = new("https://sentinel.test/v1/verify/signature");

    [Fact]
    public async Task ReturnsVerdictAndSendsPayloadAndSecret()
    {
        var stub = new StubHttpMessageHandler().Enqueue(HttpStatusCode.OK, """{"verified":true,"apiKey":"key_123"}""");

        var result = await Client(stub).VerifyAsync(new VerifyServerOptions { Url = Url, Payload = "p", Secret = "shh" });

        Assert.True(result.Verified);
        Assert.Equal("key_123", result.ApiKey);
        Assert.Equal("""{"payload":"p","secret":"shh"}""", stub.Requests.Single().Body);
        Assert.Equal("application/json", stub.Requests.Single().ContentType);
    }

    [Fact]
    public async Task BadRequestIsDefinitiveAndNotRetried()
    {
        var stub = new StubHttpMessageHandler().Enqueue(HttpStatusCode.BadRequest, """{"error":"INVALID_PAYLOAD"}""");

        var result = await Client(stub).VerifyAsync(new VerifyServerOptions { Url = Url, Payload = "p", Retries = 3 });

        Assert.False(result.Verified);
        Assert.Equal("INVALID_PAYLOAD", result.Reason);
        Assert.Single(stub.Requests);
    }

    [Fact]
    public async Task BadRequestWithoutErrorBodyFallsBackToStatusReason()
    {
        var stub = new StubHttpMessageHandler().Enqueue(HttpStatusCode.BadRequest, "not json");

        var result = await Client(stub).VerifyAsync(new VerifyServerOptions { Url = Url, Payload = "p" });

        Assert.Equal("HTTP_400", result.Reason);
    }

    [Fact]
    public async Task RetriesServerErrorsUntilSuccess()
    {
        var stub = new StubHttpMessageHandler()
            .Enqueue(HttpStatusCode.InternalServerError, "")
            .Enqueue(HttpStatusCode.InternalServerError, "")
            .Enqueue(HttpStatusCode.OK, """{"verified":true}""");

        var result = await Client(stub).VerifyAsync(new VerifyServerOptions
        {
            Url = Url,
            Payload = "p",
            Retries = 2,
            RetryBackoff = RetryBackoff.Fixed,
            RetryDelay = TimeSpan.FromMilliseconds(1),
        });

        Assert.True(result.Verified);
        Assert.Equal(3, stub.Requests.Count);
    }

    [Fact]
    public async Task ThrowsAfterRetriesAreExhausted()
    {
        var stub = new StubHttpMessageHandler();
        for (var i = 0; i < 5; i++)
        {
            stub.Enqueue(HttpStatusCode.InternalServerError, "");
        }

        var ex = await Assert.ThrowsAsync<AltchaSentinelException>(() => Client(stub).VerifyAsync(new VerifyServerOptions
        {
            Url = Url,
            Payload = "p",
            Retries = 2,
            RetryDelay = TimeSpan.FromMilliseconds(1),
        }));

        var status = Assert.IsType<AltchaHttpStatusException>(ex.InnerException);
        Assert.Equal(500, status.StatusCode);
        Assert.Equal(3, stub.Requests.Count);
    }

    [Theory]
    [InlineData(HttpStatusCode.Unauthorized)]
    [InlineData(HttpStatusCode.Forbidden)]
    [InlineData(HttpStatusCode.TooManyRequests)]
    public async Task ClientErrorsOtherThanBadRequestAreNotRetried(HttpStatusCode status)
    {
        var stub = new StubHttpMessageHandler()
            .Enqueue(status, """{"code":"API_KEY_REQUIRED","error":"API key required.","statusCode":401}""")
            .Enqueue(HttpStatusCode.OK, """{"verified":true}""");

        var ex = await Assert.ThrowsAsync<AltchaSentinelException>(() => Client(stub).VerifyAsync(new VerifyServerOptions
        {
            Url = Url,
            Payload = "p",
            Retries = 3,
            RetryDelay = TimeSpan.FromMilliseconds(1),
        }));

        Assert.Equal((int)status, Assert.IsType<AltchaHttpStatusException>(ex.InnerException).StatusCode);
        Assert.Single(stub.Requests);
    }

    [Fact]
    public async Task TimedOutAttemptIsReportedAsTimeout()
    {
        var stub = new StubHttpMessageHandler { Delay = TimeSpan.FromSeconds(5) };
        stub.Enqueue(HttpStatusCode.OK, """{"verified":true}""");

        var ex = await Assert.ThrowsAsync<AltchaSentinelException>(() => Client(stub).VerifyAsync(new VerifyServerOptions
        {
            Url = Url,
            Payload = "p",
            Timeout = TimeSpan.FromMilliseconds(50),
        }));

        Assert.IsType<TimeoutException>(ex.InnerException);
    }

    [Fact]
    public async Task CallerCancellationPropagates()
    {
        var stub = new StubHttpMessageHandler().Enqueue(HttpStatusCode.OK, """{"verified":true}""");

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            Client(stub).VerifyAsync(new VerifyServerOptions { Url = Url, Payload = "p" }, new CancellationToken(canceled: true)));
        Assert.Empty(stub.Requests);
    }

    [Fact]
    public async Task ForwardsCustomHeadersAndOmitsNullSecret()
    {
        var stub = new StubHttpMessageHandler().Enqueue(HttpStatusCode.OK, """{"verified":true}""");

        await Client(stub).VerifyAsync(new VerifyServerOptions
        {
            Url = Url,
            Payload = "p",
            Headers = new Dictionary<string, string> { ["X-Custom"] = "yes" },
        });

        var request = stub.Requests.Single();
        Assert.Equal("yes", request.Headers["X-Custom"]);
        Assert.Equal("""{"payload":"p"}""", request.Body);
    }

    [Fact]
    public async Task V2AuthenticatesWithBasicCredentialsInsteadOfBodySecret()
    {
        var stub = new StubHttpMessageHandler().Enqueue(HttpStatusCode.OK, """{"apiKey":"key_widget","verificationData":null,"verified":true}""");

        var result = await Client(stub).VerifyAsync(new VerifyServerOptions
        {
            Url = new Uri("https://sentinel.test/v2/verify/signature"),
            Payload = "p",
            ApiKey = "key_backend",
            Secret = "sec_backend",
            Headers = new Dictionary<string, string> { ["Authorization"] = "Bearer stale", ["X-Custom"] = "yes" },
        });

        var request = stub.Requests.Single();
        Assert.True(result.Verified);
        Assert.Equal("Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes("key_backend:sec_backend")), request.Headers["Authorization"]);
        Assert.Equal("yes", request.Headers["X-Custom"]);
        Assert.Equal("""{"payload":"p"}""", request.Body);
    }

    [Fact]
    public async Task V2ApiKeyWithoutSecretThrowsBeforeSending()
    {
        var stub = new StubHttpMessageHandler();

        await Assert.ThrowsAsync<ArgumentException>(() =>
            Client(stub).VerifyAsync(new VerifyServerOptions { Url = Url, Payload = "p", ApiKey = "key_backend" }));
        Assert.Empty(stub.Requests);
    }

    [Fact]
    public async Task SerializesStructuredPayload()
    {
        var stub = new StubHttpMessageHandler().Enqueue(HttpStatusCode.OK, """{"verified":true}""");

        await Client(stub).VerifyAsync(new VerifyServerOptions
        {
            Url = Url,
            Payload = new ServerSignaturePayload { Algorithm = "SHA-256", Signature = "s", VerificationData = "v", Verified = true },
        });

        Assert.Equal(
            """{"payload":{"algorithm":"SHA-256","signature":"s","verificationData":"v","verified":true}}""",
            stub.Requests.Single().Body);
    }

    [Fact]
    public async Task ParsesNestedSentinelVerificationData()
    {
        // The shape Sentinel's /v1/verify/signature returns: dotted keys expanded into objects, numeric strings parsed.
        var stub = new StubHttpMessageHandler().Enqueue(
            HttpStatusCode.OK,
            """
            {"apiKey":"key_1","reason":null,"verified":true,"verificationData":{
              "location":{"countryCode":"id","score":0,"timeZone":"Asia/Makassar","triggeredRules":""},
              "id":"1k38phtgs00b1u0d28n","classification":"GOOD","challengeAlgorithm":"PBKDF2/SHA-256",
              "device":{"browser":"Firefox","edk":"655a58a14d7ece290c57f62ac03d18f4","type":"desktop"},
              "text":{"language":"en","score":0.5,"triggeredRules":"r1,r2"},
              "params":{"plan":"pro","seats":5},
              "expire":1790224057,"ipAddress":"38.86.221.134","penalty":0,"origin":"http://localhost:5081",
              "reasons":[],"score":0,"time":1790222859,"verified":true}}
            """);

        var result = await Client(stub).VerifyAsync(new VerifyServerOptions { Url = Url, Payload = "p" });

        var vd = result.VerificationData!;
        Assert.Equal("id", vd.Location!.CountryCode);
        Assert.Equal("Asia/Makassar", vd.Location.TimeZone);
        Assert.Empty(vd.Location.TriggeredRules!);
        Assert.Equal("Firefox", vd.Device!.Browser);
        Assert.Equal("en", vd.Text!.Language);
        Assert.Equal(["r1", "r2"], vd.Text.TriggeredRules!);
        Assert.Equal("5", vd.Params!["seats"]);
        Assert.Equal("PBKDF2/SHA-256", vd.ChallengeAlgorithm);
        Assert.Equal("http://localhost:5081", vd.Origin);
        Assert.Equal(0, vd.Penalty);
        Assert.Empty(vd.Reasons!);
        Assert.Equal(1790224057, vd.Expire);
        Assert.True(vd.Verified);
        Assert.Null(vd.Extra);
    }

    [Fact]
    public async Task ParsesLenientVerificationData()
    {
        var stub = new StubHttpMessageHandler().Enqueue(
            HttpStatusCode.OK,
            """{"verified":true,"verificationData":{"id":123,"fields":"a,b","score":"1.5","expire":"1700000000","verified":"true","email":"legacy@example.com","location":null}}""");

        var result = await Client(stub).VerifyAsync(new VerifyServerOptions { Url = Url, Payload = "p" });

        var vd = result.VerificationData!;
        Assert.Equal("123", vd.Id);
        Assert.Equal(["a", "b"], vd.Fields);
        Assert.Equal(1.5, vd.Score);
        Assert.Equal(1700000000, vd.Expire);
        Assert.True(vd.Verified);
        Assert.Null(vd.Email);
        Assert.Null(vd.Location);
    }

    [Fact]
    public async Task ParsesSentinelV2VerificationData()
    {
        // The shape Sentinel v2's /v2/verify/signature returns: new groups (challenge, his, ...), and id, fieldsHash,
        // device.edk and params.* kept as strings.
        var stub = new StubHttpMessageHandler().Enqueue(
            HttpStatusCode.OK,
            """
            {"apiKey":"key_1k4pfmle60061hr87tv","verified":true,"verificationData":{
              "challenge":{"algorithm":"PBKDF2/SHA-256","issued":1791856880,"protectionLevel":"frictionless"},
              "classification":"GOOD","score":0.5,"reasons":["r1"],
              "device":{"browser":"Firefox","edk":"0123","os":"Linux","score":0,"triggeredRules":[],"type":"desktop"},
              "ip":{"asname":"AS1","countryCode":"cz","networks":"a,b","score":1,"triggeredRules":["ip.vpn"]},
              "his":{"assistive":false,"automation":0,"flags":"","mode":"passive"},
              "location":{"countryCode":"cz","score":0,"timeZone":"Europe/Prague","triggeredRules":[]},
              "expire":1791858092,"fields":["email","name"],"fieldsHash":"0042","id":"5437",
              "ipAddress":"203.0.113.1","origin":"https://example.com","params":{"formId":"contact","zip":"01234"},
              "time":1791856892,"verified":true}}
            """);

        var result = await Client(stub).VerifyAsync(new VerifyServerOptions { Url = Url, Payload = "p", ApiKey = "k", Secret = "s" });

        var vd = result.VerificationData!;
        Assert.Equal("key_1k4pfmle60061hr87tv", result.ApiKey);
        Assert.Equal("5437", vd.Id);
        Assert.Equal("0042", vd.FieldsHash);
        Assert.Equal(["email", "name"], vd.Fields);
        Assert.Equal(1791858092, vd.Expire);
        Assert.Equal("GOOD", vd.Classification);
        Assert.Equal("0123", vd.Device!.Edk);
        Assert.Equal("Linux", vd.Device.Extra!["os"].GetString());
        Assert.Equal(["ip.vpn"], vd.Ip!.TriggeredRules!);
        Assert.Equal("cz", vd.Location!.CountryCode);
        Assert.Equal("01234", vd.Params!["zip"]);
        Assert.Equal("PBKDF2/SHA-256", vd.Extra!["challenge"].GetProperty("algorithm").GetString());
        Assert.True(vd.Extra.ContainsKey("his"));
        Assert.True(vd.Verified);
    }

    private static SentinelClient Client(StubHttpMessageHandler stub) => new(new HttpClient(stub));
}

internal sealed class StubHttpMessageHandler : HttpMessageHandler
{
    private readonly Queue<(HttpStatusCode Status, string Body)> _responses = new();

    public List<RecordedRequest> Requests { get; } = [];

    public TimeSpan Delay { get; init; }

    public StubHttpMessageHandler Enqueue(HttpStatusCode status, string body)
    {
        _responses.Enqueue((status, body));
        return this;
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var body = request.Content is null ? "" : await request.Content.ReadAsStringAsync(cancellationToken);
        var headers = request.Headers.ToDictionary(h => h.Key, h => string.Join(",", h.Value), StringComparer.OrdinalIgnoreCase);
        Requests.Add(new RecordedRequest(request.RequestUri, body, request.Content?.Headers.ContentType?.MediaType, headers));
        if (Delay > TimeSpan.Zero)
        {
            await Task.Delay(Delay, cancellationToken);
        }

        var (status, responseBody) = _responses.Dequeue();
        return new HttpResponseMessage(status) { Content = new StringContent(responseBody, Encoding.UTF8, "application/json") };
    }
}

internal sealed record RecordedRequest(Uri? Uri, string Body, string? ContentType, Dictionary<string, string> Headers);
