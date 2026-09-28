# ALTCHA .NET Library

The ALTCHA .NET Library creates and verifies [ALTCHA](https://altcha.org) challenges in .NET and ASP.NET Core applications. It implements the ALTCHA v2 proof-of-work protocol, which is based on key derivation functions (KDFs), and supports ALTCHA Sentinel payloads, verified either locally or through the remote API.

## Compatibility

- .NET 8.0+ (targets `net8.0` and `net10.0`)
- ASP.NET Core 8.0+ for `Altcha.AspNetCore`

## Interoperability

- Only the v2 PoW protocol is supported.

## Packages

| Package | Description |
|---|---|
| `Altcha` | Framework-free core: create, solve and verify challenges; PBKDF2, SHA, scrypt and Argon2id; Sentinel server signatures; Sentinel HTTP client |
| `Altcha.AspNetCore` | ASP.NET Core integration: DI, challenge endpoint, minimal-API filter, MVC / Razor Pages attribute, `<altcha-widget>` tag helper, replay protection |

## Installation

```sh
dotnet add package Altcha.AspNetCore   # ASP.NET Core apps (includes Altcha)
dotnet add package Altcha              # core library only
```

## ASP.NET Core quick start

### 1. Register services and the challenge endpoint

`Program.cs`:

```csharp
using Altcha.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddRazorPages();
builder.Services.AddAltcha(builder.Configuration.GetSection(AltchaDefaults.ConfigurationSection));

var app = builder.Build();

app.MapAltchaChallenge();          // GET /altcha/challenge
app.MapRazorPages();

app.Run();
```

`appsettings.json` (the `Altcha` section sits at the root, next to `Logging`):

```json
{
  "Altcha": {
    "HmacSignatureSecret": "change-me-hmac-secret",
    "HmacKeySignatureSecret": "change-me-key-secret"
  }
}
```

Keep secrets out of source control, for example in user secrets, environment variables (`Altcha__HmacSignatureSecret`) or a vault. You can also configure the options in code:

```csharp
builder.Services.AddAltcha(o =>
{
    o.HmacSignatureSecret = builder.Configuration["AltchaSecret"];
    o.Challenge.Cost = 10_000;
});
```

The options are validated at startup, so an invalid algorithm, cost or URL fails fast with an `OptionsValidationException`.

### 2. Render the widget

Add the tag helper in `_ViewImports.cshtml`:

```cshtml
@addTagHelper *, Altcha.AspNetCore
```

Then load the widget script and place the widget inside your form:

```cshtml
<script type="module" src="https://cdn.jsdelivr.net/npm/altcha@3/dist/main/altcha.min.js"></script>

<form method="post">
    <input name="message" />
    <altcha-widget></altcha-widget>
    <button type="submit">Submit</button>
</form>
```

The tag helper fills in `name` (the configured `FieldName`, default `altcha`) and `challenge`. `challenge` is `Sentinel:ChallengeUrl` when that is set, otherwise the URL of the mapped challenge endpoint. The tag helper never overwrites attributes you set yourself, and it does not add the widget script.

### 3. Verify submissions

#### Minimal APIs

```csharp
app.MapPost("/contact", (HttpContext context) =>
{
    var result = context.GetAltchaResult()!;
    return Results.Ok(new { result.PayloadType });
})
.RequireAltcha();
```

`RequireAltcha()` also works on route groups. By default a failed verification short-circuits with a problem response (see [Failures](#failures)). Use `RequireAltcha(rejectOnFailure: false)` to always run the handler and inspect `context.GetAltchaResult()` yourself.

#### MVC controllers

```csharp
[HttpPost]
[AltchaVerify]
public IActionResult Contact(ContactForm form) => Ok();
```

#### Razor Pages

```csharp
[AltchaVerify(RejectOnFailure = false)]
public class ContactModel : PageModel
{
    public void OnPost()
    {
        if (!ModelState.IsValid)
        {
            // ModelState["altcha"] holds the ALTCHA error message.
        }
    }
}
```

On Razor Pages, `GET`, `HEAD`, `OPTIONS` and `TRACE` handlers are skipped, so a page-level attribute does not block rendering. With `RejectOnFailure = false`, the error is added to `ModelState` under `FieldName` and the handler runs.

#### JSON bodies

For form posts the payload is read from the `FieldName` form field. For JSON endpoints, have the bound model implement `IAltchaPayloadCarrier`:

```csharp
public sealed class ContactRequest : IAltchaPayloadCarrier
{
    public string? Message { get; set; }

    [JsonPropertyName("altcha")]
    public string? AltchaPayload { get; set; }
}

app.MapPost("/api/contact", (ContactRequest request) => Results.Ok()).RequireAltcha();
```

The carrier works as an action argument or Razor Pages handler argument, and on a Razor Pages page model.

#### Calling the service directly

```csharp
app.MapPost("/custom", async (HttpRequest request, IAltchaService altcha) =>
{
    var form = await request.ReadFormAsync();
    var result = await altcha.VerifyAsync(form["altcha"], name => form[name].FirstOrDefault());
    return result.Verified ? Results.Ok() : Results.BadRequest(result.Error);
});
```

The second argument supplies form values for the Sentinel `fieldsHash` check.

### Failures

Rejected requests get an RFC 7807 `application/problem+json` response with status `FailureStatusCode` (default `403`) and a machine-readable `code`:

```json
{
  "status": 403,
  "title": "ALTCHA verification failed.",
  "detail": "ALTCHA payload has been already used.",
  "code": "replayed"
}
```

| `AltchaErrorCode` | `code` | Meaning |
|---|---|---|
| `Missing` | `missing` | No payload was submitted |
| `Malformed` | `malformed` | The payload is not valid base64 JSON, or its challenge is malformed |
| `Misconfigured` | `misconfigured` | A secret or URL required for this payload type is not configured |
| `Expired` | `expired` | The challenge or the Sentinel verification has expired |
| `InvalidSignature` | `invalid_signature` | The challenge or server signature does not match |
| `InvalidSolution` | `invalid_solution` | The proof-of-work solution is wrong |
| `Unverified` | `unverified` | Sentinel did not verify the payload |
| `Replayed` | `replayed` | The payload was already used |
| `ClassificationRejected` | `classification_rejected` | Sentinel's classification is in `RejectClassifications` |
| `FieldsHashMismatch` | `fields_hash_mismatch` | The submitted fields do not match Sentinel's `fieldsHash` |
| `BackendError` | `backend_error` | The remote Sentinel API is unavailable (fails closed) |

`AltchaVerificationResult` also exposes the parsed payload, the verification details and the Sentinel `VerificationData`. It has the same shape whether it was verified locally or remotely: `Classification`, `Score`, `Reasons`, `Location` (`CountryCode`, `TimeZone`), `Device` (`Browser`, `Type`), `Text` (`Language`), `Email` and `Ip` scores, custom `Params`, and so on.

### Sentinel

Point the widget at Sentinel and choose how its payloads are verified.

`appsettings.json` (the `Sentinel` object goes inside the same `Altcha` section as the secrets above):

```json
{
  "Altcha": {
    "Sentinel": {
      "ChallengeUrl": "https://sentinel.example.com/v1/challenge?apiKey=key_...",
      "ApiSecret": "sec_...",
      "Mode": "Local"
    }
  }
}
```

- **`Local`** (default): the server signature is checked with `ApiSecret` as the HMAC key. No network call is made.
- **`Remote`**: the raw payload is posted to `VerifyUrl` (`https://sentinel.example.com/v1/verify/signature`). `ApiSecret` is sent as `secret`. Timeouts, network errors and unexpected statuses are retried (`Retries`, `RetryDelay`, `RetryBackoff`). If every attempt fails, the request fails with `backend_error`.

Both modes apply the same policies: the classifications in `RejectClassifications` are rejected (default `BAD`), `fieldsHash` is checked against the submitted form fields when present, and replay protection applies.

Proof-of-work and Sentinel payloads are told apart automatically, so one app can accept both.

### Replay protection

Every verified payload is claimed in an `IAltchaReplayStore` until shortly after it expires. The replay key is `data.challengeId` or the nonce for proof-of-work payloads, and the verification `id` for Sentinel payloads. The default `InMemoryAltchaReplayStore` is per process. For multiple instances:

```csharp
builder.Services.AddStackExchangeRedisCache(o => o.Configuration = "...");
builder.Services.AddAltchaDistributedReplayStore();
```

The `IDistributedCache` store uses a check-then-set that is not atomic across instances. Where that matters, register your own `IAltchaReplayStore` with an atomic set-if-absent:

```csharp
builder.Services.AddSingleton<IAltchaReplayStore, RedisSetNxReplayStore>();
```

Set `ReplayProtection` to `false` to disable replay protection.

### Customizing challenges

```csharp
builder.Services.AddAltcha(o =>
{
    o.ConfigureChallenge = (httpContext, challenge) =>
    {
        challenge.Data = new Dictionary<string, object?>
        {
            ["challengeId"] = Guid.NewGuid().ToString("N"),
            ["ip"] = httpContext?.Connection.RemoteIpAddress?.ToString(),
        };
    };
});
```

`data` is signed with the challenge and returned in the verified payload (`result.Payload.Challenge.Parameters.Data`).

### Configuration reference

All settings bind from the `Altcha` section of your configuration: `appsettings.json`, `appsettings.{Environment}.json`, environment variables, user secrets or any other configuration source. Nested settings are written `Challenge:Cost` here, which is `"Altcha": { "Challenge": { "Cost": 5000 } }` in JSON and `Altcha__Challenge__Cost` as an environment variable. `ConfigureChallenge` and `DeriveKey` are delegates and can only be set in code. `TimeSpan` values use the `hh:mm:ss` format.

| Setting | Default | Description |
|---|---|---|
| `HmacSignatureSecret` | — | Signs challenges. Required for proof-of-work |
| `HmacKeySignatureSecret` | — | Adds a key signature to deterministic challenges, so a solution is verified without re-deriving the key |
| `HmacAlgorithm` | `Sha256` | HMAC hash: `Sha1`, `Sha256`, `Sha384`, `Sha512` |
| `FieldName` | `altcha` | Form field and widget `name` |
| `FailureStatusCode` | `403` | Status code of rejected requests |
| `ReplayProtection` | `true` | Accept each payload only once |
| `Challenge:Algorithm` | `PBKDF2/SHA-256` | See [Key derivation algorithms](#key-derivation-algorithms) |
| `Challenge:Cost` | `5000` | KDF work factor |
| `Challenge:KeyLength` | `32` | Derived key length in bytes |
| `Challenge:MemoryCost` | — | scrypt `r` / Argon2id memory in KiB |
| `Challenge:Parallelism` | — | scrypt `p` / Argon2id lanes |
| `Challenge:Expires` | `00:10:00` | Challenge lifetime |
| `Challenge:Deterministic` | `true` | The server picks the counter and derives the key prefix. When `false`, a random challenge with `KeyPrefix` is issued |
| `Challenge:CounterMin` / `CounterMax` | `5000` / `10000` | Range of the deterministic counter (min inclusive, max exclusive) |
| `Challenge:KeyPrefixLength` | half of `KeyLength` | Prefix length in bytes for deterministic challenges |
| `Challenge:KeyPrefix` | `00` | Hex prefix for random challenges |
| `Sentinel:Mode` | `Local` | `Local` or `Remote` |
| `Sentinel:ApiSecret` | — | HMAC key (local) or `secret` (remote) |
| `Sentinel:VerifyUrl` | — | `/v1/verify/signature` URL. Required for `Remote` |
| `Sentinel:ChallengeUrl` | — | Challenge URL rendered by the tag helper |
| `Sentinel:Timeout` | `00:00:10` | Timeout per remote attempt |
| `Sentinel:Retries` | `1` | Retries after the first remote attempt |
| `Sentinel:RetryDelay` | `00:00:00.300` | Base retry delay |
| `Sentinel:RetryBackoff` | `Exponential` | `Exponential` or `Fixed` |
| `Sentinel:Headers` | — | Extra headers for remote requests |
| `Sentinel:RejectClassifications` | `["BAD"]` | Classifications that fail verification |
| `Sentinel:VerifyFieldsHash` | `true` | Check `fieldsHash` when present |

Sentinel requests go through the `IHttpClientFactory` client named `AltchaDefaults.SentinelHttpClientName`, which you can configure with `AddHttpClient(...)` (proxies, handlers, resilience).

## Core library

The `Altcha` package has no ASP.NET Core dependency.

### Create a challenge

```csharp
using Altcha;

var challenge = AltchaPow.CreateChallenge(new CreateChallengeOptions
{
    Algorithm = "PBKDF2/SHA-256",
    Cost = 5000,
    Counter = Random.Shared.Next(5000, 10000),   // deterministic; omit for a random challenge
    ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(10),
    HmacSignatureSecret = "your-secret",
    HmacKeySignatureSecret = "your-key-secret",
});

var json = JsonSerializer.Serialize(challenge, AltchaJson.SerializerOptions);
```

Always serialize and deserialize wire types with `AltchaJson.SerializerOptions`.

### Solve a challenge

```csharp
var solution = AltchaPow.SolveChallenge(new SolveChallengeOptions { Challenge = challenge }, cancellationToken);
```

### Verify a solution

```csharp
var payload = JsonSerializer.Deserialize<Payload>(Convert.FromBase64String(base64), AltchaJson.SerializerOptions)!;

var result = AltchaPow.VerifySolution(new VerifySolutionOptions
{
    Challenge = payload.Challenge,
    Solution = payload.Solution,
    HmacSignatureSecret = "your-secret",
    HmacKeySignatureSecret = "your-key-secret",
});

if (result.Verified)
{
    // valid
}
```

Verification checks, in order: expiry (`Expired`), the challenge signature (`InvalidSignature`), and then the solution (`InvalidSolution`). The solution is checked against the key signature when the challenge has one and `HmacKeySignatureSecret` is set, and by re-deriving the key otherwise. `VerifySolution` does not protect against replay. Track used challenges yourself, or use `Altcha.AspNetCore`.

`AltchaSecrets.DeriveHmacKeySecret(masterSecret)` derives a key-signature secret from a master secret, the same way as the JS `deriveHmacKeySecret`.

### Verify a Sentinel server signature locally

```csharp
var result = ServerSignature.Verify(base64Payload, "sentinel-api-secret");

if (result.Verified)
{
    var data = result.VerificationData!;   // Classification, Score, Location.CountryCode, Device.Browser, FieldsHash, Id, ...

    if (data.FieldsHash is { } hash
        && !ServerSignature.VerifyFieldsHash(formValues, data.Fields ?? [], hash))
    {
        // the submitted fields were modified
    }
}
```

`ServerSignature.Verify` also accepts a deserialized `ServerSignaturePayload`, and `ServerSignature.ParseVerificationData` parses the URL-encoded verification data on its own.

### Verify a payload remotely with Sentinel

```csharp
var client = new SentinelClient(httpClient);

var result = await client.VerifyAsync(new VerifyServerOptions
{
    Url = new Uri("https://sentinel.example.com/v1/verify/signature"),
    Payload = base64Payload,        // raw string or ServerSignaturePayload
    Secret = "sentinel-api-secret",
    Timeout = TimeSpan.FromSeconds(5),
    Retries = 2,
    RetryBackoff = RetryBackoff.Exponential,
}, cancellationToken);

if (result.Verified)
{
    // valid
}
```

Sentinel's verdict is always returned, including a rejection (`Verified = false`, `Reason`, e.g. `PAYLOAD_ALREADY_USED`) and an HTTP 400 response. Network errors, timeouts, unexpected statuses and invalid responses are retried. When every attempt fails, `AltchaSentinelException` is thrown, and its `InnerException` holds the last error (`AltchaHttpStatusException`, `TimeoutException`, `HttpRequestException` or `JsonException`). Cancelling `cancellationToken` throws `OperationCanceledException`.

## Key derivation algorithms

`KeyDerivation.Resolve(algorithm)` returns the built-in function for an algorithm name, ignoring case. You can pass a custom `DeriveKeyFunc` through `DeriveKey` on any options type. The ASP.NET Core options accept only the canonical spellings below, which are the ones the widget uses.

| Algorithm | `Cost` | `MemoryCost` | `Parallelism` |
|---|---|---|---|
| `PBKDF2/SHA-256` (recommended), `PBKDF2/SHA-384`, `PBKDF2/SHA-512` | iterations | — | — |
| `SHA-256`, `SHA-384`, `SHA-512` | hash rounds | — | — |
| `SCRYPT` | N (default 16384) | r (default 8) | p (default 1) |
| `ARGON2ID` | time cost (default 1) | memory in KiB (default 65536) | lanes (default 1) |

- **PBKDF2**: moderate cost, widely supported. This is the default.
- **SHA**: iterated hashing. Fast; suitable for low-friction challenges.
- **scrypt** and **Argon2id (v1.3)**: memory-hard. Both are provided by [BouncyCastle](https://www.bouncycastle.org/).


## Examples

### Self-hosted proof-of-work

[`examples/Altcha.Example`](./examples/Altcha.Example) is a Razor Pages app with the widget, the tag helper, `[AltchaVerify]` and a `RequireAltcha()` minimal API endpoint. The app issues its own challenges:

```sh
dotnet run --project examples/Altcha.Example
# http://localhost:5080
```

### Sentinel

In [`examples/Altcha.Example.Sentinel`](./examples/Altcha.Example.Sentinel), challenges come from Sentinel and payloads are verified by Sentinel's `/v1/verify/signature` API (`Sentinel:Mode` `Remote`). The app has no `HmacSignatureSecret` and no challenge endpoint. After a successful submission, the page shows Sentinel's classification, score, country, time zone, device and reasons.

Set your Sentinel URLs and API key, then run it:

```sh
cd examples/Altcha.Example.Sentinel
dotnet user-secrets set "Altcha:Sentinel:ChallengeUrl" "https://sentinel.example.com/v1/challenge?apiKey=key_..."
dotnet user-secrets set "Altcha:Sentinel:VerifyUrl" "https://sentinel.example.com/v1/verify/signature"
dotnet user-secrets set "Altcha:Sentinel:ApiSecret" "sec_..."
dotnet run
# http://localhost:5081
```

`ApiSecret` is optional in remote mode. When it is set, Sentinel also checks that the payload belongs to that API key.

## Development

```sh
dotnet build Altcha.slnx
dotnet test Altcha.slnx      # runs on net8.0 and net10.0
```

## License

MIT
