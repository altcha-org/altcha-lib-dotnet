using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Altcha;

/// <summary>Options for <see cref="SentinelClient.VerifyAsync"/>.</summary>
public sealed class VerifyServerOptions
{
    /// <summary>The full Sentinel verify URL, e.g. <c>https://sentinel.example.com/v1/verify/signature</c>.</summary>
    public required Uri Url { get; set; }

    /// <summary>The payload received from the client: the raw base64 string or a <see cref="ServerSignaturePayload"/>.</summary>
    public required object Payload { get; set; }

    /// <summary>API secret. When set, Sentinel checks that it matches the payload's API key.</summary>
    public string? Secret { get; set; }

    /// <summary>Additional request headers.</summary>
    public IDictionary<string, string>? Headers { get; set; }

    /// <summary>Timeout for each individual attempt.</summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(10);

    /// <summary>Number of retries after the first attempt.</summary>
    public int Retries { get; set; }

    /// <summary>Base delay between retries.</summary>
    public TimeSpan RetryDelay { get; set; } = TimeSpan.FromMilliseconds(300);

    /// <summary>How the retry delay grows.</summary>
    public RetryBackoff RetryBackoff { get; set; } = RetryBackoff.Exponential;
}

/// <summary>Client for the ALTCHA Sentinel <c>POST /v1/verify/signature</c> API.</summary>
public sealed class SentinelClient
{
    private static readonly MediaTypeHeaderValue JsonContentType = new("application/json");

    private readonly HttpClient _httpClient;

    /// <summary>Creates a client that sends requests through <paramref name="httpClient"/>.</summary>
    public SentinelClient(HttpClient httpClient)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        _httpClient = httpClient;
    }

    /// <summary>
    /// Verifies a payload remotely. A definitive verdict (including an HTTP 400 rejection) is returned;
    /// transport errors, unexpected statuses, invalid responses and timeouts are retried.
    /// </summary>
    /// <exception cref="AltchaSentinelException">All attempts failed; the inner exception is the last error.</exception>
    /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> was cancelled.</exception>
    public async Task<VerifyServerResult> VerifyAsync(VerifyServerOptions options, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(options.Url, nameof(options.Url));

        var body = JsonSerializer.SerializeToUtf8Bytes(
            new RequestBody(options.Payload, string.IsNullOrEmpty(options.Secret) ? null : options.Secret),
            AltchaJson.SerializerOptions);
        var retries = Math.Max(0, options.Retries);

        Exception? lastError = null;
        for (var attempt = 0; attempt <= retries; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                return await SendAsync(options, body, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException e) when (!cancellationToken.IsCancellationRequested)
            {
                lastError = new TimeoutException("Sentinel request timed out.", e);
            }
            catch (Exception e) when (e is HttpRequestException or AltchaHttpStatusException or JsonException)
            {
                lastError = e;
            }

            if (attempt < retries)
            {
                var delay = options.RetryBackoff == RetryBackoff.Fixed
                    ? options.RetryDelay
                    : options.RetryDelay * Math.Pow(2, attempt);
                await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
            }
        }

        throw new AltchaSentinelException($"Sentinel verification failed after {retries + 1} attempt(s).", lastError);
    }

    private async Task<VerifyServerResult> SendAsync(VerifyServerOptions options, byte[] body, CancellationToken cancellationToken)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(options.Timeout);

        using var request = new HttpRequestMessage(HttpMethod.Post, options.Url);
        var content = new ByteArrayContent(body);
        content.Headers.ContentType = JsonContentType;
        request.Content = content;
        if (options.Headers is not null)
        {
            foreach (var (name, value) in options.Headers)
            {
                if (string.Equals(name, "Content-Type", StringComparison.OrdinalIgnoreCase))
                {
                    content.Headers.ContentType = MediaTypeHeaderValue.Parse(value);
                }
                else if (!request.Headers.TryAddWithoutValidation(name, value))
                {
                    content.Headers.TryAddWithoutValidation(name, value);
                }
            }
        }

        using var response = await _httpClient.SendAsync(request, cts.Token).ConfigureAwait(false);
        var responseBody = await response.Content.ReadAsStringAsync(cts.Token).ConfigureAwait(false);

        if (response.StatusCode == HttpStatusCode.BadRequest)
        {
            return new VerifyServerResult { Verified = false, Reason = ReadErrorReason(responseBody) ?? "HTTP_400" };
        }

        if (!response.IsSuccessStatusCode)
        {
            throw new AltchaHttpStatusException((int)response.StatusCode, response.ReasonPhrase);
        }

        return JsonSerializer.Deserialize<VerifyServerResult>(responseBody, AltchaJson.SerializerOptions)
            ?? throw new JsonException("Sentinel returned an empty response.");
    }

    private static string? ReadErrorReason(string body)
    {
        try
        {
            using var doc = JsonDocument.Parse(body);
            return doc.RootElement.ValueKind == JsonValueKind.Object
                && doc.RootElement.TryGetProperty("error", out var error)
                && error.ValueKind == JsonValueKind.String
                && error.GetString() is { Length: > 0 } reason
                    ? reason
                    : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private sealed record RequestBody(
        [property: JsonPropertyName("payload")] object Payload,
        [property: JsonPropertyName("secret")] string? Secret);
}
