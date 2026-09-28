using Microsoft.Extensions.Options;

namespace Altcha.AspNetCore;

/// <summary>
/// Validates <see cref="AltchaOptions"/> at startup. Secrets are not required here: an app may use only
/// Sentinel or only proof-of-work, so missing secrets surface at runtime as <see cref="AltchaErrorCode.Misconfigured"/>.
/// </summary>
public sealed class AltchaOptionsValidator : IValidateOptions<AltchaOptions>
{
    private const string Prefix = AltchaDefaults.ConfigurationSection + ":";

    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, AltchaOptions options)
    {
        var failures = new List<string>();
        var challenge = options.Challenge;
        var sentinel = options.Sentinel;

        if (challenge is null)
        {
            failures.Add($"{Prefix}Challenge is required.");
        }
        else
        {
            if (!KeyDerivation.CanonicalAlgorithms.Contains(challenge.Algorithm, StringComparer.Ordinal))
            {
                failures.Add($"{Prefix}Challenge:Algorithm must be one of {string.Join(", ", KeyDerivation.CanonicalAlgorithms)}.");
            }

            if (challenge.Cost < 1)
            {
                failures.Add($"{Prefix}Challenge:Cost must be >= 1.");
            }

            if (challenge.KeyLength < 1)
            {
                failures.Add($"{Prefix}Challenge:KeyLength must be >= 1.");
            }

            if (challenge.Expires <= TimeSpan.Zero)
            {
                failures.Add($"{Prefix}Challenge:Expires must be > 0.");
            }

            if (challenge.Deterministic)
            {
                if (challenge.CounterMin < 0 || challenge.CounterMin >= challenge.CounterMax)
                {
                    failures.Add($"{Prefix}Challenge:CounterMin must be >= 0 and < Challenge:CounterMax.");
                }
            }
            else if (challenge.KeyPrefix is null || !challenge.KeyPrefix.All(Uri.IsHexDigit))
            {
                failures.Add($"{Prefix}Challenge:KeyPrefix must be a hex string.");
            }
        }

        if (string.IsNullOrEmpty(options.FieldName))
        {
            failures.Add($"{Prefix}FieldName must not be empty.");
        }

        if (options.FailureStatusCode is < 400 or > 599)
        {
            failures.Add($"{Prefix}FailureStatusCode must be between 400 and 599.");
        }

        if (sentinel is null)
        {
            failures.Add($"{Prefix}Sentinel is required.");
        }
        else
        {
            if (sentinel.Timeout <= TimeSpan.Zero)
            {
                failures.Add($"{Prefix}Sentinel:Timeout must be > 0.");
            }

            if (sentinel.Retries < 0)
            {
                failures.Add($"{Prefix}Sentinel:Retries must be >= 0.");
            }

            if (sentinel.Mode == SentinelVerifyMode.Remote && !IsHttpUrl(sentinel.VerifyUrl))
            {
                failures.Add($"{Prefix}Sentinel:VerifyUrl must be an absolute http(s) URL when Sentinel:Mode is Remote.");
            }
        }

        return failures.Count > 0 ? ValidateOptionsResult.Fail(failures) : ValidateOptionsResult.Success;
    }

    internal static bool IsHttpUrl(string? url) =>
        Uri.TryCreate(url, UriKind.Absolute, out var uri) && (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps);
}
