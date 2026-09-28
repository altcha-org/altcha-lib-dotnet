using System.Diagnostics.CodeAnalysis;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;

namespace Altcha.AspNetCore;

/// <summary>Request feature holding the ALTCHA verification result of the current request.</summary>
public interface IAltchaFeature
{
    /// <summary>The verification result.</summary>
    AltchaVerificationResult Result { get; }
}

/// <summary>
/// Implemented by bound request models (e.g. JSON bodies) that carry the ALTCHA payload,
/// for endpoints that do not receive form posts.
/// </summary>
public interface IAltchaPayloadCarrier
{
    /// <summary>The base64 ALTCHA payload.</summary>
    string? AltchaPayload { get; }
}

/// <summary>Access to the ALTCHA verification result of a request.</summary>
public static class AltchaHttpContextExtensions
{
    /// <summary>Returns the result set by the ALTCHA filter, or null when the request was not verified.</summary>
    public static AltchaVerificationResult? GetAltchaResult(this HttpContext httpContext)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        return httpContext.Features.Get<IAltchaFeature>()?.Result;
    }

    internal static void SetAltchaResult(this HttpContext httpContext, AltchaVerificationResult result) =>
        httpContext.Features.Set<IAltchaFeature>(new AltchaFeature(result));

    private sealed class AltchaFeature(AltchaVerificationResult result) : IAltchaFeature
    {
        public AltchaVerificationResult Result { get; } = result;
    }
}

/// <summary>Maps the ALTCHA challenge endpoint.</summary>
public static class AltchaEndpointRouteBuilderExtensions
{
    /// <summary>Maps <c>GET <paramref name="pattern"/></c> returning a fresh signed challenge.</summary>
    public static RouteHandlerBuilder MapAltchaChallenge(
        this IEndpointRouteBuilder endpoints,
        [StringSyntax("Route")] string pattern = AltchaDefaults.ChallengePattern)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        return endpoints
            .MapGet(pattern, (HttpContext context, IAltchaService service) =>
            {
                context.Response.Headers.CacheControl = "no-store";
                return Results.Json(service.CreateChallenge(context), AltchaJson.SerializerOptions);
            })
            .WithName(AltchaDefaults.ChallengeEndpointName)
            .ExcludeFromDescription();
    }
}

/// <summary>Adds ALTCHA verification to minimal-API endpoints and route groups.</summary>
public static class AltchaEndpointConventionBuilderExtensions
{
    /// <summary>
    /// Requires a verified ALTCHA payload. When <paramref name="rejectOnFailure"/> is false the handler still runs
    /// and can inspect <see cref="AltchaHttpContextExtensions.GetAltchaResult"/>.
    /// </summary>
    public static TBuilder RequireAltcha<TBuilder>(this TBuilder builder, bool rejectOnFailure = true)
        where TBuilder : IEndpointConventionBuilder
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.AddEndpointFilter(new AltchaEndpointFilter(rejectOnFailure));
        return builder;
    }
}

internal static class AltchaPayloadReader
{
    public static async Task<(string? Payload, Func<string, string?>? GetFieldValue)> ReadAsync(
        HttpContext context,
        string fieldName,
        IEnumerable<object?> boundValues,
        CancellationToken cancellationToken)
    {
        string? payload = null;
        Func<string, string?>? getFieldValue = null;
        if (context.Request.HasFormContentType)
        {
            // ReadFormAsync caches the form, so this is safe after model binding.
            var form = await context.Request.ReadFormAsync(cancellationToken).ConfigureAwait(false);
            payload = form[fieldName].FirstOrDefault();
            getFieldValue = name => form[name].FirstOrDefault();
        }

        payload ??= boundValues.OfType<IAltchaPayloadCarrier>().FirstOrDefault()?.AltchaPayload;
        return (payload, getFieldValue);
    }
}

internal static class AltchaFailure
{
    public static ProblemDetails CreateProblem(AltchaVerificationResult result, int status)
    {
        var problem = new ProblemDetails
        {
            Status = status,
            Title = "ALTCHA verification failed.",
            Detail = result.Error,
        };
        problem.Extensions["code"] = result.ErrorCode?.ToCode();
        return problem;
    }
}
