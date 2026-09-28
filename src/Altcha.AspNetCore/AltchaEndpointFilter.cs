using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Altcha.AspNetCore;

/// <summary>
/// Endpoint filter that verifies the ALTCHA payload from the form field or an <see cref="IAltchaPayloadCarrier"/> argument.
/// Applies to every HTTP method, since it is opted into per endpoint.
/// </summary>
internal sealed class AltchaEndpointFilter : IEndpointFilter
{
    private readonly bool _rejectOnFailure;

    /// <summary>Creates the filter.</summary>
    public AltchaEndpointFilter(bool rejectOnFailure)
    {
        _rejectOnFailure = rejectOnFailure;
    }

    /// <inheritdoc />
    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        var httpContext = context.HttpContext;
        var service = httpContext.RequestServices.GetRequiredService<IAltchaService>();
        var options = httpContext.RequestServices.GetRequiredService<IOptionsMonitor<AltchaOptions>>().CurrentValue;

        var (payload, getFieldValue) = await AltchaPayloadReader
            .ReadAsync(httpContext, options.FieldName, context.Arguments, httpContext.RequestAborted)
            .ConfigureAwait(false);
        var result = await service.VerifyAsync(payload, getFieldValue, httpContext.RequestAborted).ConfigureAwait(false);
        httpContext.SetAltchaResult(result);

        if (!result.Verified && _rejectOnFailure)
        {
            return Results.Problem(AltchaFailure.CreateProblem(result, options.FailureStatusCode));
        }

        return await next(context).ConfigureAwait(false);
    }
}
