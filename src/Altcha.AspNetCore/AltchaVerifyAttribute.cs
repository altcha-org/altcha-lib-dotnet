using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Altcha.AspNetCore;

/// <summary>
/// Requires a verified ALTCHA payload for MVC actions and Razor Pages handlers. On pages, GET/HEAD/OPTIONS/TRACE
/// handlers are skipped so a page-level attribute does not block rendering.
/// </summary>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = false)]
public sealed class AltchaVerifyAttribute : Attribute, IFilterFactory, IOrderedFilter
{
    /// <summary>
    /// When true (default), failures short-circuit with a problem response. When false, the error is added to
    /// ModelState under <see cref="AltchaOptions.FieldName"/> and the action runs.
    /// </summary>
    public bool RejectOnFailure { get; set; } = true;

    /// <inheritdoc />
    public int Order { get; set; }

    /// <inheritdoc />
    public bool IsReusable => false;

    /// <inheritdoc />
    public IFilterMetadata CreateInstance(IServiceProvider serviceProvider) =>
        new AltchaMvcFilter(
            serviceProvider.GetRequiredService<IAltchaService>(),
            serviceProvider.GetRequiredService<IOptionsMonitor<AltchaOptions>>(),
            RejectOnFailure);
}

internal sealed class AltchaMvcFilter : IAsyncActionFilter, IAsyncPageFilter
{
    private readonly IAltchaService _service;
    private readonly IOptionsMonitor<AltchaOptions> _options;
    private readonly bool _rejectOnFailure;

    public AltchaMvcFilter(IAltchaService service, IOptionsMonitor<AltchaOptions> options, bool rejectOnFailure)
    {
        _service = service;
        _options = options;
        _rejectOnFailure = rejectOnFailure;
    }

    public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
    {
        if (await VerifyAsync(context.HttpContext, context.ModelState, context.ActionArguments.Values) is { } rejection)
        {
            context.Result = rejection;
            return;
        }

        await next();
    }

    public Task OnPageHandlerSelectionAsync(PageHandlerSelectedContext context) => Task.CompletedTask;

    public async Task OnPageHandlerExecutionAsync(PageHandlerExecutingContext context, PageHandlerExecutionDelegate next)
    {
        var method = context.HttpContext.Request.Method;
        if (HttpMethods.IsGet(method) || HttpMethods.IsHead(method) || HttpMethods.IsOptions(method) || HttpMethods.IsTrace(method))
        {
            await next();
            return;
        }

        var boundValues = context.HandlerArguments.Values.Append(context.HandlerInstance);
        if (await VerifyAsync(context.HttpContext, context.ModelState, boundValues) is { } rejection)
        {
            context.Result = rejection;
            return;
        }

        await next();
    }

    /// <summary>Verifies the request; returns a result to short-circuit with, or null to continue.</summary>
    private async Task<IActionResult?> VerifyAsync(HttpContext httpContext, ModelStateDictionary modelState, IEnumerable<object?> boundValues)
    {
        var options = _options.CurrentValue;
        var (payload, getFieldValue) = await AltchaPayloadReader
            .ReadAsync(httpContext, options.FieldName, boundValues, httpContext.RequestAborted);
        var result = await _service.VerifyAsync(payload, getFieldValue, httpContext.RequestAborted);
        httpContext.SetAltchaResult(result);
        if (result.Verified)
        {
            return null;
        }

        if (_rejectOnFailure)
        {
            return new ObjectResult(AltchaFailure.CreateProblem(result, options.FailureStatusCode))
            {
                StatusCode = options.FailureStatusCode,
            };
        }

        modelState.AddModelError(options.FieldName, result.Error!);
        return null;
    }
}
