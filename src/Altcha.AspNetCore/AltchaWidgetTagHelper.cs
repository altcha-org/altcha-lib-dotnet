using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using Microsoft.AspNetCore.Razor.TagHelpers;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Options;

namespace Altcha.AspNetCore;

/// <summary>
/// Fills in <c>name</c> and <c>challenge</c> on <c>&lt;altcha-widget&gt;</c> when they are not set explicitly.
/// <c>challenge</c> is <see cref="AltchaSentinelOptions.ChallengeUrl"/> if configured, otherwise the mapped challenge endpoint.
/// Register with <c>@addTagHelper *, Altcha.AspNetCore</c>. The widget script is not injected.
/// </summary>
[HtmlTargetElement("altcha-widget")]
public sealed class AltchaWidgetTagHelper : TagHelper
{
    private readonly IOptionsMonitor<AltchaOptions> _options;
    private readonly LinkGenerator _links;

    /// <summary>Creates the tag helper.</summary>
    public AltchaWidgetTagHelper(IOptionsMonitor<AltchaOptions> options, LinkGenerator links)
    {
        _options = options;
        _links = links;
    }

    /// <summary>The current view context.</summary>
    [ViewContext]
    [HtmlAttributeNotBound]
    public ViewContext ViewContext { get; set; } = default!;

    /// <inheritdoc />
    public override void Process(TagHelperContext context, TagHelperOutput output)
    {
        var options = _options.CurrentValue;
        if (!output.Attributes.ContainsName("name"))
        {
            output.Attributes.SetAttribute("name", options.FieldName);
        }

        if (!output.Attributes.ContainsName("challenge"))
        {
            var challengeUrl = !string.IsNullOrEmpty(options.Sentinel.ChallengeUrl)
                ? options.Sentinel.ChallengeUrl
                : _links.GetPathByName(ViewContext.HttpContext, AltchaDefaults.ChallengeEndpointName, values: null);
            if (challengeUrl is not null)
            {
                output.Attributes.SetAttribute("challenge", challengeUrl);
            }
        }
    }
}
