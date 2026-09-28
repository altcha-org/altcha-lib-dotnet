using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.AspNetCore.Razor.TagHelpers;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Altcha.AspNetCore.Tests;

public class TagHelperTests
{
    [Fact]
    public async Task FillsNameAndSentinelChallengeUrl()
    {
        await using var app = await TestApp.StartAsync(o => o.Sentinel.ChallengeUrl = "https://s/v1/challenge?apiKey=k");

        var output = Process(app.Services);

        Assert.Equal("altcha", output.Attributes["name"].Value);
        Assert.Equal("https://s/v1/challenge?apiKey=k", output.Attributes["challenge"].Value);
    }

    [Fact]
    public async Task FallsBackToMappedChallengeEndpoint()
    {
        await using var app = await TestApp.StartAsync();

        var output = Process(app.Services);

        Assert.Equal("/altcha/challenge", output.Attributes["challenge"].Value);
    }

    [Fact]
    public async Task LeavesPresetAttributesUntouched()
    {
        await using var app = await TestApp.StartAsync(o => o.Sentinel.ChallengeUrl = "https://s/v1/challenge?apiKey=k");

        var output = Process(app.Services, new TagHelperAttribute("name", "custom"), new TagHelperAttribute("challenge", "/mine"));

        Assert.Equal("custom", output.Attributes["name"].Value);
        Assert.Equal("/mine", output.Attributes["challenge"].Value);
        Assert.Equal(2, output.Attributes.Count);
    }

    private static TagHelperOutput Process(IServiceProvider services, params TagHelperAttribute[] attributes)
    {
        var tagHelper = new AltchaWidgetTagHelper(
            services.GetRequiredService<IOptionsMonitor<AltchaOptions>>(),
            services.GetRequiredService<LinkGenerator>())
        {
            ViewContext = new ViewContext { HttpContext = new DefaultHttpContext { RequestServices = services } },
        };
        var output = new TagHelperOutput(
            "altcha-widget",
            new TagHelperAttributeList(attributes),
            (_, _) => Task.FromResult<TagHelperContent>(new DefaultTagHelperContent()));
        tagHelper.Process(new TagHelperContext(new TagHelperAttributeList(attributes), new Dictionary<object, object>(), "id"), output);
        return output;
    }
}
