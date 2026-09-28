using Altcha.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddRazorPages();

// Sentinel issues and signs the challenges, so no HmacSignatureSecret is configured and no
// challenge endpoint is mapped. Payloads are verified by Sentinel's /v1/verify/signature API.
builder.Services.AddAltcha(builder.Configuration.GetSection(AltchaDefaults.ConfigurationSection));

var app = builder.Build();

app.MapPost("/api/submit", (HttpContext context) =>
    {
        var data = context.GetAltchaResult()!.VerificationData;
        return Results.Ok(new
        {
            verified = true,
            classification = data?.Classification,
            score = data?.Score,
            countryCode = data?.Location?.CountryCode,
        });
    })
    .RequireAltcha();
app.MapRazorPages();

app.Run();
