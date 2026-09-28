using Altcha.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddRazorPages();
builder.Services.AddAltcha(builder.Configuration.GetSection(AltchaDefaults.ConfigurationSection));

var app = builder.Build();

app.UseStaticFiles();
app.MapAltchaChallenge();
app.MapPost("/api/submit", (HttpContext c) => Results.Ok(new { verified = true, type = c.GetAltchaResult()!.PayloadType.ToString() }))
    .RequireAltcha();
app.MapRazorPages();

app.Run();
