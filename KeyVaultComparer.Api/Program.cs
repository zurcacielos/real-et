using KeyVaultComparer.Api.Models;
using KeyVaultComparer.Api.Services;
using Microsoft.AspNetCore.Mvc;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddOpenApi();
builder.Services.AddSingleton<KeyVaultService>();
builder.Services.AddSingleton<KeyVaultManagementService>();
builder.Services.AddSingleton<ProfileService>();

// Enable CORS for Vue dev server
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        policy.WithOrigins("http://localhost:5173", "http://localhost:3000") // Common Vite ports
              .AllowAnyHeader()
              .AllowAnyMethod();
    });
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();
app.UseCors();

app.MapPost("/api/compare", async ([FromBody] VaultComparisonRequest request, KeyVaultService service) =>
{
    var result = await service.CompareVaultsAsync(request);
    return Results.Ok(result);
})
.WithName("CompareVaults");

app.MapGet("/api/vaults", async ([FromQuery] string? query, [FromQuery] string? subscriptionId, KeyVaultManagementService service) =>
{
    var vaults = await service.GetAvailableVaultsAsync(query, subscriptionId);
    return Results.Ok(vaults);
})
.WithName("GetVaults");

app.MapGet("/api/profile", async (ProfileService service) =>
{
    var profile = await service.GetProfileAsync();
    return Results.Ok(profile);
})
.WithName("GetProfile");

app.MapGet("/api/subscriptions", async (KeyVaultManagementService service) =>
{
    var subs = await service.GetSubscriptionsAsync();
    return Results.Ok(subs);
})
.WithName("GetSubscriptions");

app.Run();
