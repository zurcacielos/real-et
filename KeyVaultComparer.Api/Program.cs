using Azure.Core;
using Azure.Identity;
using KeyVaultComparer.Api.Models;
using KeyVaultComparer.Api.Services;
using Microsoft.AspNetCore.Mvc;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddOpenApi();

// Register the global TokenCredential
builder.Services.AddSingleton<TokenCredential>(sp => 
{
    // Use AzureCliCredential as the Single Source of Truth for local dev
    return new AzureCliCredential();
});

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

app.Use(async (context, next) =>
{
    try
    {
        await next(context);
    }
    catch (Azure.Identity.CredentialUnavailableException ex)
    {
        context.Response.StatusCode = 401;
        context.Response.ContentType = "application/json";
        await context.Response.WriteAsJsonAsync(new { error = "az_login_required", message = ex.Message });
    }
});

app.MapPost("/api/vaults/keys", async ([FromBody] List<string> vaultUris, KeyVaultService service) =>
{
    var result = await service.GetAllSecretNamesAsync(vaultUris);
    return Results.Ok(result);
})
.WithName("GetVaultKeys");

app.MapPost("/api/vault/values", async ([FromBody] SecretValuesRequest request, KeyVaultService service) =>
{
    var result = await service.GetSecretValuesAsync(request.VaultUri, request.SecretNames);
    return Results.Ok(result);
})
.WithName("GetVaultValues");

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
