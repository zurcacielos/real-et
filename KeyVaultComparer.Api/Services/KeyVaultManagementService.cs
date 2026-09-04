using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Azure.Identity;
using Azure.ResourceManager;
using Azure.ResourceManager.KeyVault;
using Azure.ResourceManager.ResourceGraph;
using Azure.ResourceManager.ResourceGraph.Models;
using KeyVaultComparer.Api.Models;

namespace KeyVaultComparer.Api.Services
{
    public class KeyVaultManagementService
    {
        public async Task<List<DiscoveredVault>> GetAvailableVaultsAsync(string? query, string? subscriptionId = null)
        {
            var vaults = new List<DiscoveredVault>();
            
            if (string.IsNullOrWhiteSpace(query) || query.Trim().Length < 2)
            {
                // Safety guard: Never query Azure if the search string is too short or empty
                return vaults;
            }

            var client = new ArmClient(new AzureCliCredential());

            try
            {
                var tenant = client.GetTenants().First();

                // Build KQL Query for Azure Resource Graph
                var queryBuilder = new System.Text.StringBuilder();
                queryBuilder.AppendLine("Resources");
                queryBuilder.AppendLine("| where type =~ 'microsoft.keyvault/vaults'");
                
                // Server-side text filtering
                if (!string.IsNullOrWhiteSpace(query))
                {
                    // Escape single quotes for safety
                    var safeQuery = query.Replace("'", @"\'");
                    queryBuilder.AppendLine($"| where name contains '{safeQuery}'");
                }
                
                queryBuilder.AppendLine("| project name, properties.vaultUri");
                queryBuilder.AppendLine("| take 100");

                var queryContent = new ResourceQueryContent(queryBuilder.ToString());

                // Apply subscription filter natively to ARG
                if (!string.IsNullOrWhiteSpace(subscriptionId))
                {
                    queryContent.Subscriptions.Add(subscriptionId);
                }

                var response = await tenant.GetResourcesAsync(queryContent);
                
                if (response.Value != null && response.Value.Data != null)
                {
                    using var doc = System.Text.Json.JsonDocument.Parse(response.Value.Data);
                    foreach (var item in doc.RootElement.EnumerateArray())
                    {
                        var name = item.GetProperty("name").GetString();
                        
                        var props = item.GetProperty("properties");
                        var vaultUri = props.TryGetProperty("vaultUri", out var uriProp) ? uriProp.GetString() : null;

                        if (!string.IsNullOrEmpty(name) && !string.IsNullOrEmpty(vaultUri))
                        {
                            vaults.Add(new DiscoveredVault
                            {
                                Name = name,
                                Uri = vaultUri
                            });
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error fetching vaults from Resource Graph: {ex.Message}");
            }

            return vaults;
        }

        public async Task<List<AzureSubscription>> GetSubscriptionsAsync()
        {
            var subs = new List<AzureSubscription>();
            try
            {
                var client = new ArmClient(new AzureCliCredential());
                await foreach (var sub in client.GetSubscriptions().GetAllAsync())
                {
                    subs.Add(new AzureSubscription
                    {
                        Id = sub.Data.SubscriptionId,
                        Name = sub.Data.DisplayName
                    });
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error fetching subscriptions: {ex.Message}");
            }
            return subs;
        }
    }
}
