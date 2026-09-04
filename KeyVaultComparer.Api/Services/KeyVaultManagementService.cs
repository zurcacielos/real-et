using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Azure.Identity;
using Azure.ResourceManager;
using Azure.ResourceManager.KeyVault;
using KeyVaultComparer.Api.Models;

namespace KeyVaultComparer.Api.Services
{
    public class KeyVaultManagementService
    {
        public async Task<List<DiscoveredVault>> GetAvailableVaultsAsync(string? query)
        {
            var vaults = new List<DiscoveredVault>();
            var client = new ArmClient(new AzureCliCredential());

            try
            {
                var subscriptions = client.GetSubscriptions();
                var subCount = 0;
                await foreach (var sub in subscriptions.GetAllAsync())
                {
                    subCount++;
                    Console.WriteLine($"Found subscription: {sub.Data.DisplayName} ({sub.Data.SubscriptionId})");
                    var vaultCount = 0;
                    await foreach (var vault in sub.GetKeyVaultsAsync())
                    {
                        if (vaults.Count >= 100) break;

                        if (vault.Data.Properties.VaultUri != null)
                        {
                            var vaultName = vault.Data.Name;
                            if (!string.IsNullOrWhiteSpace(query) && !vaultName.Contains(query, StringComparison.OrdinalIgnoreCase))
                            {
                                continue;
                            }
                            vaults.Add(new DiscoveredVault
                            {
                                Name = vault.Data.Name,
                                Uri = vault.Data.Properties.VaultUri.ToString()
                            });
                        }
                    }
                    Console.WriteLine($"Found {vaultCount} vaults in subscription.");
                }
                Console.WriteLine($"Total subscriptions checked: {subCount}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error fetching vaults: {ex.Message}");
            }

            return vaults;
        }
    }
}
