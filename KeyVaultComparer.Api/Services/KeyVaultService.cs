using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using KeyVaultComparer.Api.Models;

namespace KeyVaultComparer.Api.Services
{
    public class KeyVaultService
    {
        private readonly DefaultAzureCredential _credential;

        public KeyVaultService()
        {
            _credential = new DefaultAzureCredential();
        }

        public async Task<List<SecretComparisonRow>> CompareVaultsAsync(VaultComparisonRequest request)
        {
            if (request.VaultUris == null || !request.VaultUris.Any())
            {
                return new List<SecretComparisonRow>();
            }

            var allSecrets = new ConcurrentDictionary<string, SecretComparisonRow>();
            var tasks = new List<Task>();

            foreach (var uri in request.VaultUris)
            {
                tasks.Add(FetchSecretsFromVaultAsync(uri, allSecrets));
            }

            await Task.WhenAll(tasks);

            // Compute global status for each row
            var results = allSecrets.Values.OrderBy(s => s.SecretName).ToList();
            foreach (var row in results)
            {
                // Ensure every requested vault has an entry in VaultValues
                foreach (var uri in request.VaultUris)
                {
                    if (!row.VaultValues.ContainsKey(uri))
                    {
                        row.VaultValues[uri] = new SecretValueStatus { Status = "Missing", Value = null };
                    }
                }

                row.GlobalStatus = ComputeGlobalStatus(row.VaultValues.Values);
            }

            return results;
        }

        private async Task FetchSecretsFromVaultAsync(string vaultUri, ConcurrentDictionary<string, SecretComparisonRow> allSecrets)
        {
            try
            {
                var client = new SecretClient(new Uri(vaultUri), _credential);
                
                // Fetch all properties (keys) first
                var secretProperties = new List<SecretProperties>();
                await foreach (var secretProp in client.GetPropertiesOfSecretsAsync())
                {
                    if (secretProp.Enabled.GetValueOrDefault())
                    {
                        secretProperties.Add(secretProp);
                    }
                }

                // Fetch the actual values in parallel (be careful with rate limits if vault is huge, but fine for local tool)
                var fetchTasks = secretProperties.Select(async prop => 
                {
                    try 
                    {
                        KeyVaultSecret secret = await client.GetSecretAsync(prop.Name);
                        
                        var row = allSecrets.GetOrAdd(prop.Name, name => new SecretComparisonRow 
                        { 
                            SecretName = name 
                        });

                        lock (row.VaultValues)
                        {
                            row.VaultValues[vaultUri] = new SecretValueStatus 
                            { 
                                Value = secret.Value, 
                                Status = "Present" 
                            };
                        }
                    }
                    catch (Exception)
                    {
                        // Handle access denied or other errors for individual secrets
                    }
                });

                await Task.WhenAll(fetchTasks);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error fetching from {vaultUri}: {ex.Message}");
                // In a real app, we might return this error to the UI
            }
        }

        private string ComputeGlobalStatus(IEnumerable<SecretValueStatus> statuses)
        {
            var statusList = statuses.ToList();
            
            if (statusList.Any(s => s.Status == "Missing"))
            {
                return "Missing";
            }

            var firstValue = statusList.First().Value;
            if (statusList.All(s => s.Value == firstValue))
            {
                return "Match";
            }

            return "Mismatch";
        }
    }
}
