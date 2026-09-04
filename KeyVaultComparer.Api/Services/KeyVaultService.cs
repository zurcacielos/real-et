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

            // Phase 1: Fetch properties from all vaults to get a master list of keys
            var allPropertyNames = new HashSet<string>();
            var propTasks = request.VaultUris.Select(async uri =>
            {
                try
                {
                    var client = new SecretClient(new Uri(uri), _credential);
                    await foreach (var secretProp in client.GetPropertiesOfSecretsAsync())
                    {
                        if (secretProp.Enabled.GetValueOrDefault())
                        {
                            lock (allPropertyNames)
                            {
                                allPropertyNames.Add(secretProp.Name);
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error fetching properties from {uri}: {ex.Message}");
                }
            });
            await Task.WhenAll(propTasks);

            // Phase 2: Apply Filters and Limits
            IEnumerable<string> filteredNames = allPropertyNames;
            
            if (!string.IsNullOrWhiteSpace(request.NameFilter))
            {
                var filters = request.NameFilter.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                
                filteredNames = filteredNames.Where(name => 
                {
                    foreach (var f in filters)
                    {
                        try 
                        {
                            if (System.Text.RegularExpressions.Regex.IsMatch(name, f, System.Text.RegularExpressions.RegexOptions.IgnoreCase))
                                return true;
                        }
                        catch 
                        {
                            // fallback to literal contains if regex is invalid
                            if (name.Contains(f, StringComparison.OrdinalIgnoreCase))
                                return true;
                        }
                    }
                    return false;
                });
            }

            var finalNames = filteredNames.OrderBy(n => n).ToList();
            if (request.Limit > 0)
            {
                finalNames = finalNames.Take(request.Limit).ToList();
            }

            // Initialize rows
            var allSecrets = new ConcurrentDictionary<string, SecretComparisonRow>();
            foreach (var name in finalNames)
            {
                allSecrets[name] = new SecretComparisonRow { SecretName = name };
            }

            // Phase 3: Fetch exact values from all vaults concurrently
            var fetchTasks = request.VaultUris.Select(async uri =>
            {
                try
                {
                    var client = new SecretClient(new Uri(uri), _credential);
                    var vaultFetchTasks = finalNames.Select(async name =>
                    {
                        try
                        {
                            KeyVaultSecret secret = await client.GetSecretAsync(name);
                            var row = allSecrets[name];
                            lock (row.VaultValues)
                            {
                                row.VaultValues[uri] = new SecretValueStatus
                                {
                                    Value = secret.Value,
                                    Status = "Present"
                                };
                            }
                        }
                        catch (Azure.RequestFailedException ex) when (ex.Status == 404)
                        {
                            // Secret not found in this specific vault
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"Error fetching secret {name} from {uri}: {ex.Message}");
                        }
                    });
                    await Task.WhenAll(vaultFetchTasks);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error creating client for {uri}: {ex.Message}");
                }
            });
            await Task.WhenAll(fetchTasks);

            // Compute global status and ColorIndex for each row
            var results = allSecrets.Values.OrderBy(s => s.SecretName).ToList();
            foreach (var row in results)
            {
                // Ensure every requested vault has an entry in VaultValues
                foreach (var uri in request.VaultUris)
                {
                    if (!row.VaultValues.ContainsKey(uri))
                    {
                        row.VaultValues[uri] = new SecretValueStatus { Status = "Missing", Value = null, ColorIndex = 0 };
                    }
                }

                // Compute ColorIndex
                var distinctValues = row.VaultValues.Values
                    .Where(v => v.Status != "Missing" && v.Value != null)
                    .Select(v => v.Value)
                    .Distinct()
                    .ToList();

                foreach (var status in row.VaultValues.Values)
                {
                    if (status.Status == "Missing" || status.Value == null)
                    {
                        status.ColorIndex = 0;
                    }
                    else
                    {
                        status.ColorIndex = distinctValues.IndexOf(status.Value) + 1;
                    }
                }

                row.GlobalStatus = ComputeGlobalStatus(row.VaultValues.Values);
            }

            return results;
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
