using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Azure.Security.KeyVault.Secrets;
using KeyVaultComparer.Api.Models;

namespace KeyVaultComparer.Api.Services
{
    public class KeyVaultService
    {
        private readonly Azure.Core.TokenCredential _credential;

        public KeyVaultService(Azure.Core.TokenCredential credential)
        {
            _credential = credential;
        }

        public async Task<Dictionary<string, List<string>>> GetAllSecretNamesAsync(List<string> vaultUris)
        {
            var results = new ConcurrentDictionary<string, List<string>>();

            if (vaultUris == null || !vaultUris.Any())
            {
                return new Dictionary<string, List<string>>();
            }

            var propTasks = vaultUris.Select(async uri =>
            {
                var vaultNames = new List<string>();
                try
                {
                    var client = new SecretClient(new Uri(uri), _credential);
                    await foreach (var secretProp in client.GetPropertiesOfSecretsAsync())
                    {
                        if (secretProp.Enabled.GetValueOrDefault())
                        {
                            vaultNames.Add(secretProp.Name);
                        }
                    }
                    results[uri] = vaultNames;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error fetching properties from {uri}: {ex.Message}");
                    results[uri] = vaultNames;
                }
            });

            await Task.WhenAll(propTasks);
            
            return results.ToDictionary(kvp => kvp.Key, kvp => kvp.Value.OrderBy(n => n).ToList());
        }

        public async Task<Dictionary<string, SecretValueStatus>> GetSecretValuesAsync(string vaultUri, List<string> secretNames)
        {
            var results = new ConcurrentDictionary<string, SecretValueStatus>();

            if (string.IsNullOrWhiteSpace(vaultUri) || secretNames == null || !secretNames.Any())
            {
                return new Dictionary<string, SecretValueStatus>();
            }

            try
            {
                var client = new SecretClient(new Uri(vaultUri), _credential);
                var fetchTasks = secretNames.Select(async name =>
                {
                    try
                    {
                        KeyVaultSecret secret = await client.GetSecretAsync(name);
                        results[name] = new SecretValueStatus
                        {
                            Value = secret.Value,
                            Status = "Present"
                        };
                    }
                    catch (Azure.RequestFailedException ex) when (ex.Status == 404)
                    {
                        // Secret not found in this specific vault
                        results[name] = new SecretValueStatus
                        {
                            Value = null,
                            Status = "Missing"
                        };
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Error fetching secret {name} from {vaultUri}: {ex.Message}");
                        results[name] = new SecretValueStatus
                        {
                            Value = null,
                            Status = "Error"
                        };
                    }
                });

                await Task.WhenAll(fetchTasks);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error creating client for {vaultUri}: {ex.Message}");
            }

            return results.ToDictionary(kvp => kvp.Key, kvp => kvp.Value);
        }
    }
}
