using System.Collections.Generic;
using System.Linq;

namespace KeyVaultComparer.Api.Models
{
    public class VaultComparisonRequest
    {
        public List<string> VaultUris { get; set; } = new();
    }

    public class SecretComparisonRow
    {
        public string SecretName { get; set; } = string.Empty;
        
        // Key is Vault URI, Value is the status/value from that vault
        public Dictionary<string, SecretValueStatus> VaultValues { get; set; } = new();
        
        public string GlobalStatus { get; set; } = "Missing"; // Match, Mismatch, Missing
    }

    public class SecretValueStatus
    {
        public string? Value { get; set; }
        
        /// <summary>
        /// "Match", "Mismatch", "Missing"
        /// </summary>
        public string Status { get; set; } = "Missing";
    }
}
