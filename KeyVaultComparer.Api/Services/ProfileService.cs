using System;
using System.Diagnostics;
using System.Text.Json;
using System.Threading.Tasks;
using KeyVaultComparer.Api.Models;

namespace KeyVaultComparer.Api.Services
{
    public class ProfileService
    {
        public async Task<UserProfile> GetProfileAsync()
        {
            var profile = new UserProfile
            {
                Email = "Unknown User",
                SubscriptionName = "Unknown Subscription",
                Initials = "??"
            };

            try
            {
                var processInfo = new ProcessStartInfo("cmd.exe", "/c az account show -o json")
                {
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using var process = Process.Start(processInfo);
                if (process != null)
                {
                    string output = await process.StandardOutput.ReadToEndAsync();
                    await process.WaitForExitAsync();

                    if (!string.IsNullOrWhiteSpace(output))
                    {
                        using var doc = JsonDocument.Parse(output);
                        var root = doc.RootElement;
                        
                        if (root.TryGetProperty("name", out var subName))
                        {
                            profile.SubscriptionName = subName.GetString() ?? profile.SubscriptionName;
                        }
                        
                        if (root.TryGetProperty("user", out var userObj) && userObj.TryGetProperty("name", out var userName))
                        {
                            profile.Email = userName.GetString() ?? profile.Email;
                            profile.Initials = GetInitials(profile.Email);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error fetching profile: {ex.Message}");
            }

            return profile;
        }

        private string GetInitials(string email)
        {
            if (string.IsNullOrWhiteSpace(email)) return "??";
            
            var namePart = email.Split('@')[0];
            var parts = namePart.Split('.');
            if (parts.Length >= 2)
            {
                return $"{parts[0][0]}{parts[1][0]}".ToUpper();
            }
            else if (namePart.Length >= 2)
            {
                return namePart.Substring(0, 2).ToUpper();
            }
            
            return namePart.Substring(0, 1).ToUpper();
        }
    }
}
