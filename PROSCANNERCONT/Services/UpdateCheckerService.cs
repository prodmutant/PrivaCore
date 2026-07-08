using System;
using System.Diagnostics;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;

namespace PROSCANNERCONT.Services
{
    public class UpdateInfo
    {
        public string CurrentVersion { get; set; } = "1.0.0";
        public string LatestVersion { get; set; } = string.Empty;
        public string ReleaseNotes { get; set; } = string.Empty;
        public string DownloadUrl { get; set; } = string.Empty;
        public bool UpdateAvailable { get; set; }
        public bool CheckFailed { get; set; }
    }

    public static class UpdateCheckerService
    {
        public const string CurrentVersion = "1.0.0";

        // Points at the public PrivaCore repo's latest release. Override at runtime if you fork it.
        public static string GitHubApiUrl { get; set; } = "https://api.github.com/repos/prodmutant/PrivaCore/releases/latest";

        private static bool IsConfigured =>
            !string.IsNullOrWhiteSpace(GitHubApiUrl) &&
            !GitHubApiUrl.Contains("YOURUSER");

        public static async Task<UpdateInfo> CheckForUpdateAsync()
        {
            var info = new UpdateInfo { CurrentVersion = CurrentVersion };

            if (!IsConfigured)
            {
                info.CheckFailed = true;
                return info;
            }

            try
            {
                using var client = new HttpClient();
                client.DefaultRequestHeaders.Add("User-Agent", "PrivaCore-UpdateChecker");
                client.Timeout = TimeSpan.FromSeconds(10);

                var response = await client.GetStringAsync(GitHubApiUrl);
                using var doc = JsonDocument.Parse(response);
                var root = doc.RootElement;

                var tag = root.GetProperty("tag_name").GetString() ?? "";
                var latestVersion = tag.TrimStart('v');
                var notes = root.TryGetProperty("body", out var bodyEl) ? bodyEl.GetString() ?? "" : "";
                var url = root.TryGetProperty("html_url", out var urlEl) ? urlEl.GetString() ?? "" : "";

                info.LatestVersion = latestVersion;
                info.ReleaseNotes = notes;
                info.DownloadUrl = url;
                info.UpdateAvailable = IsNewer(latestVersion, CurrentVersion);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[UpdateCheckerService] {ex.Message}");
                info.CheckFailed = true;
            }
            return info;
        }

        private static bool IsNewer(string latest, string current)
        {
            if (!Version.TryParse(latest, out var l) || !Version.TryParse(current, out var c))
                return false;
            return l > c;
        }
    }
}
