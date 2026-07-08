using System.Net.Http;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using System.Text;
using PROSCANNERCONT.Services;

namespace PROSCANNERCONT.Security
{
    public class NVDChecker
    {
        private readonly HttpClient _client;
        private readonly HttpClient _openAiClient;

        private const string NVD_API_URL  = "https://services.nvd.nist.gov/rest/json/cves/2.0";
        private static string NVD_API_KEY => SecretsManager.Get(SecretsManager.KeyNvdApiKey);

        private static string OpenAiApiKey      => SecretsManager.Get(SecretsManager.KeyOpenAiApiKey);
        private static string OpenAiApiEndpoint => MainWindow.ApiEndpoint;

        private const int CRITICAL_RISK = 30;
        private const int HIGH_RISK     = 20;
        private const int MEDIUM_RISK   = 15;
        private const int LOW_RISK      = 5;

        private static readonly JsonSerializerOptions _jsonOpts =
            new() { PropertyNameCaseInsensitive = true };

        private readonly Dictionary<string, ServiceNormalizationResult> _normalizationCache = new();

        public NVDChecker()
        {
            _client = new HttpClient();
            _client.Timeout = TimeSpan.FromSeconds(20);

            _openAiClient = new HttpClient();
            if (!string.IsNullOrEmpty(OpenAiApiKey))
                _openAiClient.DefaultRequestHeaders.Add("Authorization", $"Bearer {OpenAiApiKey}");
            _openAiClient.Timeout = TimeSpan.FromSeconds(15);
        }

        // =====================================================================
        // Public entry point
        // =====================================================================
        public async Task<List<SecurityCheck.SecurityIssue>> CheckServiceVulnerabilities(
            string serviceName, string version)
        {
            var allIssues = new List<SecurityCheck.SecurityIssue>();

            try
            {
                // Normalise the service name for searching
                var normalized = await NormalizeServiceWithAI(serviceName, version);

                // Build a de-duplicated set of keywords to search
                var keywords = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                // Most important: service name alone (broadest, most CVEs)
                keywords.Add(normalized.PrimaryServiceName);

                // Service + clean version (specific hits)
                if (!string.IsNullOrWhiteSpace(normalized.CleanVersion))
                    keywords.Add($"{normalized.PrimaryServiceName} {normalized.CleanVersion}");

                // Alternatives (e.g. "apache httpd")
                foreach (var alt in normalized.AlternativeNames.Take(2))
                    keywords.Add(alt);

                // Run searches sequentially to respect rate limits
                foreach (var kw in keywords)
                {
                    var results = await SearchNVD(kw, resultsPerPage: 20);
                    allIssues.AddRange(results);
                    await Task.Delay(300); // stay within NVD rate limit
                }

                // De-duplicate by CVE ID
                var unique = allIssues
                    .GroupBy(i => ExtractCveId(i.Description))
                    .Select(g => g.OrderByDescending(i => i.RiskScore).First())
                    .OrderByDescending(i => i.RiskScore)
                    .ToList();

                return unique;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[NVDChecker] Error: {ex.Message}");
                // Return a single issue that is clearly an error (not "Clean")
                return new List<SecurityCheck.SecurityIssue>
                {
                    new SecurityCheck.SecurityIssue
                    {
                        Category       = "Vulnerability",
                        Description    = $"CVE lookup failed: {ex.Message}",
                        RiskScore      = LOW_RISK,
                        Severity       = "Unknown",
                        Recommendation = "Manual vulnerability check recommended — verify service version against NVD."
                    }
                };
            }
        }

        // =====================================================================
        // NVD search
        // =====================================================================
        private async Task<List<SecurityCheck.SecurityIssue>> SearchNVD(
            string keyword, int resultsPerPage = 20)
        {
            var issues = new List<SecurityCheck.SecurityIssue>();

            if (string.IsNullOrWhiteSpace(keyword)) return issues;

            try
            {
                var url = $"{NVD_API_URL}?keywordSearch={Uri.EscapeDataString(keyword)}" +
                          $"&resultsPerPage={resultsPerPage}";

                // Add the NVD API key per-request only when one is configured. NVD works keyless
                // (lower rate limit); sending an EMPTY apiKey header makes NVD reject the request.
                var request = new HttpRequestMessage(HttpMethod.Get, url);
                if (!string.IsNullOrWhiteSpace(NVD_API_KEY))
                    request.Headers.Add("apiKey", NVD_API_KEY);

                var response = await _client.SendAsync(request);
                if (!response.IsSuccessStatusCode) return issues;

                var json    = await response.Content.ReadAsStringAsync();
                var nvdResp = JsonSerializer.Deserialize<NVDResponse>(json, _jsonOpts);

                if (nvdResp?.Vulnerabilities == null) return issues;

                foreach (var entry in nvdResp.Vulnerabilities)
                {
                    var cve = entry.Cve;
                    if (cve == null) continue;

                    decimal cvss      = ExtractBestCvss(cve.Metrics);
                    string  severity  = CvssToSeverity(cvss);
                    string  desc      = cve.Descriptions
                                          ?.FirstOrDefault(d => d.Lang == "en")?.Value
                                       ?? "No description available";
                    string  reference = cve.References?.FirstOrDefault()?.Url ?? "";

                    issues.Add(new SecurityCheck.SecurityIssue
                    {
                        Category       = "Vulnerability",
                        Description    = $"{cve.Id} - {desc}",
                        RiskScore      = CvssToRiskScore(cvss),
                        Severity       = severity,
                        CvssScore      = cvss,
                        Recommendation = string.IsNullOrEmpty(reference)
                                         ? $"Patch {keyword} to remediate this vulnerability."
                                         : $"Reference: {reference}"
                    });
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[NVDChecker] SearchNVD '{keyword}' error: {ex.Message}");
            }

            return issues;
        }

        // =====================================================================
        // CVSS extraction — tries V3.1, then V3.0, then V2
        // =====================================================================
        private static decimal ExtractBestCvss(NvdMetrics? metrics)
        {
            if (metrics == null) return 0;

            // V3.1 preferred
            var v31 = metrics.CvssMetricV31?.FirstOrDefault()?.CvssData?.BaseScore;
            if (v31.HasValue && v31.Value > 0) return v31.Value;

            // V3.0 fallback
            var v30 = metrics.CvssMetricV30?.FirstOrDefault()?.CvssData?.BaseScore;
            if (v30.HasValue && v30.Value > 0) return v30.Value;

            // V2 fallback
            var v2 = metrics.CvssMetricV2?.FirstOrDefault()?.CvssData?.BaseScore;
            if (v2.HasValue && v2.Value > 0) return v2.Value;

            return 0;
        }

        private static string CvssToSeverity(decimal score) => score switch
        {
            >= 9.0m => "Critical",
            >= 7.0m => "High",
            >= 4.0m => "Medium",
            > 0     => "Low",
            _       => "Unknown"
        };

        private static int CvssToRiskScore(decimal score) => score switch
        {
            >= 9.0m => CRITICAL_RISK,
            >= 7.0m => HIGH_RISK,
            >= 4.0m => MEDIUM_RISK,
            > 0     => LOW_RISK,
            _       => LOW_RISK
        };

        private static string ExtractCveId(string description)
        {
            var m = Regex.Match(description ?? "", @"CVE-\d{4}-\d+");
            return m.Success ? m.Value : description ?? "";
        }

        // =====================================================================
        // AI normalization (best-effort; fallback if AI unavailable)
        // =====================================================================
        private async Task<ServiceNormalizationResult> NormalizeServiceWithAI(
            string serviceName, string version)
        {
            var key = $"{serviceName}|{version}";
            if (_normalizationCache.TryGetValue(key, out var cached)) return cached;

            ServiceNormalizationResult result;

            try
            {
                if (string.IsNullOrEmpty(OpenAiApiKey))
                    throw new InvalidOperationException("No AI key configured");

                var prompt = $"Normalize for NVD CVE search. Return ONLY JSON.\n" +
                             $"Service: \"{serviceName}\"  Version: \"{version}\"\n" +
                             $"{{\"primaryServiceName\":\"name\",\"cleanVersion\":\"ver\"," +
                             $"\"alternativeNames\":[\"alt1\",\"alt2\"]}}";

                var aiJson = await CallOpenAI(prompt);
                result     = ParseAIResponse(aiJson);
            }
            catch
            {
                result = FallbackNormalize(serviceName, version);
            }

            _normalizationCache[key] = result;
            return result;
        }

        private static ServiceNormalizationResult FallbackNormalize(string serviceName, string version)
        {
            var name  = (serviceName ?? "").ToLower().Trim();
            var clean = ExtractVersionNumber(version);

            var alternatives = name switch
            {
                var n when n.Contains("apache") => new List<string> { "apache httpd", "apache2" },
                var n when n.Contains("nginx")  => new List<string> { "nginx" },
                var n when n.Contains("ssh")    => new List<string> { "openssh" },
                var n when n.Contains("mysql")  => new List<string> { "mysql", "mariadb" },
                var n when n.Contains("iis")    => new List<string> { "microsoft iis" },
                var n when n.Contains("ftp")    => new List<string> { "vsftpd", "proftpd" },
                var n when n.Contains("smtp")   => new List<string> { "postfix", "sendmail" },
                _                               => new List<string>()
            };

            return new ServiceNormalizationResult
            {
                PrimaryServiceName = name,
                CleanVersion       = clean,
                AlternativeNames   = alternatives
            };
        }

        private static string ExtractVersionNumber(string version)
        {
            if (string.IsNullOrWhiteSpace(version) || version == "Unknown") return "";
            var m = Regex.Match(version, @"\d+(?:\.\d+)+");
            return m.Success ? m.Value : "";
        }

        private async Task<string> CallOpenAI(string prompt)
        {
            var body = new
            {
                model    = "gpt-3.5-turbo",
                messages = new[]
                {
                    new { role = "system", content = "Return only valid JSON." },
                    new { role = "user",   content = prompt }
                },
                max_tokens  = 120,
                temperature = 0.0
            };

            var content  = new StringContent(
                JsonSerializer.Serialize(body), Encoding.UTF8, "application/json");
            var response = await _openAiClient.PostAsync(OpenAiApiEndpoint, content);

            if (!response.IsSuccessStatusCode)
                throw new Exception($"OpenAI {response.StatusCode}");

            using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            return doc.RootElement
                      .GetProperty("choices")[0]
                      .GetProperty("message")
                      .GetProperty("content")
                      .GetString() ?? "";
        }

        private static ServiceNormalizationResult ParseAIResponse(string raw)
        {
            var clean = raw.Trim();
            if (clean.StartsWith("```")) clean = Regex.Replace(clean, @"```\w*\n?", "").Trim();

            var r = JsonSerializer.Deserialize<ServiceNormalizationResult>(clean, _jsonOpts);
            if (r != null && !string.IsNullOrEmpty(r.PrimaryServiceName))
            {
                r.AlternativeNames ??= new List<string>();
                return r;
            }
            return new ServiceNormalizationResult
            {
                PrimaryServiceName = "unknown",
                CleanVersion       = "",
                AlternativeNames   = new List<string>()
            };
        }

        public void Dispose()
        {
            _client?.Dispose();
            _openAiClient?.Dispose();
        }
    }

    // =========================================================================
    // Models
    // =========================================================================
    public class ServiceNormalizationResult
    {
        public string       PrimaryServiceName { get; set; } = "";
        public string       CleanVersion       { get; set; } = "";
        public List<string> AlternativeNames   { get; set; } = new();
    }

    public class NVDResponse
    {
        public int                    TotalResults   { get; set; }
        public List<VulnerabilityEntry> Vulnerabilities { get; set; } = new();
    }

    public class VulnerabilityEntry
    {
        public CVEData? Cve { get; set; }
    }

    public class CVEData
    {
        public string            Id           { get; set; } = "";
        public List<Description> Descriptions { get; set; } = new();
        public NvdMetrics?       Metrics      { get; set; }
        public List<Reference>   References   { get; set; } = new();
    }

    public class Description
    {
        public string Lang  { get; set; } = "";
        public string Value { get; set; } = "";
    }

    public class NvdMetrics
    {
        // V3.1 — most CVEs published after 2019
        public List<CvssMetricEntry>? CvssMetricV31 { get; set; }
        // V3.0 — transitional period
        public List<CvssMetricEntry>? CvssMetricV30 { get; set; }
        // V2 — older CVEs
        public List<CvssMetricEntry>? CvssMetricV2  { get; set; }
    }

    public class CvssMetricEntry
    {
        public CvssData? CvssData { get; set; }
    }

    public class CvssData
    {
        public decimal BaseScore { get; set; }
    }

    public class Reference
    {
        public string Url { get; set; } = "";
    }
}
