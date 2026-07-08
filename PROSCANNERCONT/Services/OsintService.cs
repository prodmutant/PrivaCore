using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace PROSCANNERCONT.Services
{
    public sealed class CrtShEntry
    {
        public string CommonName { get; set; } = "";
        public string IssuerName { get; set; } = "";
        public string NameValue { get; set; } = "";
        public DateTime? NotAfter { get; set; }
    }

    public sealed class ShodanHostResult
    {
        public string Ip { get; set; } = "";
        public List<int> Ports { get; } = new();
        public string? Country { get; set; }
        public string? Org { get; set; }
        public string? Os { get; set; }
        public List<string> Hostnames { get; } = new();
        public List<string> Vulns { get; } = new();
        public string? Raw { get; set; }
    }

    /// <summary>
    /// Passive open-source intelligence service. All checks are read-only
    /// queries to public APIs / DNS — nothing here touches the target host
    /// directly. API-key-bearing services (Shodan, VirusTotal) are skipped
    /// if SecretsManager has no key.
    /// </summary>
    public sealed class OsintService
    {
        private readonly HttpClient _http;

        public OsintService()
        {
            _http = new HttpClient { Timeout = TimeSpan.FromSeconds(15) };
            _http.DefaultRequestHeaders.UserAgent.ParseAdd("PrivaCore-OSINT/1.0");
        }

        // ── crt.sh certificate transparency ─────────────────────────────────
        public async Task<List<CrtShEntry>> CertTransparencyAsync(string domain)
        {
            var url = $"https://crt.sh/?q=%25.{Uri.EscapeDataString(domain)}&output=json";
            try
            {
                var json = await _http.GetStringAsync(url);
                using var doc = JsonDocument.Parse(json);
                var list = new List<CrtShEntry>();
                foreach (var item in doc.RootElement.EnumerateArray().Take(500))
                {
                    var e = new CrtShEntry
                    {
                        CommonName = item.TryGetProperty("common_name",   out var cn) ? cn.GetString() ?? "" : "",
                        IssuerName = item.TryGetProperty("issuer_name",   out var iss) ? iss.GetString() ?? "" : "",
                        NameValue  = item.TryGetProperty("name_value",    out var nv) ? nv.GetString() ?? "" : "",
                    };
                    if (item.TryGetProperty("not_after", out var na) && DateTime.TryParse(na.GetString(), out var d)) e.NotAfter = d;
                    list.Add(e);
                }
                return list;
            }
            catch (Exception ex)
            {
                AppLogger.Log.Warning(ex, "[OSINT/crt.sh]");
                return new();
            }
        }

        // ── WHOIS via whois.iana.org → authoritative server chain ──────────
        public async Task<string> WhoisAsync(string domain)
        {
            try
            {
                var ianaResponse = await WhoisQuery("whois.iana.org", domain);
                var refer = ianaResponse.Split('\n').FirstOrDefault(l => l.TrimStart().StartsWith("refer:", StringComparison.OrdinalIgnoreCase));
                if (refer != null)
                {
                    var server = refer.Split(':')[1].Trim();
                    return await WhoisQuery(server, domain);
                }
                return ianaResponse;
            }
            catch (Exception ex)
            {
                AppLogger.Log.Warning(ex, "[OSINT/whois]");
                return $"WHOIS failed: {ex.Message}";
            }
        }

        private static async Task<string> WhoisQuery(string server, string query)
        {
            using var tcp = new TcpClient();
            await tcp.ConnectAsync(server, 43);
            using var ns = tcp.GetStream();
            var bytes = Encoding.ASCII.GetBytes(query + "\r\n");
            await ns.WriteAsync(bytes);
            using var ms = new System.IO.MemoryStream();
            var buf = new byte[4096];
            int n;
            while ((n = await ns.ReadAsync(buf)) > 0) ms.Write(buf, 0, n);
            return Encoding.UTF8.GetString(ms.ToArray());
        }

        // ── Have I Been Pwned password (k-anonymity, no key required) ──────
        public async Task<int> HibpPasswordCountAsync(string password)
        {
            var sha = Convert.ToHexString(SHA1.HashData(Encoding.UTF8.GetBytes(password))).ToUpperInvariant();
            var prefix = sha[..5];
            var suffix = sha[5..];
            try
            {
                var text = await _http.GetStringAsync($"https://api.pwnedpasswords.com/range/{prefix}");
                foreach (var line in text.Split('\n'))
                {
                    var parts = line.Trim().Split(':');
                    if (parts.Length == 2 && parts[0].Equals(suffix, StringComparison.OrdinalIgnoreCase))
                        return int.Parse(parts[1]);
                }
                return 0;
            }
            catch (Exception ex)
            {
                AppLogger.Log.Warning(ex, "[OSINT/HIBP]");
                return -1;
            }
        }

        // ── Shodan host lookup (requires API key) ───────────────────────────
        public async Task<ShodanHostResult?> ShodanHostAsync(string ip)
        {
            var key = SecretsManager.Get(SecretsManager.KeyShodanApiKey);
            if (string.IsNullOrEmpty(key)) return null;

            var url = $"https://api.shodan.io/shodan/host/{ip}?key={key}";
            try
            {
                var json = await _http.GetStringAsync(url);
                using var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;
                var result = new ShodanHostResult { Ip = ip, Raw = json };
                if (root.TryGetProperty("country_name", out var c)) result.Country = c.GetString();
                if (root.TryGetProperty("org",          out var o)) result.Org     = o.GetString();
                if (root.TryGetProperty("os",           out var os)) result.Os    = os.GetString();
                if (root.TryGetProperty("ports", out var p))
                    foreach (var pp in p.EnumerateArray()) result.Ports.Add(pp.GetInt32());
                if (root.TryGetProperty("hostnames", out var hn))
                    foreach (var h in hn.EnumerateArray()) result.Hostnames.Add(h.GetString() ?? "");
                if (root.TryGetProperty("vulns", out var v) && v.ValueKind == JsonValueKind.Array)
                    foreach (var vv in v.EnumerateArray()) result.Vulns.Add(vv.GetString() ?? "");
                return result;
            }
            catch (Exception ex)
            {
                AppLogger.Log.Warning(ex, "[OSINT/Shodan]");
                return null;
            }
        }

        // ── VirusTotal hash lookup (requires API key) ───────────────────────
        public async Task<string?> VtHashLookupAsync(string sha256)
        {
            var key = SecretsManager.Get(SecretsManager.KeyVirusTotalKey);
            if (string.IsNullOrEmpty(key)) return null;

            using var req = new HttpRequestMessage(HttpMethod.Get, $"https://www.virustotal.com/api/v3/files/{sha256}");
            req.Headers.Add("x-apikey", key);
            try
            {
                using var resp = await _http.SendAsync(req);
                if (!resp.IsSuccessStatusCode) return null;
                return await resp.Content.ReadAsStringAsync();
            }
            catch (Exception ex)
            {
                AppLogger.Log.Warning(ex, "[OSINT/VT]");
                return null;
            }
        }
    }
}
