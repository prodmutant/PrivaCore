using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using PROSCANNERCONT.Utils;

namespace PROSCANNERCONT.Services
{
    public sealed record ThreatIntelHit(string Source, string Indicator, string Type, string? Tag, string? Description);

    /// <summary>
    /// Pulls open threat-intelligence feeds and exposes a fast in-memory lookup
    /// keyed by IPv4 / domain / SHA256.  Used by IDSManager to enrich alerts
    /// with ThreatIntelTags = "feodo-c2; urlhaus-malware".  Feeds refresh every
    /// 6 h to a cache directory under %APPDATA%\PrivaCore\threatintel\.
    ///
    /// Currently bundled feeds (all free, public, no auth required):
    ///   • abuse.ch Feodo Tracker — botnet C2 IPs
    ///   • abuse.ch URLhaus       — malware delivery URLs / hosts
    ///   • abuse.ch ThreatFox     — multi-platform IoCs (IP / hash / domain)
    ///
    /// Additional feeds (OTX, MISP) can be added with API keys via SecretsManager.
    /// </summary>
    public sealed class ThreatIntelService : IDisposable
    {
        private static readonly Lazy<ThreatIntelService> _instance = new(() => new ThreatIntelService());
        public static ThreatIntelService Instance => _instance.Value;

        private readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(45) };
        private readonly string _cacheDir = Path.Combine(AppConstants.Paths.AppDataDir, "threatintel");
        private readonly ConcurrentDictionary<string, List<ThreatIntelHit>> _byIp     = new(StringComparer.OrdinalIgnoreCase);
        private readonly ConcurrentDictionary<string, List<ThreatIntelHit>> _byDomain = new(StringComparer.OrdinalIgnoreCase);
        private readonly ConcurrentDictionary<string, List<ThreatIntelHit>> _byHash   = new(StringComparer.OrdinalIgnoreCase);
        private CancellationTokenSource? _cts;

        public DateTime LastRefresh { get; private set; }
        public int TotalIndicators => _byIp.Count + _byDomain.Count + _byHash.Count;
        public bool Enabled { get; set; } = true;

        private ThreatIntelService()
        {
            Directory.CreateDirectory(_cacheDir);
        }

        public void StartBackgroundRefresh()
        {
            _cts = new CancellationTokenSource();
            _ = Task.Run(async () =>
            {
                while (!_cts.IsCancellationRequested)
                {
                    if (Enabled)
                    {
                        try { await RefreshAllAsync(_cts.Token).ConfigureAwait(false); }
                        catch (Exception ex) { AppLogger.Log.Warning(ex, "[TI] refresh failed"); }
                    }
                    try { await Task.Delay(TimeSpan.FromHours(6), _cts.Token).ConfigureAwait(false); }
                    catch (OperationCanceledException) { }
                }
            });
        }

        public async Task RefreshAllAsync(CancellationToken ct = default)
        {
            AppLogger.Log.Information("[TI] starting refresh");
            await Task.WhenAll(
                RefreshFeodoAsync(ct),
                RefreshUrlhausAsync(ct),
                RefreshThreatfoxAsync(ct)
            ).ConfigureAwait(false);
            LastRefresh = DateTime.UtcNow;
            AppLogger.Log.Information("[TI] refresh complete: {N} indicators", TotalIndicators);
        }

        public string? Lookup(string indicator, string kind)
        {
            if (!Enabled || string.IsNullOrEmpty(indicator)) return null;
            ConcurrentDictionary<string, List<ThreatIntelHit>> map = kind switch
            {
                "ip"     => _byIp,
                "domain" => _byDomain,
                "hash"   => _byHash,
                _        => _byIp,
            };
            if (!map.TryGetValue(indicator, out var hits) || hits.Count == 0) return null;
            return string.Join("; ", hits.Select(h => $"{h.Source}:{h.Tag ?? h.Description ?? "?"}").Distinct());
        }

        // ── Feodo Tracker (botnet C2 IPs) ───────────────────────────────────
        private async Task RefreshFeodoAsync(CancellationToken ct)
        {
            const string url = "https://feodotracker.abuse.ch/downloads/ipblocklist.json";
            try
            {
                var json = await GetWithCacheAsync(url, "feodo.json", ct).ConfigureAwait(false);
                if (string.IsNullOrEmpty(json)) return;
                using var doc = JsonDocument.Parse(json);
                foreach (var item in doc.RootElement.EnumerateArray())
                {
                    if (!item.TryGetProperty("ip_address", out var ipEl)) continue;
                    var ip = ipEl.GetString();
                    if (string.IsNullOrEmpty(ip)) continue;
                    var malware = item.TryGetProperty("malware", out var m) ? m.GetString() : null;
                    var port    = item.TryGetProperty("port",     out var p) ? p.GetRawText() : null;
                    var hit = new ThreatIntelHit("feodo", ip!, "ip",
                        $"c2-{malware?.ToLower() ?? "unknown"}",
                        $"C2 {malware} :{port}");
                    _byIp.AddOrUpdate(ip!, _ => new List<ThreatIntelHit> { hit }, (_, l) => { l.Add(hit); return l; });
                }
            }
            catch (Exception ex) { AppLogger.Log.Warning(ex, "[TI/Feodo]"); }
        }

        // ── URLhaus (malware delivery hosts) ────────────────────────────────
        private async Task RefreshUrlhausAsync(CancellationToken ct)
        {
            const string url = "https://urlhaus.abuse.ch/downloads/text/";
            try
            {
                var text = await GetWithCacheAsync(url, "urlhaus.txt", ct).ConfigureAwait(false);
                if (string.IsNullOrEmpty(text)) return;
                foreach (var line in text.Split('\n'))
                {
                    var t = line.Trim();
                    if (t.Length == 0 || t.StartsWith("#")) continue;
                    if (!Uri.TryCreate(t, UriKind.Absolute, out var uri)) continue;
                    var host = uri.Host;
                    if (string.IsNullOrEmpty(host)) continue;
                    var hit = new ThreatIntelHit("urlhaus", host, "domain", "urlhaus-malware",
                        $"URLhaus delivery host {host}");
                    if (System.Net.IPAddress.TryParse(host, out _))
                        _byIp.AddOrUpdate(host, _ => new List<ThreatIntelHit> { hit }, (_, l) => { l.Add(hit); return l; });
                    else
                        _byDomain.AddOrUpdate(host, _ => new List<ThreatIntelHit> { hit }, (_, l) => { l.Add(hit); return l; });
                }
            }
            catch (Exception ex) { AppLogger.Log.Warning(ex, "[TI/URLhaus]"); }
        }

        // ── ThreatFox (multi-IoC) ───────────────────────────────────────────
        private async Task RefreshThreatfoxAsync(CancellationToken ct)
        {
            const string url = "https://threatfox.abuse.ch/export/json/recent/";
            try
            {
                var json = await GetWithCacheAsync(url, "threatfox.json", ct).ConfigureAwait(false);
                if (string.IsNullOrEmpty(json)) return;
                using var doc = JsonDocument.Parse(json);
                foreach (var dayProp in doc.RootElement.EnumerateObject())
                {
                    if (dayProp.Value.ValueKind != JsonValueKind.Array) continue;
                    foreach (var item in dayProp.Value.EnumerateArray())
                    {
                        if (!item.TryGetProperty("ioc_value", out var iocEl)) continue;
                        var ioc = iocEl.GetString();
                        if (string.IsNullOrEmpty(ioc)) continue;
                        var iocType = item.TryGetProperty("ioc_type",    out var tEl) ? tEl.GetString() : "";
                        var malware = item.TryGetProperty("malware",     out var mEl) ? mEl.GetString() : null;
                        var tag     = $"threatfox-{(malware ?? "unknown").ToLower()}";
                        var hit     = new ThreatIntelHit("threatfox", ioc!, iocType ?? "ip", tag,
                            $"{malware} ({iocType})");

                        if (iocType?.Contains("ip", StringComparison.OrdinalIgnoreCase) == true)
                        {
                            var host = ioc!.Split(':')[0];
                            _byIp.AddOrUpdate(host, _ => new List<ThreatIntelHit> { hit }, (_, l) => { l.Add(hit); return l; });
                        }
                        else if (iocType?.Contains("domain", StringComparison.OrdinalIgnoreCase) == true)
                        {
                            _byDomain.AddOrUpdate(ioc!, _ => new List<ThreatIntelHit> { hit }, (_, l) => { l.Add(hit); return l; });
                        }
                        else if (iocType?.Contains("sha256", StringComparison.OrdinalIgnoreCase) == true
                              || iocType?.Contains("md5",    StringComparison.OrdinalIgnoreCase) == true)
                        {
                            _byHash.AddOrUpdate(ioc!, _ => new List<ThreatIntelHit> { hit }, (_, l) => { l.Add(hit); return l; });
                        }
                    }
                }
            }
            catch (Exception ex) { AppLogger.Log.Warning(ex, "[TI/ThreatFox]"); }
        }

        // ── Cached HTTP fetch ───────────────────────────────────────────────
        private async Task<string> GetWithCacheAsync(string url, string cacheFile, CancellationToken ct)
        {
            var path = Path.Combine(_cacheDir, cacheFile);
            bool isFresh = File.Exists(path) &&
                (DateTime.UtcNow - File.GetLastWriteTimeUtc(path)).TotalHours < 6;

            if (!isFresh)
            {
                try
                {
                    using var resp = await _http.GetAsync(url, ct).ConfigureAwait(false);
                    if (resp.IsSuccessStatusCode)
                    {
                        var body = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
                        await File.WriteAllTextAsync(path, body, ct).ConfigureAwait(false);
                    }
                }
                catch (Exception ex)
                {
                    AppLogger.Log.Warning(ex, "[TI] fetch failed for {Url}", url);
                }
            }

            return File.Exists(path) ? await File.ReadAllTextAsync(path, ct).ConfigureAwait(false) : string.Empty;
        }

        public void Dispose()
        {
            _cts?.Cancel();
            _http.Dispose();
        }
    }
}
