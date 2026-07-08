using System;
using System.Collections.Concurrent;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;

namespace PROSCANNERCONT.Services
{
    public class GeoIpResult
    {
        public bool Success { get; set; }
        public string Country { get; set; } = "";
        public string CountryCode { get; set; } = "";
        public string ISP { get; set; } = "";
        public string ASN { get; set; } = "";
        public string Query { get; set; } = "";
    }

    public static class GeoIpService
    {
        private static readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(5) };
        private static readonly ConcurrentDictionary<string, GeoIpResult> _cache = new();
        private static readonly ConcurrentDictionary<string, byte> _inflight = new();
        private static DateTime _lastRequest = DateTime.MinValue;
        private static readonly object _rateLock = new();

        /// <summary>Non-blocking cache read — for synchronous enrichment on the ingest path.</summary>
        public static bool TryGetCached(string ip, out GeoIpResult? result) => _cache.TryGetValue(ip, out result);

        /// <summary>Warm the cache for an IP without blocking (deduped + rate-limited inside LookupAsync).</summary>
        public static void Prefetch(string ip)
        {
            if (string.IsNullOrWhiteSpace(ip) || _cache.ContainsKey(ip)) return;
            if (!_inflight.TryAdd(ip, 0)) return;
            _ = LookupAsync(ip).ContinueWith(t => _inflight.TryRemove(ip, out _));
        }

        /// <summary>For tests: inject a known result into the cache.</summary>
        public static void SeedCacheForTests(string ip, GeoIpResult r) => _cache[ip] = r;

        // ip-api.com free tier: 45 requests/minute, no API key needed.
        // Returns cached result instantly; on miss, fetches from api and caches.
        public static async Task<GeoIpResult> LookupAsync(string ip)
        {
            if (string.IsNullOrWhiteSpace(ip) || ip == "?" || IsPrivate(ip))
                return new GeoIpResult { Success = false, Query = ip, Country = "Private/Local" };

            if (_cache.TryGetValue(ip, out var cached))
                return cached;

            // Respect rate limit: no faster than 1 request per 1.4 seconds (~43/min)
            lock (_rateLock)
            {
                var gap = (DateTime.UtcNow - _lastRequest).TotalMilliseconds;
                if (gap < 1400)
                    System.Threading.Thread.Sleep((int)(1400 - gap));
                _lastRequest = DateTime.UtcNow;
            }

            try
            {
                string url = $"http://ip-api.com/json/{ip}?fields=status,country,countryCode,isp,org,as,query";
                string json = await _http.GetStringAsync(url);
                using var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;

                var result = new GeoIpResult
                {
                    Success      = root.TryGetProperty("status", out var s) && s.GetString() == "success",
                    Country      = root.TryGetProperty("country",     out var c)  ? c.GetString()  ?? "" : "",
                    CountryCode  = root.TryGetProperty("countryCode", out var cc) ? cc.GetString() ?? "" : "",
                    ISP          = root.TryGetProperty("isp",         out var i)  ? i.GetString()  ?? "" : "",
                    ASN          = root.TryGetProperty("as",          out var a)  ? a.GetString()  ?? "" : "",
                    Query        = ip
                };

                _cache[ip] = result;
                return result;
            }
            catch
            {
                var fail = new GeoIpResult { Success = false, Query = ip };
                _cache[ip] = fail;
                return fail;
            }
        }

        private static bool IsPrivate(string ip)
        {
            if (!System.Net.IPAddress.TryParse(ip, out var addr)) return false;
            var b = addr.GetAddressBytes();
            if (b.Length != 4) return false; // IPv6 — not private for our purposes
            return (b[0] == 10) ||
                   (b[0] == 172 && b[1] >= 16 && b[1] <= 31) ||
                   (b[0] == 192 && b[1] == 168) ||
                   (b[0] == 127) ||
                   (b[0] == 169 && b[1] == 254);
        }
    }
}
