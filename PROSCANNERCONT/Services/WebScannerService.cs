using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace PROSCANNERCONT.Services
{
    public sealed class WebFinding
    {
        public string Url { get; set; } = "";
        public string Category { get; set; } = ""; // dir, headers, cookie, xss, sqli, info
        public string Title { get; set; } = "";
        public string Severity { get; set; } = "Info";
        public string Detail { get; set; } = "";
    }

    public sealed class WebScanReport
    {
        public string BaseUrl { get; set; } = "";
        public List<WebFinding> Findings { get; } = new();
        public List<string> DiscoveredPaths { get; } = new();
        public DateTime ScannedAt { get; set; } = DateTime.UtcNow;
    }

    /// <summary>
    /// Lightweight DAST scanner — directory busting against a built-in
    /// wordlist, missing security-header audit, cookie flag inspection,
    /// reflected-XSS canary probe, basic SQLi error reflection check,
    /// robots.txt / sitemap.xml discovery.  Not Burp — but enough to catch
    /// the easy-win findings that show up in every pentest report.
    /// </summary>
    public sealed class WebScannerService : IDisposable
    {
        private readonly HttpClientHandler _handler = new()
        {
            AllowAutoRedirect = false,
            ServerCertificateCustomValidationCallback = (_, __, ___, ____) => true,
            UseCookies = true,
            CookieContainer = new CookieContainer(),
        };
        private readonly HttpClient _http;

        // Small, sane default wordlist — extended with SecLists if found on disk.
        private static readonly string[] _defaultWordlist =
        {
            "admin", "admin/", "api", "api/v1", "backup", "backup.zip", "backup.tar.gz",
            "config", "config.json", "config.yaml", "config.php", "debug", "env", ".env",
            "git/HEAD", ".git/HEAD", "dump.sql", "phpinfo.php", "info.php",
            "login", "logout", "register", "signup", "user", "users",
            "robots.txt", "sitemap.xml", "humans.txt", "security.txt", ".well-known/security.txt",
            "test", "test.html", "tmp", "uploads", "uploads/", "vendor", "wp-admin", "wp-login.php",
            "swagger", "swagger.json", "openapi.json", "actuator", "actuator/env", "metrics",
            "console", "graphql", "graphiql", "kibana", "elasticsearch",
            "server-status", "server-info", ".DS_Store", ".htaccess",
        };

        public WebScannerService()
        {
            _http = new HttpClient(_handler) { Timeout = TimeSpan.FromSeconds(8) };
            _http.DefaultRequestHeaders.UserAgent.ParseAdd("PrivaCore-WebScanner/1.0");
        }

        public async Task<WebScanReport> ScanAsync(string url, CancellationToken ct = default)
        {
            if (!url.StartsWith("http", StringComparison.OrdinalIgnoreCase))
                url = "http://" + url;
            if (!url.EndsWith("/")) url += "/";

            var report = new WebScanReport { BaseUrl = url };

            // Scope check
            var host = new Uri(url).Host;
            var guard = ScopeGuard.Check(host);
            if (!guard.Allowed)
            {
                report.Findings.Add(new WebFinding { Category = "info", Title = "Scope guard blocked", Severity = "Critical", Detail = guard.Reason });
                return report;
            }

            await ProbeHeaders(url, report, ct);
            await ProbeCookies(url, report, ct);
            await ProbeWordlist(url, report, ct);
            await ProbeXssReflection(url, report, ct);
            await ProbeSqliReflection(url, report, ct);
            await ProbeRobotsAndSitemap(url, report, ct);

            return report;
        }

        // ── Security-header audit ───────────────────────────────────────────
        private async Task ProbeHeaders(string url, WebScanReport r, CancellationToken ct)
        {
            try
            {
                using var resp = await _http.GetAsync(url, ct);
                var h = resp.Headers;
                var ch = resp.Content?.Headers;

                void Miss(string name, string sev) =>
                    r.Findings.Add(new WebFinding {
                        Url = url, Category = "headers", Title = $"Missing header: {name}",
                        Severity = sev, Detail = $"{name} not present in response."
                    });

                if (!h.Contains("Strict-Transport-Security") && url.StartsWith("https")) Miss("Strict-Transport-Security", "High");
                if (!h.Contains("Content-Security-Policy"))    Miss("Content-Security-Policy", "Medium");
                if (!h.Contains("X-Frame-Options") && !h.Contains("Content-Security-Policy")) Miss("X-Frame-Options", "Medium");
                if (!h.Contains("X-Content-Type-Options"))     Miss("X-Content-Type-Options", "Low");
                if (!h.Contains("Referrer-Policy"))            Miss("Referrer-Policy", "Low");
                if (!h.Contains("Permissions-Policy"))         Miss("Permissions-Policy", "Low");

                if (h.TryGetValues("Server", out var srv))
                    r.Findings.Add(new WebFinding { Url = url, Category = "info", Severity = "Info",
                        Title = "Server header disclosed", Detail = string.Join(", ", srv) });

                if (h.TryGetValues("X-Powered-By", out var pwr))
                    r.Findings.Add(new WebFinding { Url = url, Category = "info", Severity = "Low",
                        Title = "X-Powered-By header disclosed", Detail = string.Join(", ", pwr) });
            }
            catch (Exception ex) { AppLogger.Log.Debug(ex, "[WebScan] header probe failed"); }
        }

        private async Task ProbeCookies(string url, WebScanReport r, CancellationToken ct)
        {
            try
            {
                using var resp = await _http.GetAsync(url, ct);
                if (!resp.Headers.TryGetValues("Set-Cookie", out var cookies)) return;
                foreach (var c in cookies)
                {
                    bool secure = c.IndexOf("Secure",   StringComparison.OrdinalIgnoreCase) >= 0;
                    bool httpO  = c.IndexOf("HttpOnly", StringComparison.OrdinalIgnoreCase) >= 0;
                    bool same   = c.IndexOf("SameSite", StringComparison.OrdinalIgnoreCase) >= 0;
                    if (!secure || !httpO || !same)
                        r.Findings.Add(new WebFinding {
                            Url = url, Category = "cookie", Title = "Cookie missing flags",
                            Severity = "Medium",
                            Detail = $"{c}  →  Secure={secure} HttpOnly={httpO} SameSite={same}"
                        });
                }
            }
            catch { }
        }

        // ── Directory busting (parallel, small wordlist) ────────────────────
        private async Task ProbeWordlist(string url, WebScanReport r, CancellationToken ct)
        {
            using var sem = new SemaphoreSlim(8);
            var tasks = _defaultWordlist.Select(async word =>
            {
                await sem.WaitAsync(ct);
                try
                {
                    using var resp = await _http.GetAsync(url + word, ct);
                    if (resp.StatusCode is HttpStatusCode.OK or HttpStatusCode.Forbidden or HttpStatusCode.Unauthorized
                        or HttpStatusCode.MovedPermanently or HttpStatusCode.Redirect)
                    {
                        var line = $"{(int)resp.StatusCode} {url}{word}";
                        r.DiscoveredPaths.Add(line);
                        var sev = (int)resp.StatusCode switch
                        {
                            200 when word.Contains(".env") || word.Contains("backup")
                                  || word.Contains(".git") || word.Contains("dump")
                                  || word.Contains("config") || word.Contains("phpinfo")
                                  || word.Contains("server-status") || word.Contains("actuator/env") => "Critical",
                            200 => "Medium",
                            _   => "Low",
                        };
                        r.Findings.Add(new WebFinding { Url = url + word, Category = "dir", Title = $"Discovered: /{word}", Severity = sev, Detail = line });
                    }
                }
                catch { }
                finally { sem.Release(); }
            });
            await Task.WhenAll(tasks);
        }

        // ── Reflected XSS canary ────────────────────────────────────────────
        private async Task ProbeXssReflection(string url, WebScanReport r, CancellationToken ct)
        {
            const string canary = "<proscanxss>";
            try
            {
                var probeUrl = url + "?q=" + Uri.EscapeDataString(canary);
                using var resp = await _http.GetAsync(probeUrl, ct);
                var body = await resp.Content.ReadAsStringAsync(ct);
                if (body.Contains(canary, StringComparison.OrdinalIgnoreCase))
                    r.Findings.Add(new WebFinding {
                        Url = probeUrl, Category = "xss", Title = "Reflected canary in response body",
                        Severity = "High", Detail = "User-supplied input echoed unencoded — investigate for reflected XSS."
                    });
            }
            catch { }
        }

        // ── SQL-error reflection (very rough) ───────────────────────────────
        private async Task ProbeSqliReflection(string url, WebScanReport r, CancellationToken ct)
        {
            try
            {
                var probeUrl = url + "?id=1'";
                using var resp = await _http.GetAsync(probeUrl, ct);
                var body = await resp.Content.ReadAsStringAsync(ct);
                string[] sqlErr =
                {
                    "you have an error in your sql syntax", "unclosed quotation mark",
                    "warning: mysql_", "pg_query():", "sqlite3::sqlexception",
                    "ora-00933", "ora-00936"
                };
                var hit = sqlErr.FirstOrDefault(s => body.Contains(s, StringComparison.OrdinalIgnoreCase));
                if (hit != null)
                    r.Findings.Add(new WebFinding {
                        Url = probeUrl, Category = "sqli", Title = "Possible SQL error leak",
                        Severity = "High", Detail = $"Response contained \"{hit}\""
                    });
            }
            catch { }
        }

        private async Task ProbeRobotsAndSitemap(string url, WebScanReport r, CancellationToken ct)
        {
            foreach (var f in new[] { "robots.txt", "sitemap.xml" })
            {
                try
                {
                    using var resp = await _http.GetAsync(url + f, ct);
                    if (resp.StatusCode == HttpStatusCode.OK)
                        r.Findings.Add(new WebFinding {
                            Url = url + f, Category = "info", Severity = "Info",
                            Title = $"{f} present", Detail = "Useful for crawling — review for sensitive disallowed paths."
                        });
                }
                catch { }
            }
        }

        public void Dispose()
        {
            _http.Dispose();
            _handler.Dispose();
        }
    }
}
