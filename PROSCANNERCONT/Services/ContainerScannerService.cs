using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;

namespace PROSCANNERCONT.Services
{
    public sealed class ContainerVuln
    {
        public string Pkg { get; set; } = "";
        public string InstalledVersion { get; set; } = "";
        public string FixedVersion { get; set; } = "";
        public string Severity { get; set; } = "";
        public string CveId { get; set; } = "";
        public string Title { get; set; } = "";
    }

    public sealed class ContainerScanResult
    {
        public string Image { get; set; } = "";
        public string ScannerVersion { get; set; } = "";
        public List<ContainerVuln> Vulns { get; } = new();
        public List<string> Misconfigs { get; } = new();
        public bool TrivyAvailable { get; set; }
        public string? ErrorMessage { get; set; }
    }

    /// <summary>
    /// Wraps the trivy CLI (https://github.com/aquasecurity/trivy) — the
    /// standard tool for container image scanning. We don't reinvent it; we
    /// shell out, parse the JSON, and present results in the UI. Trivy is
    /// detected on PATH; if missing the result clearly says so.
    /// </summary>
    public sealed class ContainerScannerService
    {
        public async Task<ContainerScanResult> ScanImageAsync(string image)
        {
            var r = new ContainerScanResult { Image = image };
            var trivy = WhereTrivy();
            if (trivy == null)
            {
                r.TrivyAvailable = false;
                r.ErrorMessage = "trivy CLI not found on PATH. Install from https://aquasecurity.github.io/trivy/";
                return r;
            }
            r.TrivyAvailable = true;

            try
            {
                r.ScannerVersion = (await RunAsync(trivy, "--version")).Split('\n').FirstOrDefault() ?? "";
                var json = await RunAsync(trivy, $"image --quiet --format json --severity CRITICAL,HIGH,MEDIUM \"{image}\"");
                if (string.IsNullOrWhiteSpace(json))
                {
                    r.ErrorMessage = "trivy returned no output (image may not exist locally — try 'docker pull' first).";
                    return r;
                }

                using var doc = JsonDocument.Parse(json);
                if (doc.RootElement.TryGetProperty("Results", out var results))
                {
                    foreach (var target in results.EnumerateArray())
                    {
                        if (target.TryGetProperty("Vulnerabilities", out var vulns))
                        {
                            foreach (var v in vulns.EnumerateArray())
                            {
                                r.Vulns.Add(new ContainerVuln
                                {
                                    Pkg              = v.TryGetProperty("PkgName",          out var p) ? p.GetString() ?? "" : "",
                                    InstalledVersion = v.TryGetProperty("InstalledVersion", out var iv) ? iv.GetString() ?? "" : "",
                                    FixedVersion     = v.TryGetProperty("FixedVersion",     out var fv) ? fv.GetString() ?? "" : "",
                                    Severity         = v.TryGetProperty("Severity",         out var sv) ? sv.GetString() ?? "" : "",
                                    CveId            = v.TryGetProperty("VulnerabilityID",  out var vi) ? vi.GetString() ?? "" : "",
                                    Title            = v.TryGetProperty("Title",            out var ti) ? ti.GetString() ?? "" : "",
                                });
                            }
                        }
                        if (target.TryGetProperty("Misconfigurations", out var mis))
                        {
                            foreach (var m in mis.EnumerateArray())
                            {
                                var id    = m.TryGetProperty("ID",    out var i) ? i.GetString() : "";
                                var title = m.TryGetProperty("Title", out var t) ? t.GetString() : "";
                                r.Misconfigs.Add($"{id}: {title}");
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                AppLogger.Log.Warning(ex, "[Trivy] scan failed");
                r.ErrorMessage = ex.Message;
            }
            return r;
        }

        private static string? WhereTrivy()
        {
            var pathDirs = (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator);
            foreach (var d in pathDirs)
            {
                try
                {
                    foreach (var exe in new[] { "trivy.exe", "trivy" })
                    {
                        var full = Path.Combine(d, exe);
                        if (File.Exists(full)) return full;
                    }
                }
                catch { }
            }
            return null;
        }

        private static async Task<string> RunAsync(string exe, string args)
        {
            var psi = new ProcessStartInfo(exe, args)
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            using var proc = Process.Start(psi)!;
            var stdout = await proc.StandardOutput.ReadToEndAsync();
            await proc.WaitForExitAsync();
            return stdout;
        }
    }
}
