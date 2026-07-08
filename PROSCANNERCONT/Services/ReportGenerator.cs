using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using PROSCANNERCONT.Models;
using PROSCANNERCONT.Services;

namespace PROSCANNERCONT.Services
{
    /// <summary>
    /// Generates professional HTML security reports from scan data.
    /// Reports open in any browser with no external dependencies — all CSS is inline.
    /// </summary>
    public static class ReportGenerator
    {
        // ── Port Scan Report ────────────────────────────────────────────────────
        public static string GeneratePortScanReport(
            string target, int startPort, int endPort, string scanType,
            List<PortScanResult> results)
        {
            var open       = results.Where(r => r.IsOpen || r.Status == "Open").ToList();
            bool cveChecked = open.Any(r => r.CveChecked);
            int totalCves  = open.Sum(r => r.VulnCount);
            int critical   = open.Count(r => r.RiskLevel == "Critical");
            int high       = open.Count(r => r.RiskLevel == "High");
            int medium     = open.Count(r => r.RiskLevel == "Medium");
            int low        = open.Count(r => r.RiskLevel == "Low");

            string overallRisk = critical > 0 ? "Critical"
                               : high     > 0 ? "High"
                               : medium   > 0 ? "Medium"
                               : totalCves > 0 ? "Low" : "Clean";

            var sb = new StringBuilder();
            sb.Append(HtmlHead($"Port Scan Report — {target}", overallRisk));

            // ── Header ──────────────────────────────────────────────────────────
            sb.Append($@"
<div class='report-header'>
  <div class='logo'>🛡 PrivaCore</div>
  <h1>Port Scan Security Report</h1>
  <div class='meta'>
    <span>Target: <strong>{Esc(target)}</strong></span>
    <span>Port range: <strong>{startPort}–{endPort}</strong></span>
    <span>Scan type: <strong>{Esc(scanType)}</strong></span>
    <span>Generated: <strong>{DateTime.Now:yyyy-MM-dd HH:mm:ss}</strong></span>
  </div>
</div>");

            // ── Executive Summary ───────────────────────────────────────────────
            int criticalCves = open.Sum(r => r.CveFindings?.Count(c => c.Severity == "Critical") ?? 0);
            int highCves     = open.Sum(r => r.CveFindings?.Count(c => c.Severity == "High")     ?? 0);
            sb.Append(ExecutiveSummary(target, open.Count, criticalCves, highCves, totalCves, overallRisk));

            // ── Summary cards ───────────────────────────────────────────────────
            sb.Append("<div class='cards'>");
            sb.Append(Card("Open Ports",  open.Count.ToString(), "#58A6FF", "total open ports found"));
            sb.Append(Card("Services",    open.Count(r => !string.IsNullOrEmpty(r.Service)).ToString(), "#56D364", "services identified"));
            sb.Append(Card("CVEs Found",  cveChecked ? totalCves.ToString() : "—", cveChecked ? "#E3B341" : "#555", cveChecked ? "known vulnerabilities" : "CVE check pending"));
            sb.Append(Card("Risk Level",  cveChecked ? overallRisk : "—", cveChecked ? RiskColor(overallRisk) : "#555", cveChecked ? "overall assessment" : "CVE check pending"));
            sb.Append("</div>");

            // ── Risk distribution bar ───────────────────────────────────────────
            if (cveChecked && (critical + high + medium + low) > 0)
            {
                sb.Append("<div class='section'><h2>Risk Distribution</h2><div class='risk-bar'>");
                foreach (var (label, count, color) in new[] {
                    ("Critical", critical, "#F85149"),
                    ("High",     high,     "#E3B341"),
                    ("Medium",   medium,   "#58A6FF"),
                    ("Low",      low,      "#56D364") })
                {
                    if (count > 0)
                        sb.Append($"<div class='risk-segment' style='background:{color};flex:{count}' title='{label}: {count}'><span>{label} ({count})</span></div>");
                }
                sb.Append("</div></div>");
            }

            // ── Open ports — expandable rows ────────────────────────────────────
            sb.Append("<div class='section'>");
            sb.Append("<div class='section-head'><h2>Open Ports</h2>");
            if (open.Any())
                sb.Append("<div class='expand-controls'><button onclick='expandAll()'>Expand All</button><button onclick='collapseAll()'>Collapse All</button></div>");
            sb.Append("</div>");

            if (!open.Any())
            {
                sb.Append("<p class='empty'>No open ports found in the specified range.</p>");
            }
            else
            {
                sb.Append("<table class='ports-table'><thead><tr>");
                sb.Append("<th style='width:28px'></th>");
                sb.Append("<th>Port</th><th>Protocol</th><th>Service</th><th>Version</th>");
                if (cveChecked) sb.Append("<th>Risk</th><th>CVEs</th>");
                sb.Append("</tr></thead><tbody>");

                int idx = 0;
                foreach (var r in open.OrderBy(p => p.Port))
                {
                    bool hasCves = r.CveFindings?.Any() == true;
                    string rowId = $"detail-{idx}";

                    // Summary row — clickable when CVE data exists
                    string clickAttr = (cveChecked) ? $"onclick=\"toggle('{rowId}')\" style='cursor:pointer'" : "";
                    sb.Append($"<tr class='port-row' {clickAttr}>");
                    sb.Append($"<td class='expand-toggle' id='arrow-{rowId}'>{(cveChecked ? "▶" : "")}</td>");
                    sb.Append($"<td><code>{r.Port}</code></td>");
                    sb.Append($"<td>{Esc(r.Protocol)}</td>");
                    sb.Append($"<td><strong>{Esc(r.Service ?? "—")}</strong></td>");
                    sb.Append($"<td><code>{Esc(r.Version ?? "—")}</code></td>");
                    if (cveChecked)
                    {
                        sb.Append($"<td>{Badge(r.RiskLevel ?? "Clean")}</td>");
                        sb.Append($"<td>{(r.VulnCount > 0 ? $"<strong style='color:#E3B341'>{r.VulnCount}</strong>" : "<span style='color:#56D364'>Clean</span>")}</td>");
                    }
                    sb.Append("</tr>");

                    // Detail row — hidden until toggled
                    int colspan = cveChecked ? 7 : 5;
                    sb.Append($"<tr id='{rowId}' class='detail-row' style='display:none'>");
                    sb.Append($"<td colspan='{colspan}' class='detail-cell'>");
                    sb.Append(BuildPortDetailPanel(r, hasCves));
                    sb.Append("</td></tr>");

                    idx++;
                }

                sb.Append("</tbody></table>");
            }
            sb.Append("</div>");

            // ── Recommendations ─────────────────────────────────────────────────
            sb.Append("<div class='section'><h2>Recommendations</h2><ul class='recs'>");
            foreach (var rec in BuildPortScanRecs(open, cveChecked, totalCves))
                sb.Append($"<li>{rec}</li>");
            sb.Append("</ul></div>");

            // ── Remediation Recommendations ─────────────────────────────────────
            sb.Append(RemediationSection(open));

            sb.Append(HtmlFoot());
            return sb.ToString();
        }

        private static string BuildPortDetailPanel(PortScanResult r, bool hasCves)
        {
            var sb = new StringBuilder();
            sb.Append("<div class='detail-panel'>");

            // Service info
            sb.Append("<div class='detail-info'>");
            sb.Append($"<span><strong>Port:</strong> {r.Port}/{Esc(r.Protocol)}</span>");
            sb.Append($"<span><strong>Service:</strong> {Esc(r.Service ?? "Unknown")}</span>");
            if (!string.IsNullOrWhiteSpace(r.Version))
                sb.Append($"<span><strong>Version:</strong> <code>{Esc(r.Version)}</code></span>");
            sb.Append($"<span><strong>Risk:</strong> {Badge(r.RiskLevel ?? (r.CveChecked ? "Clean" : "Not checked"))}</span>");
            sb.Append($"<span><strong>CVEs:</strong> {r.VulnCount}</span>");
            sb.Append("</div>");

            // CVE table
            if (hasCves)
            {
                sb.Append("<table class='cve-table'><thead><tr>");
                sb.Append("<th>CVE ID</th><th>Severity</th><th>CVSS</th><th>Description</th><th>Reference</th>");
                sb.Append("</tr></thead><tbody>");

                foreach (var cve in r.CveFindings.OrderByDescending(c => c.Cvss))
                {
                    string nvdUrl  = $"https://nvd.nist.gov/vuln/detail/{Esc(cve.CveId)}";
                    string refUrl  = cve.Reference?.StartsWith("http") == true ? cve.Reference : nvdUrl;
                    string refHost = Uri.TryCreate(refUrl, UriKind.Absolute, out var uri) ? uri.Host : "reference";

                    sb.Append("<tr>");
                    sb.Append($"<td><a href='{nvdUrl}' target='_blank'><code>{Esc(cve.CveId)}</code></a></td>");
                    sb.Append($"<td>{Badge(cve.Severity)}</td>");
                    sb.Append($"<td><strong style='color:{CvssColor(cve.Cvss)}'>{(cve.Cvss > 0 ? cve.Cvss.ToString("F1") : "—")}</strong></td>");
                    sb.Append($"<td class='cve-desc'>{Esc(cve.Summary)}</td>");
                    sb.Append($"<td><a href='{Esc(refUrl)}' target='_blank'>{Esc(refHost)}</a></td>");
                    sb.Append("</tr>");
                }

                sb.Append("</tbody></table>");
            }
            else if (r.CveChecked)
            {
                sb.Append("<p class='cve-clean'>✓ No known CVEs found for this service/version.</p>");
            }
            else
            {
                sb.Append("<p class='empty'>CVE check was not run for this port.</p>");
            }

            sb.Append("</div>");
            return sb.ToString();
        }

        private static string ExecutiveSummary(string target, int openPorts, int criticalCves, int highCves, int totalCves, string overallRisk)
        {
            var recommendation = overallRisk switch
            {
                "Critical" => "Immediate remediation required. Critical vulnerabilities present significant risk of exploitation.",
                "High"     => "Urgent attention recommended. High-severity vulnerabilities should be patched within 7 days.",
                "Medium"   => "Scheduled remediation advised. Medium-severity findings should be addressed in the next maintenance window.",
                "Low"      => "Low risk identified. Address findings during routine maintenance.",
                _          => "No significant vulnerabilities detected. Maintain regular scanning schedule."
            };

            var color = overallRisk switch
            {
                "Critical" => "#F44747", "High" => "#FF8C00",
                "Medium"   => "#FFA500", "Low"  => "#4EC9B0",
                _          => "#56D364"
            };

            return $@"
<div class='exec-summary' style='border-left:4px solid {color};padding:16px 20px;margin:20px 0;background:#161b22;border-radius:0 8px 8px 0'>
  <h2 style='margin:0 0 8px;color:{color}'>Executive Summary</h2>
  <p style='margin:0 0 12px;color:#c9d1d9'>
    Scan of <strong>{Esc(target)}</strong> completed on {DateTime.Now:MMMM dd, yyyy} at {DateTime.Now:HH:mm}.
    {openPorts} open port(s) were identified.
    {(totalCves > 0 ? $"{totalCves} CVE(s) found including {criticalCves} Critical and {highCves} High severity." : "No CVEs detected.")}
  </p>
  <p style='margin:0;color:#e6edf3'><strong>Recommendation:</strong> {recommendation}</p>
</div>";
        }

        private static string RemediationSection(List<PortScanResult> openPorts)
        {
            var allCves = openPorts
                .Where(p => p.CveFindings?.Count > 0)
                .SelectMany(p => p.CveFindings.Select(c => (Port: p, Cve: c)))
                .OrderByDescending(x => x.Cve.Cvss)
                .ToList();

            if (!allCves.Any()) return string.Empty;

            var sb = new StringBuilder();
            sb.Append("<div class='section'><h2>Remediation Recommendations</h2><table>");
            sb.Append("<thead><tr><th>CVE</th><th>CVSS</th><th>Severity</th><th>Port/Service</th><th>Recommendation</th></tr></thead><tbody>");

            foreach (var (port, cve) in allCves)
            {
                var advice = cve.Severity switch
                {
                    "Critical" => "Patch immediately or disable service. Consider emergency change window.",
                    "High"     => "Patch within 7 days. Apply vendor security advisory.",
                    "Medium"   => "Patch in next maintenance window. Apply available updates.",
                    "Low"      => "Patch during routine maintenance. Monitor for exploit activity.",
                    _          => "Review vendor advisory and apply available patches."
                };
                sb.Append($@"<tr>
          <td><a href='https://nvd.nist.gov/vuln/detail/{Esc(cve.CveId)}' style='color:#58A6FF'>{Esc(cve.CveId)}</a></td>
          <td><span style='background:{cve.SeverityColor};color:#fff;padding:2px 8px;border-radius:4px'>{cve.Cvss:F1}</span></td>
          <td style='color:{cve.SeverityColor}'>{Esc(cve.Severity)}</td>
          <td>{port.Port}/{Esc(port.Service)}</td>
          <td style='color:#c9d1d9'>{advice}</td>
        </tr>");
            }
            sb.Append("</tbody></table></div>");
            return sb.ToString();
        }

        private static string CvssColor(decimal score) => score switch
        {
            >= 9.0m => "#F85149",
            >= 7.0m => "#E3B341",
            >= 4.0m => "#58A6FF",
            > 0     => "#56D364",
            _       => "#8B949E"
        };

        // ── IDS Session Report ──────────────────────────────────────────────────
        public static string GenerateIDSReport(
            IReadOnlyList<IDSAlert> alerts,
            IReadOnlyList<IDSRule>  rules,
            IDSStats stats,
            bool isNids)
        {
            string mode     = isNids ? "Network IDS (NIDS)" : "Host IDS (HIDS)";
            int critical    = alerts.Count(a => a.Severity == IDSAlertSeverity.Critical);
            int high        = alerts.Count(a => a.Severity == IDSAlertSeverity.High);
            int unacked     = alerts.Count(a => !a.IsAcknowledged);
            string overall  = critical > 0 ? "Critical" : high > 0 ? "High"
                            : alerts.Any() ? "Medium" : "Clean";

            var sb = new StringBuilder();
            sb.Append(HtmlHead($"IDS Session Report — {mode}", overall));

            sb.Append($@"
<div class='report-header'>
  <div class='logo'>🛡 PrivaCore</div>
  <h1>IDS Session Report</h1>
  <div class='meta'>
    <span>Mode: <strong>{mode}</strong></span>
    <span>Interface: <strong>{Esc(stats.ActiveInterface ?? "—")}</strong></span>
    <span>Generated: <strong>{DateTime.Now:yyyy-MM-dd HH:mm:ss}</strong></span>
  </div>
</div>");

            // Cards
            sb.Append("<div class='cards'>");
            sb.Append(Card("Packets",       stats.TotalPackets.ToString("N0"),  "#58A6FF", "captured"));
            sb.Append(Card("Alerts",        stats.TotalAlerts.ToString(),       "#E3B341", $"{unacked} unacknowledged"));
            sb.Append(Card("Critical/High", $"{critical}/{high}",               "#F85149", "require action"));
            sb.Append(Card("Sig Matches",   stats.SignatureMatches.ToString(),  "#56D364", "rule detections"));
            sb.Append("</div>");

            // Attack distribution
            if (alerts.Any())
            {
                var cats = alerts.GroupBy(a => a.AttackCategory ?? "Unknown")
                                 .OrderByDescending(g => g.Count()).ToList();
                sb.Append("<div class='section'><h2>Attack Distribution</h2><table><thead><tr><th>Category</th><th>Alerts</th><th>Critical</th><th>High</th></tr></thead><tbody>");
                foreach (var g in cats)
                {
                    sb.Append($"<tr><td><strong>{Esc(g.Key)}</strong></td><td>{g.Count()}</td>" +
                              $"<td>{g.Count(a => a.Severity == IDSAlertSeverity.Critical)}</td>" +
                              $"<td>{g.Count(a => a.Severity == IDSAlertSeverity.High)}</td></tr>");
                }
                sb.Append("</tbody></table></div>");

                // Top source IPs
                var topIps = alerts.GroupBy(a => a.SourceIP ?? "?")
                                   .OrderByDescending(g => g.Count()).Take(10).ToList();
                if (topIps.Any())
                {
                    sb.Append("<div class='section'><h2>Top Source IPs</h2><table><thead><tr><th>Source IP</th><th>Alerts</th><th>Top Alert</th></tr></thead><tbody>");
                    foreach (var g in topIps)
                    {
                        var top = g.OrderByDescending(a => (int)a.Severity).First();
                        sb.Append($"<tr><td><code>{Esc(g.Key)}</code></td><td>{g.Count()}</td><td>{Esc(top.AlertType)}</td></tr>");
                    }
                    sb.Append("</tbody></table></div>");
                }

                // Critical & High alerts in full
                var critical_high = alerts.Where(a => a.Severity >= IDSAlertSeverity.High)
                                         .OrderByDescending(a => a.Timestamp).ToList();
                if (critical_high.Any())
                {
                    sb.Append("<div class='section'><h2>Critical &amp; High Alerts</h2>");
                    sb.Append("<table><thead><tr><th>Time</th><th>Severity</th><th>Alert</th><th>Source</th><th>Destination</th><th>Category</th></tr></thead><tbody>");
                    foreach (var a in critical_high)
                    {
                        sb.Append($"<tr><td><code>{a.TimestampFormatted}</code></td><td>{Badge(a.SeverityText)}</td>" +
                                  $"<td>{Esc(a.AlertType)}</td><td><code>{Esc(a.SourceEndpoint)}</code></td>" +
                                  $"<td><code>{Esc(a.DstEndpoint)}</code></td><td>{Esc(a.AttackCategory)}</td></tr>");
                    }
                    sb.Append("</tbody></table></div>");
                }
            }

            // Active rules summary
            sb.Append($"<div class='section'><h2>Detection Rules</h2>");
            sb.Append($"<p>{stats.ActiveRules} of {stats.TotalRules} rules active. Top triggered:</p>");
            var triggered = rules.Where(r => r.TriggerCount > 0).OrderByDescending(r => r.TriggerCount).Take(10).ToList();
            if (triggered.Any())
            {
                sb.Append("<table><thead><tr><th>Rule</th><th>Category</th><th>Hits</th><th>Last Hit</th></tr></thead><tbody>");
                foreach (var r in triggered)
                    sb.Append($"<tr><td><strong>{Esc(r.Name)}</strong></td><td>{Esc(r.AttackCategory)}</td>" +
                              $"<td>{r.TriggerCount}</td><td><code>{r.LastTriggeredFormatted}</code></td></tr>");
                sb.Append("</tbody></table>");
            }
            sb.Append("</div>");

            // Recommendations
            sb.Append("<div class='section'><h2>Recommendations</h2><ul class='recs'>");
            foreach (var r in BuildIDSRecs(alerts, critical, high)) sb.Append($"<li>{r}</li>");
            sb.Append("</ul></div>");

            sb.Append(HtmlFoot());
            return sb.ToString();
        }

        // ── Network Discovery Report ────────────────────────────────────────────
        public static string GenerateNetworkDiscoveryReport(
            string subnet, List<NetworkDevice> devices)
        {
            int online   = devices.Count(d => d.IsOnline);
            int windows  = devices.Count(d => d.OS?.Contains("Windows", StringComparison.OrdinalIgnoreCase) == true);
            int linux    = devices.Count(d => d.OS?.Contains("Linux",   StringComparison.OrdinalIgnoreCase) == true);
            int routers  = devices.Count(d => d.DeviceType?.Equals("Router", StringComparison.OrdinalIgnoreCase) == true);

            var sb = new StringBuilder();
            sb.Append(HtmlHead($"Network Discovery — {subnet}", "Info"));

            sb.Append($@"
<div class='report-header'>
  <div class='logo'>🛡 PrivaCore</div>
  <h1>Network Discovery Report</h1>
  <div class='meta'>
    <span>Subnet: <strong>{Esc(subnet)}</strong></span>
    <span>Generated: <strong>{DateTime.Now:yyyy-MM-dd HH:mm:ss}</strong></span>
  </div>
</div>");

            sb.Append("<div class='cards'>");
            sb.Append(Card("Devices Found", online.ToString(),   "#58A6FF", "hosts responding"));
            sb.Append(Card("Windows",       windows.ToString(),  "#56D364", "hosts identified"));
            sb.Append(Card("Linux",         linux.ToString(),    "#E3B341", "hosts identified"));
            sb.Append(Card("Routers/APs",   routers.ToString(),  "#888",    "infrastructure"));
            sb.Append("</div>");

            sb.Append("<div class='section'><h2>Discovered Hosts</h2>");
            sb.Append("<table><thead><tr><th>IP Address</th><th>Hostname</th><th>MAC</th><th>Vendor</th><th>OS</th><th>Type</th></tr></thead><tbody>");
            foreach (var d in devices.Where(d => d.IsOnline).OrderBy(d => d.IPAddress))
            {
                sb.Append($"<tr>" +
                          $"<td><code>{Esc(d.IPAddress)}</code></td>" +
                          $"<td>{Esc(d.Hostname ?? "—")}</td>" +
                          $"<td><code>{Esc(d.MACAddress ?? "—")}</code></td>" +
                          $"<td>{Esc(d.DeviceType ?? "—")}</td>" +
                          $"<td>{Esc(d.OS ?? "—")}</td>" +
                          $"<td>{Esc(d.DeviceType ?? "—")}</td>" +
                          $"</tr>");
            }
            sb.Append("</tbody></table></div>");

            sb.Append("<div class='section'><h2>Recommendations</h2><ul class='recs'>");
            if (devices.Count == 0) sb.Append("<li>No hosts found — verify network connectivity and subnet range.</li>");
            else
            {
                sb.Append($"<li>Review all {online} discovered hosts to verify they are authorised on the network.</li>");
                if (routers > 0) sb.Append($"<li>Ensure {routers} router/AP device(s) have up-to-date firmware and strong admin credentials.</li>");
                sb.Append("<li>Run a port scan against high-value targets to enumerate open services.</li>");
            }
            sb.Append("</ul></div>");

            sb.Append(HtmlFoot());
            return sb.ToString();
        }

        // ── HTML helpers ────────────────────────────────────────────────────────
        /// <summary>
        /// Theme + branding options injected into every HTML report.
        /// Updated by Settings → Reports; static fields so existing callers
        /// keep their signatures.
        /// </summary>
        public static string ReportTheme { get; set; } = "dark"; // "dark" | "light" | "auto"
        public static string ReportLogo  { get; set; } = "🛡 PrivaCore";
        public static string? ReportCompany { get; set; } = null;
        public static string ReportAccentColor { get; set; } = "#58A6FF";

        private static string HtmlHead(string title, string risk) => HtmlHeadInternal(title, risk, ReportTheme);

        private static string HtmlHeadInternal(string title, string risk, string theme)
        {
            bool light = theme == "light";
            string bg       = light ? "#FFFFFF" : "#0D1117";
            string fg       = light ? "#24292F" : "#E6EDF3";
            string card     = light ? "#F6F8FA" : "#161B22";
            string border   = light ? "#D0D7DE" : "#30363D";
            string subtle   = light ? "#57606A" : "#8B949E";
            string accent   = ReportAccentColor;
            return $@"<!DOCTYPE html>
<html lang='en'>
<head>
<meta charset='UTF-8'>
<meta name='viewport' content='width=device-width,initial-scale=1'>
<title>{Esc(title)}</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:'-apple-system',BlinkMacSystemFont,'Segoe UI',sans-serif;background:{bg};color:{fg};line-height:1.6;font-size:14px}}
  a{{color:{accent};text-decoration:none}} a:hover{{text-decoration:underline}}
  code{{font-family:Consolas,'Courier New',monospace;font-size:13px;background:{card};padding:1px 5px;border-radius:3px}}
  .report-header{{background:{card};border-bottom:1px solid {border};padding:32px 40px}}
  .logo{{font-size:13px;font-weight:700;color:{accent};letter-spacing:2px;margin-bottom:12px;opacity:.8}}
  .report-header h1{{font-size:28px;font-weight:700;margin-bottom:14px}}
  .meta{{display:flex;flex-wrap:wrap;gap:20px;font-size:13px;color:{subtle}}}
  .meta strong{{color:{fg}}}
  .cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:1px;background:{border};border-bottom:1px solid {border}}}
  .card{{background:{card};padding:20px 24px}}
  .card-value{{font-size:32px;font-weight:700;line-height:1;margin:6px 0}}
  .card-label{{font-size:11px;font-weight:700;letter-spacing:1px;text-transform:uppercase;opacity:.6}}
  .card-sub{{font-size:11px;color:{subtle};margin-top:3px}}
  .section{{padding:28px 40px;border-bottom:1px solid {border}}}
  .section-head{{display:flex;align-items:center;justify-content:space-between;margin-bottom:16px}}
  .section-head h2{{font-size:16px;font-weight:600;color:{fg};margin:0}}
  .expand-controls{{display:flex;gap:8px}}
  .expand-controls button{{background:{card};color:{subtle};border:1px solid {border};padding:4px 12px;border-radius:4px;font-size:11px;cursor:pointer}}
  .expand-controls button:hover{{background:{border};color:{fg}}}
  table{{width:100%;border-collapse:collapse;font-size:13px}}
  th{{text-align:left;padding:8px 12px;background:{card};color:{subtle};font-size:11px;font-weight:700;letter-spacing:.5px;text-transform:uppercase;border-bottom:1px solid {border}}}
  td{{padding:10px 12px;border-bottom:1px solid {border};vertical-align:middle}}
  .port-row:hover td{{background:{card}}}
  .port-row td{{transition:background .15s}}
  .expand-toggle{{font-size:10px;color:{accent};transition:transform .2s;text-align:center;user-select:none}}
  .expand-toggle.open{{transform:rotate(90deg)}}
  .detail-row td{{padding:0;border-bottom:1px solid {border}}}
  .detail-panel{{padding:16px 20px 20px 36px;background:{bg};border-top:1px solid {border}}}
  .detail-info{{display:flex;flex-wrap:wrap;gap:16px;margin-bottom:14px;font-size:12px;color:{subtle}}}
  .detail-info strong{{color:{fg}}}
  .cve-table{{width:100%;border-collapse:collapse;font-size:12px;margin-top:4px}}
  .cve-table th{{padding:6px 10px;background:{card};color:{subtle};font-size:10px;letter-spacing:.5px;text-transform:uppercase;border-bottom:1px solid {border}}}
  .cve-table td{{padding:8px 10px;border-bottom:1px solid {border};vertical-align:top}}
  .cve-table tr:hover td{{background:{card}}}
  .cve-desc{{max-width:380px;color:{subtle};line-height:1.4}}
  .cve-clean{{color:#56D364;font-size:12px;margin-top:8px}}
  .badge{{display:inline-block;padding:2px 8px;border-radius:3px;font-size:11px;font-weight:700;color:#fff}}
  .badge-critical{{background:#F85149}} .badge-high{{background:#E3B341;color:#000}}
  .badge-medium{{background:#58A6FF}} .badge-low{{background:#56D364;color:#000}}
  .badge-clean{{background:#30363D}} .badge-info{{background:#30363D}}
  .badge-unknown,.badge-,.badge-notchecked{{background:#444}}
  .risk-bar{{display:flex;height:28px;border-radius:4px;overflow:hidden;margin-top:8px}}
  .risk-segment{{display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:700;color:#fff;min-width:40px}}
  .recs{{padding-left:20px}} .recs li{{margin-bottom:8px;color:#8B949E}} .recs li strong{{color:#E6EDF3}}
  .version{{font-family:Consolas,monospace;font-size:12px;color:#8B949E}}
  .empty{{color:#8B949E;font-style:italic}}
  footer{{padding:20px 40px;color:#30363D;font-size:12px;text-align:center}}
  @media print{{
    body{{background:#fff;color:#000}} .report-header{{background:#f6f8fa}}
    code{{background:#f6f8fa}} th{{background:#f6f8fa}} .card{{background:#f6f8fa}}
    .section{{border-color:#d0d7de}} td{{border-color:#d0d7de}}
    .detail-row{{display:table-row!important}} .detail-panel{{background:#fff;border-top:1px solid #d0d7de}}
    .expand-controls{{display:none}}
  }}
</style>
<script>
function toggle(id){{
  var row=document.getElementById(id);
  var arrow=document.getElementById('arrow-'+id);
  if(!row)return;
  var open=row.style.display==='none'||row.style.display==='';
  row.style.display=open?'table-row':'none';
  if(arrow){{arrow.textContent=open?'▼':'▶';arrow.classList.toggle('open',open);}}
}}
function expandAll(){{
  document.querySelectorAll('.detail-row').forEach(function(r){{r.style.display='table-row';}});
  document.querySelectorAll('.expand-toggle').forEach(function(a){{a.textContent='▼';a.classList.add('open');}});
}}
function collapseAll(){{
  document.querySelectorAll('.detail-row').forEach(function(r){{r.style.display='none';}});
  document.querySelectorAll('.expand-toggle').forEach(function(a){{a.textContent='▶';a.classList.remove('open');}});
}}
</script>
</head>
<body>";
        }

        private static string HtmlFoot() =>
            $"<footer>Generated by PrivaCore on {DateTime.Now:yyyy-MM-dd HH:mm:ss} · For authorised security testing only</footer></body></html>";

        private static string Card(string label, string value, string color, string sub) =>
            $"<div class='card'><div class='card-label'>{label}</div><div class='card-value' style='color:{color}'>{value}</div><div class='card-sub'>{sub}</div></div>";

        private static string Badge(string severity) =>
            $"<span class='badge badge-{severity?.ToLower().Replace(" ", "")}'>{Esc(severity)}</span>";

        private static string RiskColor(string risk) => risk switch
        {
            "Critical" => "#F85149", "High" => "#E3B341",
            "Medium"   => "#58A6FF", "Low"  => "#56D364",
            "Clean"    => "#56D364", _      => "#888"
        };

        private static string Esc(string? s) =>
            s == null ? "" : s.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;").Replace("\"", "&quot;");

        // ── Recommendation builders ─────────────────────────────────────────────
        private static List<string> BuildPortScanRecs(List<PortScanResult> open, bool cveChecked, int totalCves)
        {
            var recs = new List<string>();
            if (!open.Any()) { recs.Add("No open ports found — the target appears well-firewalled or offline."); return recs; }
            if (!cveChecked) recs.Add("Run the <strong>Check CVEs</strong> feature in PrivaCore to identify known vulnerabilities in detected services.");

            var telnet  = open.Any(r => r.Port == 23);
            var ftp     = open.Any(r => r.Port == 21);
            var rdp     = open.Any(r => r.Port == 3389);
            var smb     = open.Any(r => r.Port == 445 || r.Port == 139);
            var http    = open.Any(r => r.Port == 80);
            var mysql   = open.Any(r => r.Port == 3306);

            if (telnet) recs.Add("<strong>Port 23 (Telnet)</strong> is open — Telnet transmits credentials in plaintext. Replace with SSH immediately.");
            if (ftp)    recs.Add("<strong>Port 21 (FTP)</strong> is open — FTP is unencrypted. Migrate to SFTP or FTPS.");
            if (rdp)    recs.Add("<strong>Port 3389 (RDP)</strong> is exposed — restrict to VPN or allowlisted IPs only. Enable NLA.");
            if (smb)    recs.Add("<strong>SMB ports (139/445)</strong> are open — ensure the system is patched against EternalBlue and similar exploits.");
            if (http)   recs.Add("<strong>Port 80 (HTTP)</strong> is open — redirect all traffic to HTTPS and ensure TLS is properly configured.");
            if (mysql)  recs.Add("<strong>Port 3306 (MySQL)</strong> is open — databases should not be exposed externally. Restrict to localhost or a private VLAN.");

            if (totalCves > 0) recs.Add($"<strong>{totalCves} CVE(s)</strong> were identified — patch or upgrade affected services. Prioritise Critical and High severity findings.");
            recs.Add("Close or firewall all ports not required for legitimate business operation.");
            recs.Add("Enable a host-based firewall and ensure all services run under least-privilege accounts.");
            return recs;
        }

        private static List<string> BuildIDSRecs(IReadOnlyList<IDSAlert> alerts, int critical, int high)
        {
            var recs = new List<string>();
            if (!alerts.Any()) { recs.Add("No alerts recorded in this session. Continue monitoring — absence of alerts does not guarantee security."); return recs; }

            if (critical > 0) recs.Add($"<strong>{critical} Critical alert(s)</strong> require immediate investigation. Isolate any affected hosts and review forensic evidence.");
            if (high     > 0) recs.Add($"<strong>{high} High alert(s)</strong> should be reviewed within 24 hours. Check whether the source IP is authorised.");

            var categories = alerts.Select(a => a.AttackCategory ?? "").Distinct().ToList();
            if (categories.Contains("DoS/DDoS"))     recs.Add("DoS/DDoS patterns detected — implement rate limiting at the network edge and consider upstream scrubbing.");
            if (categories.Contains("Brute Force"))  recs.Add("Brute force activity detected — enable account lockout policies and consider geo-blocking or CAPTCHA.");
            if (categories.Contains("Malware/C2"))   recs.Add("<strong>Malware/C2 traffic detected</strong> — isolate the affected host immediately and conduct a forensic investigation.");
            if (categories.Contains("Web Attack"))   recs.Add("Web attack patterns detected — review WAF rules and ensure all web frameworks are up to date.");
            if (categories.Contains("Reconnaissance"))recs.Add("Reconnaissance activity detected — investigate the scanning source and consider adding it to a blocklist.");
            if (categories.Contains("Exploit"))      recs.Add("<strong>Exploit attempts detected</strong> — verify patching status on targeted services.");

            var unacked = alerts.Count(a => !a.IsAcknowledged);
            if (unacked > 0) recs.Add($"{unacked} alert(s) remain unacknowledged — review and acknowledge them in the IDS dashboard.");
            recs.Add("Export and share this report with your security team for follow-up action.");
            return recs;
        }
    }
}
