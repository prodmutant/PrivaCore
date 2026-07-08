using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using PROSCANNERCONT.Models;

namespace PROSCANNERCONT.Utils
{
    public static class ExportUtils
    {
        // ── CSV Export ──────────────────────────────────────────────────────────

        public static string ToPortScanCsv(List<PortScanResult> results)
        {
            var sb = new StringBuilder();
            sb.AppendLine("IP Address,Port,Protocol,Status,Service,Version,Risk Level,CVE Count,CVEs");
            foreach (var r in results)
            {
                var cveIds = r.CveFindings != null
                    ? string.Join("|", r.CveFindings.Select(c => c.CveId))
                    : string.Empty;
                sb.AppendLine(string.Join(",",
                    CsvEscape(r.IPAddress),
                    r.Port,
                    CsvEscape(r.Protocol),
                    CsvEscape(r.Status),
                    CsvEscape(r.Service),
                    CsvEscape(r.Version),
                    CsvEscape(r.RiskLevel),
                    r.VulnCount,
                    CsvEscape(cveIds)));
            }
            return sb.ToString();
        }

        public static string ToNetworkDeviceCsv(List<NetworkDevice> devices)
        {
            var sb = new StringBuilder();
            sb.AppendLine("IP Address,Hostname,MAC Address,OS,Device Type,Status,Online");
            foreach (var d in devices)
            {
                sb.AppendLine(string.Join(",",
                    CsvEscape(d.IPAddress),
                    CsvEscape(d.Hostname),
                    CsvEscape(d.MACAddress),
                    CsvEscape(d.OS),
                    CsvEscape(d.DeviceType),
                    CsvEscape(d.Status),
                    d.IsOnline));
            }
            return sb.ToString();
        }

        // ── JSON Export ─────────────────────────────────────────────────────────

        public static string ToPortScanJson(string target, List<PortScanResult> results)
        {
            var export = new
            {
                ExportedAt = DateTime.UtcNow,
                Tool = "PrivaCore",
                Target = target,
                TotalScanned = results.Count,
                OpenPorts = results.Count(r => r.IsOpen),
                Results = results.Select(r => new
                {
                    r.IPAddress, r.Port, r.Protocol, r.Status,
                    r.Service, r.Version, r.RiskLevel, r.VulnCount,
                    r.RawBanner,
                    Cves = r.CveFindings?.Select(c => new
                    {
                        c.CveId, c.Cvss, c.Severity, c.Summary, c.Reference
                    })
                })
            };
            return JsonSerializer.Serialize(export, new JsonSerializerOptions { WriteIndented = true });
        }

        public static string ToNetworkDeviceJson(List<NetworkDevice> devices)
        {
            var export = new
            {
                ExportedAt = DateTime.UtcNow,
                Tool = "PrivaCore",
                TotalDevices = devices.Count,
                OnlineDevices = devices.Count(d => d.IsOnline),
                Devices = devices
            };
            return JsonSerializer.Serialize(export, new JsonSerializerOptions { WriteIndented = true });
        }

        // ── File Helpers ─────────────────────────────────────────────────────────

        public static void SaveToFile(string content, string defaultFileName, string filter)
        {
            var dialog = new Microsoft.Win32.SaveFileDialog
            {
                FileName = defaultFileName,
                Filter = filter,
                DefaultExt = Path.GetExtension(defaultFileName)
            };
            if (dialog.ShowDialog() == true)
            {
                try
                {
                    File.WriteAllText(dialog.FileName, content, Encoding.UTF8);
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"[ExportUtils.SaveToFile] {ex.Message}");
                    throw;
                }
            }
        }

        public static void ExportPortScanToCsv(string target, List<PortScanResult> results)
        {
            var csv = ToPortScanCsv(results);
            SaveToFile(csv, $"PortScan_{SanitizeFileName(target)}_{DateTime.Now:yyyyMMdd_HHmmss}.csv",
                "CSV Files (*.csv)|*.csv|All Files (*.*)|*.*");
        }

        public static void ExportPortScanToJson(string target, List<PortScanResult> results)
        {
            var json = ToPortScanJson(target, results);
            SaveToFile(json, $"PortScan_{SanitizeFileName(target)}_{DateTime.Now:yyyyMMdd_HHmmss}.json",
                "JSON Files (*.json)|*.json|All Files (*.*)|*.*");
        }

        public static void ExportNetworkDevicesToCsv(List<NetworkDevice> devices)
        {
            var csv = ToNetworkDeviceCsv(devices);
            SaveToFile(csv, $"NetworkScan_{DateTime.Now:yyyyMMdd_HHmmss}.csv",
                "CSV Files (*.csv)|*.csv|All Files (*.*)|*.*");
        }

        public static void ExportNetworkDevicesToJson(List<NetworkDevice> devices)
        {
            var json = ToNetworkDeviceJson(devices);
            SaveToFile(json, $"NetworkScan_{DateTime.Now:yyyyMMdd_HHmmss}.json",
                "JSON Files (*.json)|*.json|All Files (*.*)|*.*");
        }

        // ── Helpers ──────────────────────────────────────────────────────────────

        private static string CsvEscape(string? value)
        {
            if (string.IsNullOrEmpty(value)) return string.Empty;
            if (value.Contains(',') || value.Contains('"') || value.Contains('\n'))
                return $"\"{value.Replace("\"", "\"\"")}\"";
            return value;
        }

        private static string SanitizeFileName(string name)
        {
            foreach (char c in Path.GetInvalidFileNameChars())
                name = name.Replace(c, '_');
            return name;
        }
    }
}
