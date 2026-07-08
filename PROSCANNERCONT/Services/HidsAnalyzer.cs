using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace PROSCANNERCONT.Services
{
    // ── Rich process info from WMI ────────────────────────────────────────
    public class ProcessDetail
    {
        public int    Pid         { get; set; }
        public string Name        { get; set; } = "";
        public string Path        { get; set; } = "";
        public string CommandLine { get; set; } = "";
        public int    ParentPid   { get; set; }
        public string ParentName  { get; set; } = "";
        public long   RamBytes    { get; set; }
        public string FileHash    { get; set; } = "";
        public bool   IsSuspicious{ get; set; }
        public string SuspiciousReason { get; set; } = "";
        public string Severity    { get; set; } = "Info";
        public string SeverityColor { get; set; } = "#808080";
        // Display-only computed props for DataGrid binding
        public string RamMB        => $"{RamBytes / 1048576} MB";
        public string DisplayDetail => IsSuspicious ? SuspiciousReason : CommandLine.Length > 80 ? CommandLine[..80] + "…" : CommandLine;
    }

    public class ServiceDetail
    {
        public string Name        { get; set; } = "";
        public string DisplayName { get; set; } = "";
        public string State       { get; set; } = "";
        public string StartMode   { get; set; } = "";
        public string PathName    { get; set; } = "";
        public bool   IsNew       { get; set; }
        public string Severity    { get; set; } = "Info";
        public string SeverityColor { get; set; } = "#808080";
    }

    public class ScheduledTaskDetail
    {
        public string TaskName    { get; set; } = "";
        public string Status      { get; set; } = "";
        public string NextRun     { get; set; } = "";
        public string LastRun     { get; set; } = "";
        public string Author      { get; set; } = "";
        public string RunAs       { get; set; } = "";
        public bool   IsNew       { get; set; }
        public string Severity    { get; set; } = "Info";
        public string SeverityColor { get; set; } = "#808080";
    }

    public class SessionDetail
    {
        public string SessionName { get; set; } = "";
        public string UserName    { get; set; } = "";
        public string State       { get; set; } = "";
        public string Type        { get; set; } = "";
        public bool   IsNew       { get; set; }
        public string Severity    { get; set; } = "Info";
        public string SeverityColor { get; set; } = "#808080";
    }

    public class DnsEntry
    {
        public string Domain      { get; set; } = "";
        public string RecordType  { get; set; } = "";
        public string Data        { get; set; } = "";
        public double Entropy     { get; set; }
        public bool   IsSuspicious{ get; set; }
        public string Reason      { get; set; } = "";
        public string Severity    { get; set; } = "Info";
        public string SeverityColor { get; set; } = "#808080";
        public string EntropyStr  => $"{Entropy:F2}";
    }

    /// <summary>
    /// All heavy-lifting HIDS analysis lives here. Keeps the Page code-behind clean.
    /// Uses WMI (System.Management) which is already referenced in the project.
    /// </summary>
    public static class HidsAnalyzer
    {
        // ── Parent-child anomaly rules ────────────────────────────────────
        private static readonly Dictionary<string, string[]> _dangerousChildren = new(StringComparer.OrdinalIgnoreCase)
        {
            // Office spawning shells = macro / phishing
            ["winword"]      = new[] { "cmd", "powershell", "pwsh", "wscript", "cscript", "mshta", "wmic", "regsvr32", "rundll32", "certutil" },
            ["excel"]        = new[] { "cmd", "powershell", "pwsh", "wscript", "cscript", "mshta", "wmic", "regsvr32", "rundll32", "certutil" },
            ["powerpnt"]     = new[] { "cmd", "powershell", "pwsh", "wscript", "cscript", "mshta" },
            ["outlook"]      = new[] { "cmd", "powershell", "pwsh", "wscript", "cscript" },
            // Browser spawning shell = browser exploit
            ["chrome"]       = new[] { "cmd", "powershell", "pwsh", "wscript", "cscript" },
            ["firefox"]      = new[] { "cmd", "powershell", "pwsh", "wscript", "cscript" },
            ["msedge"]       = new[] { "cmd", "powershell", "pwsh", "wscript", "cscript" },
            ["iexplore"]     = new[] { "cmd", "powershell", "pwsh", "wscript", "cscript", "mshta" },
        };

        // Suspicious execution locations
        private static readonly string[] _suspiciousPaths = { @"\temp\", @"\tmp\", @"\appdata\local\temp\", @"\public\", @"\users\public\" };

        // Known bad TLDs for DNS monitoring
        private static readonly HashSet<string> _suspiciousTlds = new(StringComparer.OrdinalIgnoreCase)
        { ".tk", ".ml", ".ga", ".cf", ".gq", ".pw", ".top", ".xyz", ".work", ".click", ".download" };

        // ── Process analysis (WMI) ────────────────────────────────────────
        public static List<ProcessDetail> GetProcessDetails(List<string> extraBlacklist, bool hashFiles)
        {
            var baseBlacklist = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "mimikatz","procdump","pwdump","wce","fgdump","gsecdump",
                "meterpreter","ncat","netcat","psexec","cobaltstrike","cobalt",
                "empire","beacon","lazagne","sharphound","bloodhound","rubeus",
                "seatbelt","powersploit","covenant","crackmapexec","responder",
                "windump","wlanhelper","netpass","mailpassview","webpassview",
                "pth-winexe","pth-wmic","pth-curl","kerbrute","hashcat","john"
            };
            foreach (var e in extraBlacklist) baseBlacklist.Add(e);

            // Build PID→Name map first
            var pidNames = new Dictionary<int, string>();
            try
            {
                using var sc = new ManagementObjectSearcher("SELECT ProcessId, Name FROM Win32_Process");
                foreach (ManagementObject o in sc.Get())
                    pidNames[Convert.ToInt32(o["ProcessId"])] = o["Name"]?.ToString()?.Replace(".exe","") ?? "";
            }
            catch { }

            var result = new List<ProcessDetail>();
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    "SELECT ProcessId, Name, ExecutablePath, CommandLine, ParentProcessId, WorkingSetSize FROM Win32_Process");

                foreach (ManagementObject obj in searcher.Get())
                {
                    // Wrap per-object so one bad process (System Idle, protected) doesn't abort the loop
                    try
                    {
                    int  pid      = obj["ProcessId"]      != null ? Convert.ToInt32(obj["ProcessId"])      : 0;
                    string name   = (obj["Name"]?.ToString() ?? "").Replace(".exe", "");
                    string path   = obj["ExecutablePath"]?.ToString() ?? "";
                    string cmd    = obj["CommandLine"]?.ToString()    ?? "";
                    int ppid      = obj["ParentProcessId"] != null ? Convert.ToInt32(obj["ParentProcessId"]) : 0;
                    // WorkingSetSize is uint64 in WMI — guard against overflow on exotic system processes
                    long ram = 0;
                    try { ram = obj["WorkingSetSize"] != null ? (long)(ulong)obj["WorkingSetSize"] : 0; } catch { }
                    string parent = pidNames.TryGetValue(ppid, out var pn) ? pn : $"PID:{ppid}";

                    string suspReason = "";
                    string sev = "Info";

                    // Blacklist check
                    if (baseBlacklist.Any(b => name.Contains(b, StringComparison.OrdinalIgnoreCase)))
                    { suspReason = $"Known attack tool: {name}"; sev = "Critical"; }

                    // Parent-child anomaly
                    if (string.IsNullOrEmpty(suspReason) &&
                        _dangerousChildren.TryGetValue(parent, out var badChildren) &&
                        badChildren.Any(c => name.Equals(c, StringComparison.OrdinalIgnoreCase)))
                    { suspReason = $"Parent-child anomaly: {parent} → {name} (LOLBin/macro)"; sev = "Critical"; }

                    // Suspicious exec path
                    if (string.IsNullOrEmpty(suspReason) && !string.IsNullOrEmpty(path))
                    {
                        string lp = path.ToLower();
                        if (_suspiciousPaths.Any(sp => lp.Contains(sp)))
                        { suspReason = $"Execution from suspicious path: {path}"; sev = "High"; }
                    }

                    // PowerShell encoded commands
                    if (string.IsNullOrEmpty(suspReason) && name.Equals("powershell", StringComparison.OrdinalIgnoreCase))
                    {
                        string lc = cmd.ToLower();
                        if (lc.Contains("-enc") || lc.Contains("-encodedcommand") || lc.Contains("-w hidden") || lc.Contains("-nop") || lc.Contains("bypass"))
                        { suspReason = $"Suspicious PowerShell flags: {cmd[..Math.Min(120, cmd.Length)]}"; sev = "High"; }
                    }

                    // File hash (optional, only for flagged processes or when explicitly enabled)
                    string hash = "";
                    if (hashFiles && !string.IsNullOrEmpty(path) && File.Exists(path) && (!string.IsNullOrEmpty(suspReason)))
                    {
                        try { hash = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)))[..16] + "…"; }
                        catch { }
                    }

                    bool isSus = !string.IsNullOrEmpty(suspReason);
                    result.Add(new ProcessDetail
                    {
                        Pid = pid, Name = name, Path = path, CommandLine = cmd,
                        ParentPid = ppid, ParentName = parent, RamBytes = ram,
                        FileHash = hash, IsSuspicious = isSus, SuspiciousReason = suspReason,
                        Severity = isSus ? sev : "Info",
                        SeverityColor = isSus ? (sev == "Critical" ? "#F44747" : "#FF8C00") : "#808080"
                    });
                    } catch { } // end per-object try
                }
            }
            catch { }
            return result.OrderByDescending(p => p.IsSuspicious).ThenByDescending(p => p.RamBytes).ToList();
        }

        // ── Service monitoring ────────────────────────────────────────────
        public static List<ServiceDetail> GetServices()
        {
            var list = new List<ServiceDetail>();
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    "SELECT Name, DisplayName, State, StartMode, PathName FROM Win32_Service");
                foreach (ManagementObject obj in searcher.Get())
                {
                    string state = obj["State"]?.ToString() ?? "";
                    string mode  = obj["StartMode"]?.ToString() ?? "";
                    string path  = obj["PathName"]?.ToString() ?? "";
                    string sev   = "Info";
                    string lp    = path.ToLower();
                    if (_suspiciousPaths.Any(sp => lp.Contains(sp))) sev = "High";

                    list.Add(new ServiceDetail
                    {
                        Name        = obj["Name"]?.ToString() ?? "",
                        DisplayName = obj["DisplayName"]?.ToString() ?? "",
                        State       = state,
                        StartMode   = mode,
                        PathName    = path,
                        Severity    = sev,
                        SeverityColor = sev == "High" ? "#FF8C00" : "#808080"
                    });
                }
            }
            catch { }
            return list.OrderBy(s => s.Name).ToList();
        }

        // ── Scheduled task monitoring ─────────────────────────────────────
        public static List<ScheduledTaskDetail> GetScheduledTasks()
        {
            var list = new List<ScheduledTaskDetail>();
            try
            {
                // /fo csv /v gives structured output; without /nh we skip the header manually
                var psi = new ProcessStartInfo("schtasks", "/query /fo csv /v")
                { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
                using var proc = Process.Start(psi);
                string output = proc?.StandardOutput.ReadToEnd() ?? "";
                proc?.WaitForExit(8000);

                bool firstLine = true;
                foreach (var line in output.Split('\n').Where(l => !string.IsNullOrWhiteSpace(l)))
                {
                    if (firstLine) { firstLine = false; continue; } // skip CSV header
                    var fields = ParseCsvLine(line);
                    if (fields.Count < 9) continue;
                    string name   = fields[1].Trim('"', ' ');
                    string status = fields[3].Trim('"', ' ');
                    string next   = fields[4].Trim('"', ' ');
                    string last   = fields[5].Trim('"', ' ');
                    string author = fields[7].Trim('"', ' ');
                    string runAs  = fields[8].Trim('"', ' ');
                    if (string.IsNullOrWhiteSpace(name) || name == "TaskName") continue;

                    string sev = runAs.Contains("SYSTEM", StringComparison.OrdinalIgnoreCase) ? "Medium" : "Info";
                    list.Add(new ScheduledTaskDetail
                    {
                        TaskName = name, Status = status, NextRun = next,
                        LastRun = last, Author = author, RunAs = runAs,
                        Severity = sev,
                        SeverityColor = sev == "Medium" ? "#DCDCAA" : "#808080"
                    });
                }
            }
            catch { }
            return list;
        }

        // ── Login session monitoring ──────────────────────────────────────
        public static List<SessionDetail> GetSessions()
        {
            var list = new List<SessionDetail>();
            try
            {
                var psi = new ProcessStartInfo("query", "session")
                { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
                using var proc = Process.Start(psi);
                string output = proc?.StandardOutput.ReadToEnd() ?? "";
                proc?.WaitForExit(3000);

                foreach (var line in output.Split('\n').Skip(1))
                {
                    if (string.IsNullOrWhiteSpace(line)) continue;
                    var parts = line.Trim().Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length < 3) continue;

                    string sessionName = parts[0]; string user = "", state = "", type = "";
                    if (parts.Length >= 4) { user = parts[1]; state = parts[3]; }
                    else if (parts.Length == 3) { user = ""; state = parts[2]; }
                    bool isRdp = sessionName.StartsWith("rdp", StringComparison.OrdinalIgnoreCase);
                    string sev = isRdp ? "Medium" : "Info";

                    list.Add(new SessionDetail
                    {
                        SessionName = sessionName, UserName = user, State = state,
                        Type = isRdp ? "RDP" : "Local",
                        Severity = sev, SeverityColor = isRdp ? "#DCDCAA" : "#808080"
                    });
                }
            }
            catch { }
            return list;
        }

        // ── DNS cache monitoring ──────────────────────────────────────────
        private static readonly Regex _dnsRecordRegex = new(
            @"Record Name\s*\.\s*\.\s*\.\s*:\s*(.+)|Record Type\s*\.\s*\.\s*\.\s*:\s*(.+)|A \(Host\) Record\s*\.\s*:\s*(.+)|CNAME Record\s*\.\s*:\s*(.+)",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        public static List<DnsEntry> GetDnsCache()
        {
            var list = new List<DnsEntry>();
            try
            {
                var psi = new ProcessStartInfo("ipconfig", "/displaydns")
                { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
                using var proc = Process.Start(psi);
                string output = proc?.StandardOutput.ReadToEnd() ?? "";
                proc?.WaitForExit(5000);

                string currentDomain = "";
                string currentType   = "";
                foreach (var line in output.Split('\n'))
                {
                    string t = line.Trim();
                    if (t.StartsWith("Record Name")) currentDomain = t.Split(':').Last().Trim();
                    else if (t.StartsWith("Record Type")) currentType = t.Split(':').Last().Trim();
                    else if ((t.StartsWith("A (Host)") || t.StartsWith("CNAME")) && !string.IsNullOrEmpty(currentDomain))
                    {
                        string data = t.Split(':').Last().Trim();
                        var entry = AnalyseDomain(currentDomain, currentType, data);
                        list.Add(entry);
                        currentDomain = "";
                    }
                }
            }
            catch { }
            // Deduplicate
            return list.GroupBy(e => e.Domain).Select(g => g.First())
                       .OrderByDescending(e => e.IsSuspicious).ThenBy(e => e.Domain).ToList();
        }

        private static DnsEntry AnalyseDomain(string domain, string type, string data)
        {
            double entropy = ShannonEntropy(domain.Split('.').FirstOrDefault() ?? domain);
            bool suspTld   = _suspiciousTlds.Any(t => domain.EndsWith(t, StringComparison.OrdinalIgnoreCase));
            bool longSub   = domain.Split('.').Any(l => l.Length > 45);
            bool highEnt   = entropy > 3.5;
            bool manyLabels = domain.Split('.').Length > 5;

            string reason = "";
            string sev    = "Info";
            if (suspTld)   { reason += "Suspicious TLD; "; sev = "High"; }
            if (highEnt)   { reason += $"High entropy ({entropy:F2}) — possible DGA; "; sev = sev == "Info" ? "Medium" : sev; }
            if (longSub)   { reason += "Very long subdomain (DNS tunnel?); "; sev = "High"; }
            if (manyLabels){ reason += "Deep label chain; "; sev = sev == "Info" ? "Low" : sev; }

            return new DnsEntry
            {
                Domain = domain, RecordType = type, Data = data, Entropy = entropy,
                IsSuspicious = !string.IsNullOrEmpty(reason),
                Reason = reason.TrimEnd(' ', ';'),
                Severity = sev,
                SeverityColor = sev switch { "High" => "#FF8C00", "Medium" => "#FFA500", "Low" => "#4EC9B0", _ => "#808080" }
            };
        }

        // ── File hash ─────────────────────────────────────────────────────
        public static string HashFile(string path)
        {
            try { return Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))); }
            catch { return ""; }
        }

        // ── Windows Event full-text extraction ───────────────────────────
        /// <summary>Extract structured fields from a raw Windows Event message.</summary>
        public static Dictionary<string, string> ParseEventFields(string message)
        {
            var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (string.IsNullOrEmpty(message)) return dict;
            foreach (var line in message.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
            {
                int colon = line.IndexOf(':');
                if (colon < 1) continue;
                string key = line[..colon].Trim();
                string val = line[(colon + 1)..].Trim();
                if (!string.IsNullOrEmpty(key) && !string.IsNullOrEmpty(val) && !dict.ContainsKey(key))
                    dict[key] = val;
            }
            return dict;
        }

        // ── Helpers ───────────────────────────────────────────────────────
        private static double ShannonEntropy(string s)
        {
            if (string.IsNullOrEmpty(s)) return 0;
            var freq = new Dictionary<char, int>();
            foreach (char c in s) freq[c] = freq.TryGetValue(c, out int v) ? v + 1 : 1;
            double e = 0;
            foreach (var f in freq.Values) { double p = (double)f / s.Length; e -= p * Math.Log2(p); }
            return e;
        }

        private static List<string> ParseCsvLine(string line)
        {
            var fields = new List<string>();
            bool inQ = false; var cur = new StringBuilder();
            foreach (char c in line)
            {
                if (c == '"') { inQ = !inQ; }
                else if (c == ',' && !inQ) { fields.Add(cur.ToString()); cur.Clear(); }
                else cur.Append(c);
            }
            fields.Add(cur.ToString());
            return fields;
        }
    }
}
