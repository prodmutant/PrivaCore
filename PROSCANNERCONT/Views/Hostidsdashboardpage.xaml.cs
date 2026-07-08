using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
using Microsoft.Win32;
using PROSCANNERCONT.Models;
using PROSCANNERCONT.Services;
using PROSCANNERCONT.Utils;

namespace PROSCANNERCONT.Views
{
    public partial class HostIDSDashboardPage : Page
    {
        // â”€â”€ State â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        private bool _isMonitoring = false;
        private readonly DispatcherTimer _timer = new();
        private volatile bool _polling = false;   // prevents overlapping background polls

        // â”€â”€ Observable collections for all tabs â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        private readonly ObservableCollection<HostEventItem>      _eventItems   = new();
        private readonly ObservableCollection<HostEventItem>      _fileItems    = new();
        private readonly ObservableCollection<ProcessDetail>      _procItems    = new();
        private readonly ObservableCollection<HostEventItem>      _connItems    = new();
        private readonly ObservableCollection<HostEventItem>      _regItems     = new();
        private readonly ObservableCollection<ServiceDetail>      _svcItems     = new();
        private readonly ObservableCollection<ScheduledTaskDetail>_taskItems    = new();
        private readonly ObservableCollection<SessionDetail>      _sessionItems = new();
        private readonly ObservableCollection<DnsEntry>           _dnsItems     = new();

        // â”€â”€ File watchers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        private readonly FileSystemWatcher _winWatcher      = new();
        private readonly FileSystemWatcher _sys32Watcher    = new();
        private readonly FileSystemWatcher _syswow64Watcher = new();
        private readonly List<FileSystemWatcher> _customWatchers = new();

        // â”€â”€ Counters â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        private int _fileChanges = 0, _procAlerts = 0, _secEvents = 0, _regChanges = 0;
        private readonly Dictionary<long, DateTime> _seenEventIds = new();

        // â”€â”€ Registry baseline â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        private Dictionary<string, string> _regSnapshot = new();
        private bool _regSnapshotTaken = false;

        // â”€â”€ Service / task / session baselines â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        private HashSet<string> _svcBaseline  = new();
        private HashSet<string> _taskBaseline = new();
        private HashSet<string> _sessionBaseline = new();
        private bool _baselinesSet = false;

        // â”€â”€ File hash baseline (path â†’ sha256) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        private readonly Dictionary<string, string> _hashBaseline = new();

        // â”€â”€ Persistence â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        private static readonly string _hidsDir   = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "PrivaCore", "HIDS");
        private static readonly string _eventsPath = Path.Combine(_hidsDir, "events.json");

        // â”€â”€ Pull live settings from ConfigManager singleton â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        private HidsRuntimeSettings S => ConfigManager.Hids;

        // â”€â”€ Registry keys to monitor â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        private static readonly (RegistryKey root, string subPath)[] _baseRegKeys =
        {
            (Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
            (Registry.CurrentUser,  @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (Registry.CurrentUser,  @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
            (Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Services"),
        };

        // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
        public HostIDSDashboardPage()
        {
            InitializeComponent();

            EventLogList.ItemsSource           = _eventItems;
            FileChangesList.ItemsSource        = _fileItems;
            ProcessList.ItemsSource            = _procItems;
            NetworkConnectionsList.ItemsSource = _connItems;
            if (RegistryChangesList != null) RegistryChangesList.ItemsSource = _regItems;
            if (ServicesList        != null) ServicesList.ItemsSource        = _svcItems;
            if (TasksList           != null) TasksList.ItemsSource           = _taskItems;
            if (SessionsList        != null) SessionsList.ItemsSource        = _sessionItems;
            if (DnsList             != null) DnsList.ItemsSource             = _dnsItems;

            Directory.CreateDirectory(_hidsDir);
            LoadPersistedEvents();

            _timer.Interval = TimeSpan.FromSeconds(S.PollIntervalSeconds);
            // Run polls on a thread-pool thread so WMI/process queries never block the UI
            _timer.Tick += (_, __) => { if (_isMonitoring && !_polling) _ = Task.Run(SafePollAll); };

            UpdateStatusStrip();
        }

        // â”€â”€ Monitoring toggle â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        private void ToggleMonitoring_Click(object sender, RoutedEventArgs e)
        {
            _isMonitoring = !_isMonitoring;
            if (_isMonitoring)
            {
                _timer.Interval = TimeSpan.FromSeconds(Math.Max(1, S.PollIntervalSeconds));
                SetupFileWatchers();
                _timer.Start();

                // Baseline + first poll run on background thread â€” never touch the UI thread
                _ = Task.Run(() =>
                {
                    TakeRegistrySnapshot();
                    TakeBaselines();
                    SafePollAll();
                });

                MonitoringToggleButton.Content    = "â¸  Stop Monitoring";
                if (StatusDot   != null) StatusDot.Fill   = new SolidColorBrush(Color.FromRgb(74, 222, 128));
                if (StatusLabel != null) StatusLabel.Text = "RUNNING â€” Events Â· Files Â· Processes Â· Connections Â· Registry Â· Services Â· Tasks Â· Sessions Â· DNS";
                try { MonitoringToggleButton.Background = (Brush)Application.Current.FindResource("WarningOrange"); }
                catch { MonitoringToggleButton.Background = Brushes.OrangeRed; }
                AddEvent(_eventItems, "HOST IDS STARTED", "Full monitoring active", "Info");
            }
            else
            {
                _timer.Stop(); StopAllWatchers(); PersistEvents();
                MonitoringToggleButton.Content    = "â–¶  Start Monitoring";
                if (StatusDot   != null) StatusDot.Fill   = new SolidColorBrush(Colors.Red);
                if (StatusLabel != null) StatusLabel.Text = "STOPPED";
                try { MonitoringToggleButton.Background = (Brush)Application.Current.FindResource("SuccessGreen"); }
                catch { MonitoringToggleButton.Background = Brushes.Green; }
                AddEvent(_eventItems, "HOST IDS STOPPED", "Monitoring paused", "Info");
            }
        }

        // â”€â”€ File watchers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        private void SetupFileWatchers()
        {
            string win    = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            string sys32  = Path.Combine(win, "System32");
            string wow64  = Path.Combine(win, "SysWOW64");
            SetupWatcher(_winWatcher,      win,   false);
            if (Directory.Exists(sys32))  SetupWatcher(_sys32Watcher,    sys32, false);
            if (Directory.Exists(wow64))  SetupWatcher(_syswow64Watcher, wow64, false);
            foreach (var p in S.CustomWatchPaths.Where(Directory.Exists))
            { var w = new FileSystemWatcher(); SetupWatcher(w, p, true); _customWatchers.Add(w); }
        }

        private void SetupWatcher(FileSystemWatcher w, string path, bool sub)
        {
            try
            {
                w.Path = path; w.Filter = "*.*"; w.IncludeSubdirectories = sub;
                w.NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Attributes;
                w.Created += (_, ev) => OnFileChanged("Created", ev.FullPath);
                w.Changed += (_, ev) => OnFileChanged("Changed", ev.FullPath);
                w.Deleted += (_, ev) => OnFileChanged("Deleted", ev.FullPath);
                w.Renamed += (_, ev) => OnFileChanged("Renamed", ev.FullPath);
                w.EnableRaisingEvents = true;
            }
            catch (Exception ex) { Debug.WriteLine($"FileWatcher ({path}): {ex.Message}"); }
        }

        private void StopAllWatchers()
        {
            foreach (var w in new[] { _winWatcher, _sys32Watcher, _syswow64Watcher })
                try { w.EnableRaisingEvents = false; } catch { }
            foreach (var w in _customWatchers)
                try { w.EnableRaisingEvents = false; w.Dispose(); } catch { }
            _customWatchers.Clear();
        }

        private void OnFileChanged(string changeType, string path)
        {
            Dispatcher.InvokeAsync(() =>
            {
                _fileChanges++;
                if (FileChangesText != null) FileChangesText.Text = _fileChanges.ToString();
                string lp  = path.ToLower();
                string sev = lp.Contains("system32") || lp.Contains("syswow64") ? "Critical" :
                             lp.EndsWith(".exe") || lp.EndsWith(".dll") || lp.EndsWith(".sys") ? "High" :
                             lp.EndsWith(".bat") || lp.EndsWith(".ps1") || lp.EndsWith(".vbs") || lp.EndsWith(".js") ? "High" : "Info";

                // Optional: hash changed file
                string hash = "";
                if (S.EnableFileHashing && sev is "Critical" or "High" && File.Exists(path))
                {
                    hash = HidsAnalyzer.HashFile(path);
                    if (!string.IsNullOrEmpty(hash))
                    {
                        if (_hashBaseline.TryGetValue(path, out var prev) && prev != hash)
                            sev = "Critical";
                        _hashBaseline[path] = hash;
                    }
                }

                string detail = string.IsNullOrEmpty(hash) ? path : $"{path}  [SHA256:{hash[..16]}â€¦]";
                AddEvent(_fileItems, $"File {changeType}", detail, sev);
                if (_fileItems.Count > 300) _fileItems.RemoveAt(_fileItems.Count - 1);
                if (sev is "Critical" or "High")
                    AlertToast.Show($"File {changeType} â€” {sev}", path, sev == "Critical" ? "#F44747" : "#FF8C00");
            });
        }

        // â”€â”€ Poll everything â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        private void SafePollAll()
        {
            if (_polling) return;
            _polling = true;
            try { PollAll(); }
            catch { }
            finally { _polling = false; }
        }

        private void PollAll()
        {
            // Each sub-poll has its own try/catch so one failure never kills the rest
            Try(PollWindowsEvents);
            Try(PollProcesses);
            Try(PollNetworkConnections);
            Try(PollRegistryChanges);
            if (S.EnableServiceMonitor)       Try(PollServices);
            if (S.EnableScheduledTaskMonitor) Try(PollScheduledTasks);
            if (S.EnableSessionMonitor)       Try(PollSessions);
            if (S.EnableDnsMonitor)           Try(PollDnsCache);
            Try(UpdateSystemHealth);
        }

        private static void Try(Action a) { try { a(); } catch { } }

        // â”€â”€ Windows Security Event Log â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        private void PollWindowsEvents()
        {
            try
            {
                var stale = _seenEventIds.Where(kv => (DateTime.Now - kv.Value).TotalMinutes > 15).Select(kv => kv.Key).ToList();
                foreach (var k in stale) _seenEventIds.Remove(k);

                var log    = new EventLog("Security");
                var recent = log.Entries.Cast<EventLogEntry>()
                    .Where(e => e.TimeGenerated > DateTime.Now.AddMinutes(-5))
                    .OrderByDescending(e => e.TimeGenerated).Take(30).ToList();

                Dispatcher.InvokeAsync(() =>
                {
                    foreach (var entry in recent)
                    {
                        if (_seenEventIds.ContainsKey(entry.Index)) continue;
                        _seenEventIds[entry.Index] = DateTime.Now;
                        int id = (int)entry.InstanceId;
                        string? sev = id switch
                        {
                            1102 => "Critical", 4625 => "Critical", 4697 => "Critical", 7045 => "Critical",
                            4648 => "High",     4672 => "High",     4698 => "High",     4720 => "High",
                            4732 => "High",     4756 => "High",     4776 => "High",
                            4688 => "Medium",   4663 => "Medium",   4624 => "Info",
                            _ => null
                        };
                        if (sev == null) continue;
                        _secEvents++;
                        if (SecurityEventsText != null) SecurityEventsText.Text = _secEvents.ToString();

                        string label = id switch
                        {
                            1102 => "âš  AUDIT LOG CLEARED",  4625 => "FAILED LOGON",      4697 => "âš  SERVICE INSTALLED",
                            7045 => "âš  NEW SERVICE",         4648 => "EXPLICIT CREDS",     4672 => "SPECIAL PRIVILEGE",
                            4698 => "SCHEDULED TASK CREATED",4720 => "USER CREATED",       4732 => "LOCAL ADMIN MODIFIED",
                            4756 => "SECURITY GROUP MODIFIED",4776 => "NTLM AUTH",         4688 => "PROCESS CREATED",
                            4663 => "OBJECT ACCESSED",       4624 => "LOGON SUCCESS",      _ => $"Event {id}"
                        };

                        // Extract structured fields from full event message
                        var fields = HidsAnalyzer.ParseEventFields(entry.Message ?? "");
                        string subject = fields.TryGetValue("Account Name", out var an) ? $"  User: {an}" :
                                         fields.TryGetValue("New Logon", out var nl)    ? $"  Logon: {nl}" : "";
                        string process = fields.TryGetValue("Process Name", out var pn) ? $"  Proc: {Path.GetFileName(pn)}" : "";
                        string detail  = (subject + process).Trim();
                        if (string.IsNullOrEmpty(detail)) detail = entry.Message?.Split(Environment.NewLine)?[0]?.Trim() ?? "";

                        AddEvent(_eventItems, label, detail, sev);
                        if (_eventItems.Count > 300) _eventItems.RemoveAt(_eventItems.Count - 1);
                        if (sev is "Critical" or "High")
                            AlertToast.Show($"HIDS â€” {label}", detail[..Math.Min(80, detail.Length)], sev == "Critical" ? "#F44747" : "#FF8C00");
                    }
                    UpdateBadges();
                });
            }
            catch { }
        }

        // â”€â”€ Processes (WMI) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        private void PollProcesses()
        {
            var procs = HidsAnalyzer.GetProcessDetails(S.AdditionalProcessBlacklist, S.EnableFileHashing);
            Dispatcher.InvokeAsync(() =>
            {
                try
                {
                    _procItems.Clear();
                    foreach (var p in procs) _procItems.Add(p);
                    int badCount = procs.Count(p => p.IsSuspicious);
                    _procAlerts = badCount;
                    if (ProcessAlertsText != null) ProcessAlertsText.Text = badCount.ToString();
                    if (ProcCountText     != null) ProcCountText.Text     = badCount > 0 ? badCount.ToString() : "0";
                    foreach (var p in procs.Where(p => p.IsSuspicious))
                    {
                        string reason = p.SuspiciousReason ?? "";
                        AlertToast.Show("Suspicious Process!", $"{p.Name} â€” {reason[..Math.Min(60, reason.Length)]}", "#F44747");
                    }
                }
                catch { }
            });
        }

        // â”€â”€ Network connections â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        private void PollNetworkConnections()
        {
            try
            {
                // netstat -b includes process names (requires admin)
                var psi = new ProcessStartInfo("netstat", "-ano")
                { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
                using var proc = Process.Start(psi);
                string output = proc?.StandardOutput.ReadToEnd() ?? "";
                proc?.WaitForExit(3000);

                Dispatcher.InvokeAsync(() =>
                {
                    _connItems.Clear();
                    var badPorts = new HashSet<int> { 4444, 4445, 5555, 6666, 6667, 1337, 31337, 9001, 9030, 4433, 2222 };
                    foreach (var p in S.AdditionalSuspiciousPorts) badPorts.Add(p);

                    foreach (var line in output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries).Skip(4).Take(60))
                    {
                        var parts = line.Trim().Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                        if (parts.Length < 3) continue;
                        string proto = parts[0]; string local = parts[1]; string remote = parts[2];
                        string state = parts.Length > 3 ? parts[3] : "";
                        string pid   = parts.Length > 4 ? parts[4] : "";

                        bool sus = remote.Split(':') is string[] rp && rp.Length > 1 &&
                                   int.TryParse(rp[rp.Length - 1], out int rport) && badPorts.Contains(rport);

                        _connItems.Add(new HostEventItem
                        {
                            Time   = DateTime.Now.ToString("HH:mm:ss"),
                            Title  = $"{proto} {state}  PID:{pid}",
                            Detail = $"{local}  â†’  {remote}",
                            Severity = sus ? "High" : "Info",
                            SeverityColor = sus ? "#FF8C00" : "#808080"
                        });
                    }
                    if (ConnCountText != null) ConnCountText.Text = _connItems.Count.ToString();
                });
            }
            catch { }
        }

        // â”€â”€ Registry monitoring â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        private void TakeRegistrySnapshot() { _regSnapshot = BuildRegSnapshot(); _regSnapshotTaken = true; }

        private Dictionary<string, string> BuildRegSnapshot()
        {
            var snap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            // Base keys
            foreach (var (root, sub) in _baseRegKeys)
                TrySnapshotKey(snap, root, sub, root == Registry.LocalMachine ? "HKLM" : "HKCU");
            // Extra keys from config
            foreach (var keyPath in S.AdditionalRegistryKeys)
            {
                var parts = keyPath.Split('\\', 2);
                if (parts.Length < 2) continue;
                var root = parts[0].Equals("HKLM", StringComparison.OrdinalIgnoreCase) ? Registry.LocalMachine : Registry.CurrentUser;
                TrySnapshotKey(snap, root, parts[1], parts[0]);
            }
            return snap;
        }

        private static void TrySnapshotKey(Dictionary<string, string> snap, RegistryKey root, string sub, string rootName)
        {
            try
            {
                using var key = root.OpenSubKey(sub);
                if (key == null) return;
                foreach (var name in key.GetValueNames())
                    snap[$"{rootName}\\{sub}\\{name}"] = key.GetValue(name)?.ToString() ?? "";
            }
            catch { }
        }

        private void PollRegistryChanges()
        {
            if (!_regSnapshotTaken) return;
            var current = BuildRegSnapshot();
            Dispatcher.InvokeAsync(() =>
            {
                foreach (var kv in current)
                {
                    if (_regSnapshot.TryGetValue(kv.Key, out var prev))
                    {
                        if (prev != kv.Value) { _regChanges++; Fire("Registry MODIFIED", $"{kv.Key}  [{prev}]  â†’  [{kv.Value}]", "Critical"); }
                    }
                    else if (_regSnapshotTaken) { _regChanges++; Fire("Registry ADDED", $"{kv.Key} = {kv.Value}", "Critical"); }
                }
                foreach (var kv in _regSnapshot.Where(k => !current.ContainsKey(k.Key)))
                { _regChanges++; Fire("Registry DELETED", kv.Key, "High"); }
                _regSnapshot = current;
                if (RegChangesText != null) RegChangesText.Text = _regChanges.ToString();

                void Fire(string title, string detail, string sev)
                {
                    AddEvent(_regItems, title, detail, sev);
                    if (_regItems.Count > 300) _regItems.RemoveAt(_regItems.Count - 1);
                    AlertToast.Show(title, detail[..Math.Min(80, detail.Length)], sev == "Critical" ? "#F44747" : "#FF8C00");
                }
            });
        }

        // â”€â”€ Services â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        private void TakeBaselines()
        {
            _svcBaseline     = new HashSet<string>(HidsAnalyzer.GetServices().Select(s => s.Name),     StringComparer.OrdinalIgnoreCase);
            _taskBaseline    = new HashSet<string>(HidsAnalyzer.GetScheduledTasks().Select(t => t.TaskName), StringComparer.OrdinalIgnoreCase);
            _sessionBaseline = new HashSet<string>(HidsAnalyzer.GetSessions().Select(s => s.SessionName), StringComparer.OrdinalIgnoreCase);
            _baselinesSet    = true;
        }

        private void PollServices()
        {
            var svcs = HidsAnalyzer.GetServices();
            Dispatcher.InvokeAsync(() =>
            {
                try
                {
                    _svcItems.Clear();
                    foreach (var s in svcs)
                    {
                        if (_baselinesSet && !_svcBaseline.Contains(s.Name ?? ""))
                        {
                            s.IsNew = true; s.Severity = "Critical"; s.SeverityColor = "#F44747";
                            string pathPreview = (s.PathName ?? "")[..Math.Min(60, (s.PathName ?? "").Length)];
                            AlertToast.Show("New Service Detected!", $"{s.Name} â€” {pathPreview}", "#F44747");
                            AddEvent(_eventItems, "NEW SERVICE INSTALLED", $"{s.Name}: {s.PathName}", "Critical");
                            _svcBaseline.Add(s.Name ?? "");
                        }
                        _svcItems.Add(s);
                    }
                    if (SvcCountText != null) SvcCountText.Text = _svcItems.Count(s => s.IsNew).ToString();
                }
                catch { }
            });
        }

        // â”€â”€ Scheduled tasks â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        private void PollScheduledTasks()
        {
            var tasks = HidsAnalyzer.GetScheduledTasks();
            Dispatcher.InvokeAsync(() =>
            {
                _taskItems.Clear();
                foreach (var t in tasks)
                {
                    if (_baselinesSet && !_taskBaseline.Contains(t.TaskName))
                    {
                        t.IsNew = true; t.Severity = "High"; t.SeverityColor = "#FF8C00";
                        AlertToast.Show("New Scheduled Task!", t.TaskName, "#FF8C00");
                        AddEvent(_eventItems, "NEW SCHEDULED TASK", $"{t.TaskName}  RunAs:{t.RunAs}", "High");
                        _taskBaseline.Add(t.TaskName);
                    }
                    _taskItems.Add(t);
                }
                if (TaskCountText != null) TaskCountText.Text = _taskItems.Count(t => t.IsNew).ToString();
            });
        }

        // â”€â”€ Sessions â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        private void PollSessions()
        {
            var sessions = HidsAnalyzer.GetSessions();
            Dispatcher.InvokeAsync(() =>
            {
                _sessionItems.Clear();
                foreach (var s in sessions)
                {
                    if (_baselinesSet && !_sessionBaseline.Contains(s.SessionName))
                    {
                        s.IsNew = true;
                        bool rdp = s.Type == "RDP";
                        s.Severity = rdp ? "High" : "Medium"; s.SeverityColor = rdp ? "#FF8C00" : "#FFA500";
                        AlertToast.Show("New Login Session!", $"{s.UserName} ({s.Type})", rdp ? "#FF8C00" : "#FFA500");
                        AddEvent(_eventItems, rdp ? "RDP SESSION OPENED" : "NEW SESSION", $"User:{s.UserName}  Session:{s.SessionName}", s.Severity);
                        _sessionBaseline.Add(s.SessionName);
                    }
                    _sessionItems.Add(s);
                }
            });
        }

        // â”€â”€ DNS cache â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        private void PollDnsCache()
        {
            var entries = HidsAnalyzer.GetDnsCache();
            Dispatcher.InvokeAsync(() =>
            {
                _dnsItems.Clear();
                foreach (var e in entries) _dnsItems.Add(e);
                int sus = entries.Count(e => e.IsSuspicious);
                if (DnsCountText != null) DnsCountText.Text = sus > 0 ? sus.ToString() : "0";
                foreach (var e in entries.Where(e => e.Severity == "High" && e.IsSuspicious))
                    AlertToast.Show("Suspicious DNS!", $"{e.Domain} â€” {e.Reason}", "#FF8C00");
            });
        }

        // â”€â”€ System health â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        private void UpdateSystemHealth()
        {
            Dispatcher.InvokeAsync(() =>
            {
                try
                {
                // Use volatile counters (thread-safe reads) to avoid accessing ObservableCollections from wrong thread
                bool critical = _procAlerts > 0 || _regChanges > 0;
                bool warn     = _secEvents > 5;
                string h = critical ? "Critical" : warn ? "Warning" : "Good";
                if (SystemHealthText != null)
                {
                    SystemHealthText.Text = h;
                    SystemHealthText.Foreground = new SolidColorBrush(h switch
                    {
                        "Critical" => Color.FromRgb(244, 71, 71),
                        "Warning"  => Color.FromRgb(255, 165, 0),
                        _          => Color.FromRgb(78, 201, 176)
                    });
                }
                } catch { }
            });
        }

        private void UpdateBadges()
        {
            if (EventCountText != null) EventCountText.Text = _eventItems.Count.ToString();
            if (FileCountText  != null) FileCountText.Text  = _fileItems.Count.ToString();
            if (ConnCountText  != null) ConnCountText.Text  = _connItems.Count.ToString();
        }

        private void UpdateStatusStrip()
        {
            // Update monitoring strip with live config values
        }

        // â”€â”€ Add helper â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        private static void AddEvent(ObservableCollection<HostEventItem> col, string title, string detail, string sev)
        {
            string color = sev switch { "Critical"=>"#F44747","High"=>"#FF8C00","Warning"=>"#FFA500","Medium"=>"#DCDCAA",_=>"#808080" };
            Application.Current?.Dispatcher.InvokeAsync(() =>
                col.Insert(0, new HostEventItem { Time = DateTime.Now.ToString("HH:mm:ss"), Title = title, Detail = detail, Severity = sev, SeverityColor = color }));
        }

        // â”€â”€ Double-click detail popups â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        private void ProcessList_DoubleClick(object sender, System.Windows.Input.MouseButtonEventArgs e)
        {
            if ((sender as DataGrid)?.SelectedItem is not ProcessDetail p) return;
            ShowDetailWindow("Process Detail", new[]
            {
                ("PID",             p.Pid.ToString()),
                ("Name",            p.Name),
                ("Path",            p.Path),
                ("Command Line",    p.CommandLine),
                ("Parent PID",      p.ParentPid.ToString()),
                ("Parent Name",     p.ParentName),
                ("RAM",             $"{p.RamBytes / 1048576} MB"),
                ("File Hash",       string.IsNullOrEmpty(p.FileHash) ? "not computed" : p.FileHash),
                ("Suspicious",      p.IsSuspicious ? "YES" : "No"),
                ("Reason",          p.SuspiciousReason),
                ("Severity",        p.Severity),
            }, p.SeverityColor);
        }

        private void EventLogList_DoubleClick(object sender, System.Windows.Input.MouseButtonEventArgs e)
        {
            if ((sender as DataGrid)?.SelectedItem is not HostEventItem item) return;
            ShowDetailWindow("Event Detail", new[]
            {
                ("Time",     item.Time),
                ("Severity", item.Severity),
                ("Event",    item.Title),
                ("Detail",   item.Detail),
            }, item.SeverityColor);
        }

        private void FileList_DoubleClick(object sender, System.Windows.Input.MouseButtonEventArgs e)
        {
            if ((sender as DataGrid)?.SelectedItem is not HostEventItem item) return;
            string path = item.Detail.Split('[')[0].Trim();
            string hash = File.Exists(path) ? HidsAnalyzer.HashFile(path) : "file deleted / inaccessible";
            ShowDetailWindow("File Change Detail", new[]
            {
                ("Time",     item.Time),
                ("Change",   item.Title),
                ("Path",     path),
                ("SHA256",   hash),
                ("Severity", item.Severity),
            }, item.SeverityColor);
        }

        private void ServiceList_DoubleClick(object sender, System.Windows.Input.MouseButtonEventArgs e)
        {
            if ((sender as DataGrid)?.SelectedItem is not ServiceDetail s) return;
            ShowDetailWindow("Service Detail", new[]
            {
                ("Name",        s.Name),
                ("Display Name",s.DisplayName),
                ("State",       s.State),
                ("Start Mode",  s.StartMode),
                ("Binary Path", s.PathName),
                ("Is New",      s.IsNew ? "YES â€” appeared after baseline!" : "No"),
                ("Severity",    s.Severity),
            }, s.SeverityColor);
        }

        private void DnsList_DoubleClick(object sender, System.Windows.Input.MouseButtonEventArgs e)
        {
            if ((sender as DataGrid)?.SelectedItem is not DnsEntry d) return;
            ShowDetailWindow("DNS Entry Detail", new[]
            {
                ("Domain",       d.Domain),
                ("Record Type",  d.RecordType),
                ("Data",         d.Data),
                ("Entropy",      $"{d.Entropy:F3} (>3.5 = suspicious)"),
                ("Suspicious",   d.IsSuspicious ? "YES" : "No"),
                ("Reason",       d.Reason),
                ("Severity",     d.Severity),
            }, d.SeverityColor);
        }

        private static void ShowDetailWindow(string title, IEnumerable<(string label, string value)> rows, string accentHex)
        {
            Color accent;
            try { accent = (Color)ColorConverter.ConvertFromString(accentHex); }
            catch { accent = Color.FromRgb(74, 194, 240); }

            var bgCol = (Application.Current.Resources["BackgroundBrush"] as SolidColorBrush)?.Color ?? Color.FromRgb(20, 20, 20);
            var secBgCol = (Application.Current.Resources["SecondaryBackgroundBrush"] as SolidColorBrush)?.Color ?? Color.FromRgb(28, 28, 28);
            var textCol = (Application.Current.Resources["TextBrush"] as SolidColorBrush)?.Color ?? Color.FromRgb(212, 212, 212);
            var borderCol = (Application.Current.Resources["BorderBrush"] as SolidColorBrush)?.Color ?? Color.FromRgb(45, 45, 45);
            var subtleCol = (Application.Current.Resources["SubtleTextBrush"] as SolidColorBrush)?.Color ?? Color.FromRgb(120, 120, 120);

            var win = new Window
            {
                Title = title, Width = 640, Height = 480, ResizeMode = ResizeMode.CanResize,
                WindowStartupLocation = WindowStartupLocation.CenterScreen,
                Background = new SolidColorBrush(bgCol)
            };

            var scroll = new ScrollViewer { VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Margin = new Thickness(16) };
            var sp = new StackPanel();

            // Accent header bar
            sp.Children.Add(new Border
            {
                Background = new SolidColorBrush(Color.FromArgb(40, accent.R, accent.G, accent.B)),
                BorderBrush = new SolidColorBrush(accent), BorderThickness = new Thickness(0, 0, 0, 1),
                Padding = new Thickness(10, 6, 10, 6), Margin = new Thickness(0, 0, 0, 12),
                Child = new TextBlock { Text = title, Foreground = new SolidColorBrush(accent), FontSize = 14, FontWeight = FontWeights.Bold, FontFamily = new FontFamily("Segoe UI") }
            });

            foreach (var (label, value) in rows)
            {
                if (string.IsNullOrEmpty(value)) continue;
                var row = new StackPanel { Margin = new Thickness(0, 0, 0, 10) };
                row.Children.Add(new TextBlock { Text = label.ToUpper(), Foreground = new SolidColorBrush(subtleCol), FontSize = 9, FontWeight = FontWeights.Bold, FontFamily = new FontFamily("Segoe UI") });
                var val = new TextBox
                {
                    Text = value, IsReadOnly = true, Background = new SolidColorBrush(secBgCol),
                    Foreground = new SolidColorBrush(textCol), BorderThickness = new Thickness(1),
                    BorderBrush = new SolidColorBrush(borderCol),
                    FontFamily = new FontFamily("Consolas"), FontSize = 11, Padding = new Thickness(8, 5, 8, 5),
                    TextWrapping = TextWrapping.Wrap
                };
                row.Children.Add(val);
                sp.Children.Add(row);
            }

            scroll.Content = sp;
            win.Content = scroll;
            win.Show();
        }

        // â”€â”€ Persistence â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        private void PersistEvents()
        {
            try
            {
                var all = _eventItems.Concat(_fileItems).Concat(_connItems).Concat(_regItems)
                    .OrderByDescending(x => x.Time).Take(1000).ToList();
                File.WriteAllText(_eventsPath, JsonSerializer.Serialize(all, new JsonSerializerOptions { WriteIndented = true }));
            }
            catch { }
        }

        private void LoadPersistedEvents()
        {
            try
            {
                if (!File.Exists(_eventsPath)) return;
                var items = JsonSerializer.Deserialize<List<HostEventItem>>(File.ReadAllText(_eventsPath));
                if (items == null) return;
                foreach (var item in items.Take(200)) _eventItems.Add(item);
                _secEvents = items.Count(i => i.Severity is "Critical" or "High");
                Dispatcher.InvokeAsync(() => { if (SecurityEventsText != null) SecurityEventsText.Text = _secEvents.ToString(); });
            }
            catch { }
        }

        // â”€â”€ Button handlers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        private void RefreshDashboard_Click(object sender, RoutedEventArgs e)
        { if (_isMonitoring) PollAll(); }

        private void ExportCsv_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var dlg = new Microsoft.Win32.SaveFileDialog
                { Title = "Export HIDS Events", Filter = "CSV (*.csv)|*.csv", FileName = $"HostIDS_{DateTime.Now:yyyyMMdd_HHmmss}.csv" };
                if (dlg.ShowDialog() != true) return;
                var sb = new StringBuilder();
                sb.AppendLine("Time,Severity,Event,Details");
                void Append(string sec, IEnumerable<HostEventItem> items)
                { foreach (var i in items) sb.AppendLine($"{i.Time},{i.Severity},{Q(sec + ": " + i.Title)},{Q(i.Detail)}"); }
                Append("SecurityEvent", _eventItems); Append("FileChange", _fileItems);
                Append("Connection",    _connItems);  Append("Registry",   _regItems);
                File.WriteAllText(dlg.FileName, sb.ToString(), Encoding.UTF8);
                AppDialog.Show($"Exported to:\n{dlg.FileName}", "Exported", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex) { AppDialog.Show($"Export failed: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error); }
        }

        private void ExportReport_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new Microsoft.Win32.SaveFileDialog
            { Title = "Export HIDS Report", Filter = "HTML (*.html)|*.html", FileName = $"HIDS_Report_{DateTime.Now:yyyyMMdd_HHmmss}.html" };
            if (dlg.ShowDialog() != true) return;
            try
            {
                string html = ReportGenerator.GenerateIDSReport(IDSManager.Engine.Alerts, IDSManager.Engine.Rules, IDSManager.Engine.GetStats(), isNids: false);
                File.WriteAllText(dlg.FileName, html, Encoding.UTF8);
                Process.Start(new ProcessStartInfo(dlg.FileName) { UseShellExecute = true });
            }
            catch (Exception ex) { AppDialog.Show($"Export failed: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error); }
        }

        // â”€â”€ Config import/export â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        private void ImportConfig_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new Microsoft.Win32.OpenFileDialog
            { Title = "Import PrivaCore Config", Filter = "JSON config (*.json)|*.json", DefaultExt = ".json" };
            if (dlg.ShowDialog() != true) return;
            try
            {
                string json = File.ReadAllText(dlg.FileName);

                // Raw rules array (from Export Rules) â€” not a full PrivaCoreConfig
                if (json.TrimStart().StartsWith("["))
                {
                    AppDialog.Show("This file is a raw rules array, not a PrivaCore config.\n\nUse the  Import Rules  button on the Network IDS dashboard to load it.",
                        "Wrong Format", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                var cfg = ConfigManager.Deserialize(json);
                if (cfg == null) { AppDialog.Show("Invalid config file.", "Error", MessageBoxButton.OK, MessageBoxImage.Error); return; }
                var (added, skipped, summary) = ConfigManager.Apply(cfg);
                _timer.Interval = TimeSpan.FromSeconds(S.PollIntervalSeconds);
                AppDialog.Show($"Config '{cfg.Name}' applied:\n\n{summary}", "Config Imported", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex) { AppDialog.Show($"Import failed:\n{ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error); }
        }

        private void ExportConfig_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new Microsoft.Win32.SaveFileDialog
            { Title = "Export PrivaCore Config", Filter = "JSON config (*.json)|*.json", FileName = $"PrivaCore_Config_{DateTime.Now:yyyyMMdd_HHmmss}.json" };
            if (dlg.ShowDialog() != true) return;
            try
            {
                File.WriteAllText(dlg.FileName, ConfigManager.Serialize(ConfigManager.Export()), Encoding.UTF8);
                AppDialog.Show($"Config exported to:\n{dlg.FileName}", "Exported", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex) { AppDialog.Show($"Export failed: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error); }
        }

        // â”€â”€ Theme-aware color helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        private static SolidColorBrush Br(string key) =>
            Application.Current.Resources[key] as SolidColorBrush
            ?? new SolidColorBrush(Colors.Gray);

        private static Color Col(string key) =>
            (Application.Current.Resources[key] as SolidColorBrush)?.Color
            ?? Colors.Gray;

        private void Settings_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new Window
            {
                Title = "Host IDS Settings", Width = 560, Height = 460, ResizeMode = ResizeMode.NoResize,
                WindowStartupLocation = WindowStartupLocation.CenterOwner, Owner = Window.GetWindow(this),
                Background = new SolidColorBrush(Col("BackgroundBrush"))
            };
            var sp = new StackPanel { Margin = new Thickness(16) };
            void AddLabel(string t) => sp.Children.Add(new TextBlock { Text = t, Foreground = Br("SubtleTextBrush"), FontSize = 9, FontWeight = FontWeights.Bold, FontFamily = new FontFamily("Segoe UI"), Margin = new Thickness(0,8,0,3) });
            TextBox MakeBox(string text, double h = 0)
            {
                var b = new TextBox { Text = text, Background = new SolidColorBrush(Col("SecondaryBackgroundBrush")), Foreground = new SolidColorBrush(Col("TextBrush")), BorderBrush = new SolidColorBrush(Col("BorderBrush")), BorderThickness = new Thickness(1), Padding = new Thickness(8,5,8,5), FontFamily = new FontFamily("Consolas"), FontSize = 11, AcceptsReturn = h > 0, TextWrapping = TextWrapping.Wrap };
                if (h > 0) { b.Height = h; b.VerticalScrollBarVisibility = ScrollBarVisibility.Auto; }
                return b;
            }
            AddLabel("POLL INTERVAL (SECONDS)");
            var pollBox = MakeBox(S.PollIntervalSeconds.ToString());
            sp.Children.Add(pollBox);
            AddLabel("CUSTOM WATCH PATHS (one per line)");
            var pathBox = MakeBox(string.Join(Environment.NewLine, S.CustomWatchPaths), 70);
            sp.Children.Add(pathBox);
            AddLabel("EXTRA PROCESS BLACKLIST (one per line, no .exe)");
            var procBox = MakeBox(string.Join(Environment.NewLine, S.AdditionalProcessBlacklist), 70);
            sp.Children.Add(procBox);
            AddLabel("EXTRA SUSPICIOUS PORTS (comma-separated)");
            var portBox = MakeBox(string.Join(",", S.AdditionalSuspiciousPorts));
            sp.Children.Add(portBox);

            var btnRow = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 12, 0, 0) };
            var btnOk     = new Button { Content = "Apply", Width = 80, Height = 28, Background = Br("AccentBrush"), Foreground = Brushes.White, BorderThickness = new Thickness(0), Margin = new Thickness(0,0,8,0) };
            var btnCancel = new Button { Content = "Cancel", Width = 80, Height = 28, Background = new SolidColorBrush(Col("SecondaryBackgroundBrush")), Foreground = new SolidColorBrush(Col("TextBrush")), BorderThickness = new Thickness(1), BorderBrush = new SolidColorBrush(Col("BorderBrush")) };
            btnOk.Click += (_, __) =>
            {
                if (int.TryParse(pollBox.Text, out int poll)) S.PollIntervalSeconds = Math.Max(1, poll);
                S.CustomWatchPaths           = pathBox.Text.Split(new[]{'\r','\n'}, StringSplitOptions.RemoveEmptyEntries).Select(p=>p.Trim()).Where(p=>!string.IsNullOrEmpty(p)).ToList();
                S.AdditionalProcessBlacklist = procBox.Text.Split(new[]{'\r','\n'}, StringSplitOptions.RemoveEmptyEntries).Select(p=>p.Trim()).Where(p=>!string.IsNullOrEmpty(p)).ToList();
                S.AdditionalSuspiciousPorts  = portBox.Text.Split(',').Select(p => int.TryParse(p.Trim(), out int port) ? port : -1).Where(p => p > 0).ToList();
                _timer.Interval = TimeSpan.FromSeconds(S.PollIntervalSeconds);
                ConfigManager.Save();
                dlg.Close();
            };
            btnCancel.Click += (_, __) => dlg.Close();
            btnRow.Children.Add(btnOk); btnRow.Children.Add(btnCancel);
            sp.Children.Add(btnRow);
            dlg.Content = new ScrollViewer { Content = sp };
            dlg.ShowDialog();
        }

        private void SwitchToNids_Click(object sender, RoutedEventArgs e)
        {
            _timer.Stop(); StopAllWatchers(); PersistEvents();
            (Application.Current.MainWindow as MainWindow)?.NavigateDirect(new NetworkIDSDashboardPage());
        }

        private static string Q(string? s) => $"\"{s?.Replace("\"","'")}\"";
    }

    internal static class TextBlockExtensions
    {
        public static T Let<T>(this T? obj, Action<T> action) where T : class { if (obj != null) action(obj); return obj!; }
    }

    public class HostEventItem
    {
        public string Time { get; set; } = "";
        public string Title { get; set; } = "";
        public string Detail { get; set; } = "";
        public string Severity { get; set; } = "";
        public string SeverityColor { get; set; } = "#808080";
    }
}

