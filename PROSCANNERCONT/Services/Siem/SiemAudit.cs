using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;

namespace PROSCANNERCONT.Services.Siem
{
    /// <summary>One recorded analyst/admin action (the SIEM audit trail / "who did what").</summary>
    public sealed class SiemAuditEntry
    {
        public DateTime Time { get; set; } = DateTime.Now;
        public string User { get; set; } = "";
        public string Category { get; set; } = "";   // Rule / Alert / Index / Config / Dashboard / Search
        public string Action { get; set; } = "";     // short verb phrase
        public string Detail { get; set; } = "";     // the object acted on

        public string TimeText => Time.ToString("MMM dd, HH:mm:ss");
        public string CategoryColor => Category switch
        {
            "Rule"      => "#58A6FF",
            "Alert"     => "#FF7B72",
            "Index"     => "#E3B341",
            "Config"    => "#A371F7",
            "Dashboard" => "#56D364",
            "Search"    => "#39C5CF",
            _           => "#8B949E",
        };
    }

    /// <summary>
    /// The SIEM audit log (ELK "stack audit"): an append-only record of configuration and triage
    /// actions, kept in a bounded in-memory ring and mirrored to an NDJSON file under %APPDATA%.
    /// Singleton so the console, collector and every tab write to one trail.
    /// </summary>
    public sealed class SiemAudit
    {
        public static SiemAudit Instance { get; } = new();

        private static readonly string Path_ = System.IO.Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "PrivaCore", "siem_audit.ndjson");

        private readonly object _lock = new();
        private readonly LinkedList<SiemAuditEntry> _entries = new();   // newest first
        private bool _loaded;

        public int Capacity { get; set; } = 5000;
        public event Action? Changed;

        /// <summary>
        /// Supplies the acting user for each entry. Set by the auth layer (SessionService) to the
        /// logged-in console user; defaults to the OS user when auth is not wired (e.g. tests).
        /// </summary>
        public static Func<string>? CurrentUser;

        private static readonly JsonSerializerOptions Json = new() { WriteIndented = false };

        private SiemAudit() { }

        /// <summary>Record an action by the current user. Best-effort persistence; never throws into callers.</summary>
        public void Log(string category, string action, string detail = "")
        {
            EnsureLoaded();
            var who = Environment.UserName;
            try { who = CurrentUser?.Invoke() ?? who; } catch { }
            var e = new SiemAuditEntry { User = who, Category = category, Action = action, Detail = detail };
            lock (_lock)
            {
                _entries.AddFirst(e);
                while (_entries.Count > Capacity) _entries.RemoveLast();
            }
            try
            {
                Directory.CreateDirectory(System.IO.Path.GetDirectoryName(Path_)!);
                File.AppendAllText(Path_, JsonSerializer.Serialize(e, Json) + Environment.NewLine);
            }
            catch { }
            Changed?.Invoke();
        }

        public List<SiemAuditEntry> Recent(int n = 1000)
        {
            EnsureLoaded();
            lock (_lock) return _entries.Take(n).ToList();
        }

        public void Clear()
        {
            lock (_lock) _entries.Clear();
            try { if (File.Exists(Path_)) File.Delete(Path_); } catch { }
            Changed?.Invoke();
        }

        private void EnsureLoaded()
        {
            if (_loaded) return;
            lock (_lock)
            {
                if (_loaded) return;
                _loaded = true;
                try
                {
                    if (File.Exists(Path_))
                        foreach (var line in File.ReadLines(Path_).Reverse().Take(Capacity))
                        {
                            if (string.IsNullOrWhiteSpace(line)) continue;
                            try { var e = JsonSerializer.Deserialize<SiemAuditEntry>(line); if (e != null) _entries.AddLast(e); } catch { }
                        }
                }
                catch { }
            }
        }
    }
}
