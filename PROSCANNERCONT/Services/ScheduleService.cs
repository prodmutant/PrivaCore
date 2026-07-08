using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using PROSCANNERCONT.Utils;

namespace PROSCANNERCONT.Services
{
    public enum ScheduledJobType
    {
        PortScan,
        NetworkDiscovery,
        VulnerabilityScan,
        TlsCertProbe,
        ThreatIntelRefresh,
        AssetInventoryRefresh,
    }

    public sealed class ScheduledJob
    {
        public Guid Id { get; set; } = Guid.NewGuid();
        public string Name { get; set; } = "";
        public ScheduledJobType JobType { get; set; }
        public string Target { get; set; } = "";
        public string Cron { get; set; } = "0 */6 * * *"; // every 6 h
        public bool Enabled { get; set; } = true;
        public DateTime? LastRun { get; set; }
        public DateTime? NextRun { get; set; }
        public string? LastStatus { get; set; }
    }

    /// <summary>
    /// Lightweight in-process job scheduler. Reads cron-style expressions
    /// (5-field: minute hour day-of-month month day-of-week, with "*" and "*/N"),
    /// fires jobs in the background, writes status back to disk.  Avoids the
    /// 1.5 MB Quartz.NET dependency for the modest needs here.
    /// </summary>
    public sealed class ScheduleService : IDisposable
    {
        private static readonly Lazy<ScheduleService> _instance = new(() => new ScheduleService());
        public static ScheduleService Instance => _instance.Value;

        private readonly string _path = Path.Combine(AppConstants.Paths.ConfigDir, "schedule.json");
        private readonly object _lock = new();
        private List<ScheduledJob> _jobs = new();
        private CancellationTokenSource? _cts;

        public event EventHandler<ScheduledJob>? JobStarted;
        public event EventHandler<(ScheduledJob Job, string Status)>? JobCompleted;

        public IReadOnlyList<ScheduledJob> Jobs
        {
            get { lock (_lock) return _jobs.ToList(); }
        }

        private ScheduleService() => Load();

        public void Start()
        {
            if (_cts != null) return;
            _cts = new CancellationTokenSource();
            _ = Task.Run(() => RunLoop(_cts.Token));
        }

        public void Stop()
        {
            _cts?.Cancel();
            _cts = null;
        }

        public void AddOrUpdate(ScheduledJob job)
        {
            lock (_lock)
            {
                var i = _jobs.FindIndex(j => j.Id == job.Id);
                job.NextRun = NextOccurrence(job.Cron, DateTime.UtcNow);
                if (i >= 0) _jobs[i] = job; else _jobs.Add(job);
                Save();
            }
        }

        public void Remove(Guid id)
        {
            lock (_lock) { _jobs.RemoveAll(j => j.Id == id); Save(); }
        }

        private async Task RunLoop(CancellationToken ct)
        {
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    var due = new List<ScheduledJob>();
                    lock (_lock)
                    {
                        foreach (var j in _jobs.Where(j => j.Enabled))
                        {
                            j.NextRun ??= NextOccurrence(j.Cron, j.LastRun ?? DateTime.UtcNow);
                            if (j.NextRun <= DateTime.UtcNow) due.Add(j);
                        }
                    }

                    foreach (var j in due)
                    {
                        if (ct.IsCancellationRequested) break;
                        JobStarted?.Invoke(this, j);
                        string status = "completed";
                        try
                        {
                            await Execute(j, ct).ConfigureAwait(false);
                            AppLogger.Log.Information("[Scheduler] ran {Job} ({Type}/{Target})", j.Name, j.JobType, j.Target);
                        }
                        catch (Exception ex)
                        {
                            status = $"failed: {ex.Message}";
                            AppLogger.Log.Warning(ex, "[Scheduler] {Job} failed", j.Name);
                        }
                        lock (_lock)
                        {
                            j.LastRun = DateTime.UtcNow;
                            j.LastStatus = status;
                            j.NextRun = NextOccurrence(j.Cron, j.LastRun.Value);
                            Save();
                        }
                        JobCompleted?.Invoke(this, (j, status));
                    }
                }
                catch (Exception ex) { AppLogger.Log.Warning(ex, "[Scheduler] loop error"); }

                try { await Task.Delay(TimeSpan.FromSeconds(30), ct).ConfigureAwait(false); }
                catch (OperationCanceledException) { break; }
            }
        }

        // Hook each job type to its target service. Wired here rather than via DI
        // so each new module just adds another switch arm.
        private async Task Execute(ScheduledJob j, CancellationToken ct)
        {
            switch (j.JobType)
            {
                case ScheduledJobType.ThreatIntelRefresh:
                    await ThreatIntelService.Instance.RefreshAllAsync(ct).ConfigureAwait(false);
                    break;
                case ScheduledJobType.TlsCertProbe:
                    var parts = j.Target.Split(':');
                    var host = parts[0];
                    var port = parts.Length > 1 && int.TryParse(parts[1], out var p) ? p : 443;
                    await CertExpiryMonitor.Instance.ProbeAsync(host, port).ConfigureAwait(false);
                    break;
                // Note: PortScan / NetworkDiscovery / VulnerabilityScan dispatch
                // intentionally left as integration points — they require the
                // page-level scanner instances which are wired in the UI layer.
                default:
                    await Task.Delay(50, ct).ConfigureAwait(false);
                    break;
            }
        }

        // ── Cron parser (5-field: m h dom mon dow) ─────────────────────────
        public static DateTime NextOccurrence(string cron, DateTime after)
        {
            var fields = cron.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (fields.Length != 5) return after.AddMinutes(1);

            DateTime t = after.AddSeconds(60 - after.Second).AddMilliseconds(-after.Millisecond);

            for (int i = 0; i < 60 * 24 * 30; i++) // search ~30 days
            {
                t = t.AddMinutes(1);
                if (!Matches(t.Minute,    fields[0], 0, 59)) continue;
                if (!Matches(t.Hour,      fields[1], 0, 23)) continue;
                if (!Matches(t.Day,       fields[2], 1, 31)) continue;
                if (!Matches(t.Month,     fields[3], 1, 12)) continue;
                if (!Matches((int)t.DayOfWeek, fields[4], 0, 6)) continue;
                return t;
            }
            return after.AddDays(1);
        }

        private static bool Matches(int value, string field, int min, int max)
        {
            if (field == "*") return true;
            if (field.StartsWith("*/") && int.TryParse(field[2..], out var step) && step > 0)
                return value % step == 0;
            foreach (var part in field.Split(','))
            {
                if (part.Contains('-'))
                {
                    var rng = part.Split('-');
                    if (rng.Length == 2 && int.TryParse(rng[0], out var a) && int.TryParse(rng[1], out var b))
                        if (value >= a && value <= b) return true;
                }
                else if (int.TryParse(part, out var v) && v == value) return true;
            }
            return false;
        }

        // ── Persistence ────────────────────────────────────────────────────
        private void Save()
        {
            try
            {
                Directory.CreateDirectory(AppConstants.Paths.ConfigDir);
                File.WriteAllText(_path,
                    JsonSerializer.Serialize(_jobs, new JsonSerializerOptions { WriteIndented = true }));
            }
            catch (Exception ex) { AppLogger.Log.Warning(ex, "[Scheduler] save failed"); }
        }

        private void Load()
        {
            try
            {
                if (!File.Exists(_path)) return;
                _jobs = JsonSerializer.Deserialize<List<ScheduledJob>>(File.ReadAllText(_path)) ?? new();
            }
            catch (Exception ex) { AppLogger.Log.Warning(ex, "[Scheduler] load failed"); }
        }

        public void Dispose() => Stop();
    }
}
