using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Text.Json;
using PROSCANNERCONT.Models;

namespace PROSCANNERCONT.Services.Siem
{
    /// <summary>
    /// Optional on-disk persistence for the SIEM index (so events survive a restart). Snapshots the
    /// most-recent events to a gzip NDJSON file periodically, on demand, and on process exit; loads
    /// them back on startup. Snapshot-based (not a WAL) — simple and good enough for this scale.
    /// Idempotent <see cref="Initialize"/> wires everything up once per process.
    /// </summary>
    public static class SiemPersistence
    {
        private static readonly string Path_ = System.IO.Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "PrivaCore", "siem_events.ndjson.gz");

        private static readonly object _gate = new();
        private static bool _initialised;
        private static bool _enabled;
        private static System.Timers.Timer? _timer;
        private const int MaxPersisted = 50_000;   // cap snapshot size

        public static bool Enabled => _enabled;

        /// <summary>Load any saved index and start periodic snapshots. Safe to call multiple times.</summary>
        public static void Initialize(bool enabled)
        {
            lock (_gate)
            {
                _enabled = enabled;
                if (_initialised)
                {
                    if (!enabled) StopTimer();
                    else StartTimer();
                    return;
                }
                _initialised = true;
                if (!enabled) return;

                LoadInto(SiemStoreProvider.Current);
                StartTimer();
                AppDomain.CurrentDomain.ProcessExit += (_, _) => SaveNow();
            }
        }

        /// <summary>Turn persistence on/off at runtime (from the index-management UI).</summary>
        public static void SetEnabled(bool enabled)
        {
            lock (_gate)
            {
                _enabled = enabled;
                if (enabled) { if (!_initialised) { Initialize(true); return; } StartTimer(); }
                else { StopTimer(); }
            }
        }

        private static void StartTimer()
        {
            if (_timer != null) return;
            _timer = new System.Timers.Timer(30_000) { AutoReset = true };
            _timer.Elapsed += (_, _) => SaveNow();
            _timer.Start();
        }

        private static void StopTimer() { _timer?.Stop(); _timer?.Dispose(); _timer = null; }

        public static void SaveNow()
        {
            if (!_enabled) return;
            try
            {
                Directory.CreateDirectory(System.IO.Path.GetDirectoryName(Path_)!);
                var snap = SiemStoreProvider.Current.Snapshot();   // newest first
                var tmp = Path_ + ".tmp";
                using (var fs = File.Create(tmp))
                using (var gz = new GZipStream(fs, CompressionLevel.Fastest))
                using (var sw = new StreamWriter(gz))
                {
                    int n = 0;
                    foreach (var e in snap)
                    {
                        sw.WriteLine(JsonSerializer.Serialize(e));
                        if (++n >= MaxPersisted) break;
                    }
                }
                File.Copy(tmp, Path_, overwrite: true);
                File.Delete(tmp);
            }
            catch { /* persistence is best-effort */ }
        }

        public static void Delete()
        {
            try { if (File.Exists(Path_)) File.Delete(Path_); } catch { }
        }

        /// <summary>Write a manual snapshot of the current index to an arbitrary gzip NDJSON file (B10). Returns events written.</summary>
        public static int SnapshotTo(string path)
        {
            var snap = SiemStoreProvider.Current.Snapshot();   // newest first
            int n = 0;
            using (var fs = File.Create(path))
            using (var gz = new GZipStream(fs, CompressionLevel.Optimal))
            using (var sw = new StreamWriter(gz))
                foreach (var e in snap) { sw.WriteLine(JsonSerializer.Serialize(e)); n++; }
            return n;
        }

        /// <summary>Restore events from a snapshot file into the index (B10). Returns events loaded.</summary>
        public static int RestoreFrom(string path)
        {
            var loaded = new List<SiemEvent>();
            using (var fs = File.OpenRead(path))
            using (var gz = new GZipStream(fs, CompressionMode.Decompress))
            using (var sr = new StreamReader(gz))
            {
                string? line;
                while ((line = sr.ReadLine()) != null)
                {
                    if (string.IsNullOrWhiteSpace(line)) continue;
                    try { var e = JsonSerializer.Deserialize<SiemEvent>(line); if (e != null) loaded.Add(e); } catch { }
                }
            }
            SiemStoreProvider.Current.LoadSnapshot(loaded);
            return loaded.Count;
        }

        public static long FileSize()
        {
            try { return File.Exists(Path_) ? new FileInfo(Path_).Length : 0; } catch { return 0; }
        }

        private static void LoadInto(ISiemStore store)
        {
            try
            {
                if (!File.Exists(Path_)) return;
                var loaded = new List<SiemEvent>();
                using (var fs = File.OpenRead(Path_))
                using (var gz = new GZipStream(fs, CompressionMode.Decompress))
                using (var sr = new StreamReader(gz))
                {
                    string? line;
                    while ((line = sr.ReadLine()) != null)
                    {
                        if (string.IsNullOrWhiteSpace(line)) continue;
                        try { var e = JsonSerializer.Deserialize<SiemEvent>(line); if (e != null) loaded.Add(e); } catch { }
                    }
                }
                store.LoadSnapshot(loaded);
            }
            catch { }
        }
    }
}
