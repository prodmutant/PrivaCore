using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using PROSCANNERCONT.Models;

namespace PROSCANNERCONT.Services.Siem
{
    /// <summary>Persists the investigation Timeline (a single pinned-events board) per user.</summary>
    public static class SiemTimelineStore
    {
        private static readonly string Path_ = System.IO.Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "PrivaCore", "siem_timeline.json");

        private static List<SiemTimelineEntry>? _cache;
        private static bool _testMode;

        public static List<SiemTimelineEntry> All()
        {
            if (_cache != null) return _cache;
            try { _cache = File.Exists(Path_) ? JsonSerializer.Deserialize<List<SiemTimelineEntry>>(File.ReadAllText(Path_)) ?? new() : new(); }
            catch { _cache = new(); }
            return _cache;
        }

        /// <summary>Entries in chronological order (oldest → newest), the natural timeline view.</summary>
        public static List<SiemTimelineEntry> Chronological() => All().OrderBy(e => e.Time).ToList();

        public static void Save()
        {
            if (_testMode) return;
            try
            {
                Directory.CreateDirectory(System.IO.Path.GetDirectoryName(Path_)!);
                File.WriteAllText(Path_, JsonSerializer.Serialize(_cache ?? new(), new JsonSerializerOptions { WriteIndented = true }));
            }
            catch { }
        }

        public static void Add(SiemTimelineEntry e) { All().Add(e); Save(); }
        public static void Remove(SiemTimelineEntry e) { All().Remove(e); Save(); }
        public static void Clear() { All().Clear(); Save(); }

        public static void ResetForTests() { _cache = new(); _testMode = true; }
    }
}
