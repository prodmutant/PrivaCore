using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using PROSCANNERCONT.Models;

namespace PROSCANNERCONT.Services.Siem
{
    /// <summary>Persists SOC cases (per user). Singleton-style in-memory list backed by disk.</summary>
    public static class SiemCaseStore
    {
        private static readonly string Path_ = System.IO.Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "PrivaCore", "siem_cases.json");

        private static List<SiemCase>? _cache;
        private static bool _testMode;

        public static List<SiemCase> All()
        {
            if (_cache != null) return _cache;
            try
            {
                if (File.Exists(Path_))
                    _cache = JsonSerializer.Deserialize<List<SiemCase>>(File.ReadAllText(Path_)) ?? new();
                else _cache = new();
            }
            catch { _cache = new(); }
            return _cache;
        }

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

        public static SiemCase Add(SiemCase c) { All().Insert(0, c); Save(); return c; }
        public static void Remove(SiemCase c) { All().Remove(c); Save(); }

        /// <summary>For tests: reset the in-memory cache.</summary>
        public static void ResetForTests() { _cache = new(); _testMode = true; }
    }
}
