using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using PROSCANNERCONT.Models;

namespace PROSCANNERCONT.Services.Siem
{
    /// <summary>Persists the SIEM dashboard widget layout (positions/sizes) per user.</summary>
    public static class SiemLayout
    {
        private static readonly string Path_ = System.IO.Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "PrivaCore", "siem_tiles.json");

        public static List<SiemWidget> Load()
        {
            try
            {
                if (File.Exists(Path_))
                {
                    var list = JsonSerializer.Deserialize<List<SiemWidget>>(File.ReadAllText(Path_));
                    if (list is { Count: > 0 }) return list;
                }
            }
            catch { }
            return SiemWidget.Default();
        }

        public static void Save(IEnumerable<SiemWidget> widgets)
        {
            try
            {
                Directory.CreateDirectory(System.IO.Path.GetDirectoryName(Path_)!);
                File.WriteAllText(Path_, JsonSerializer.Serialize(widgets, new JsonSerializerOptions { WriteIndented = true }));
            }
            catch { }
        }

        public static void Reset()
        {
            try { if (File.Exists(Path_)) File.Delete(Path_); } catch { }
        }
    }
}
