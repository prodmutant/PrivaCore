using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using PROSCANNERCONT.Models;

namespace PROSCANNERCONT.Services.Siem
{
    /// <summary>One named dashboard = a set of tiles (Kibana saved dashboard).</summary>
    public sealed class SiemDashboard
    {
        public string Name { get; set; } = "Default";
        public List<SiemWidget> Tiles { get; set; } = new();
    }

    /// <summary>The collection of saved dashboards plus which one is current.</summary>
    public sealed class SiemDashboardDoc
    {
        public List<SiemDashboard> Dashboards { get; set; } = new();
        public string Current { get; set; } = "Default";

        public SiemDashboard CurrentDashboard()
            => Dashboards.FirstOrDefault(d => string.Equals(d.Name, Current, StringComparison.OrdinalIgnoreCase))
               ?? Dashboards.First();
    }

    /// <summary>Persists all SIEM dashboards (per user). Migrates the legacy single tile layout.</summary>
    public static class SiemDashboardStore
    {
        private static readonly string Path_ = System.IO.Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "PrivaCore", "siem_dashboards.json");

        public static SiemDashboardDoc Load()
        {
            try
            {
                if (File.Exists(Path_))
                {
                    var doc = JsonSerializer.Deserialize<SiemDashboardDoc>(File.ReadAllText(Path_));
                    if (doc is { Dashboards.Count: > 0 }) return doc;
                }
            }
            catch { }

            // migrate the legacy single layout into a "Default" dashboard
            var migrated = new SiemDashboardDoc { Current = "Default" };
            migrated.Dashboards.Add(new SiemDashboard { Name = "Default", Tiles = SiemLayout.Load() });
            return migrated;
        }

        public static void Save(SiemDashboardDoc doc)
        {
            try
            {
                Directory.CreateDirectory(System.IO.Path.GetDirectoryName(Path_)!);
                File.WriteAllText(Path_, JsonSerializer.Serialize(doc, new JsonSerializerOptions { WriteIndented = true }));
            }
            catch { }
        }
    }
}
