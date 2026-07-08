using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using PROSCANNERCONT.Models;

namespace PROSCANNERCONT.Services
{
    public static class WidgetService
    {
        private static readonly string _path = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "PrivaCore", "dashboard_widgets.json");

        private static readonly JsonSerializerOptions _opts =
            new() { WriteIndented = true };

        public static List<DashboardWidget> Load()
        {
            try
            {
                if (!File.Exists(_path)) return DashboardWidget.Defaults();
                var saved = JsonSerializer.Deserialize<List<DashboardWidget>>(
                    File.ReadAllText(_path), _opts);
                if (saved == null || saved.Count == 0) return DashboardWidget.Defaults();

                // Merge: ensure every WidgetType has an entry (handles newly added widget types)
                foreach (WidgetType wt in Enum.GetValues<WidgetType>())
                {
                    if (!saved.Any(w => w.Type == wt))
                    {
                        var def = DashboardWidget.Defaults().FirstOrDefault(d => d.Type == wt);
                        if (def != null) { def.Order = saved.Count; saved.Add(def); }
                    }
                }

                return saved.OrderBy(w => w.Order).ToList();
            }
            catch
            {
                return DashboardWidget.Defaults();
            }
        }

        public static void Save(List<DashboardWidget> widgets)
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
                File.WriteAllText(_path, JsonSerializer.Serialize(widgets, _opts));
            }
            catch { }
        }
    }
}
