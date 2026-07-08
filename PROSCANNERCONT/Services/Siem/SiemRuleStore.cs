using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using PROSCANNERCONT.Models;

namespace PROSCANNERCONT.Services.Siem
{
    /// <summary>Persists the user's detection rules (per user).</summary>
    public static class SiemRuleStore
    {
        private static readonly string Path_ = System.IO.Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "PrivaCore", "siem_rules.json");

        public static List<SiemRule> Load()
        {
            try
            {
                if (File.Exists(Path_))
                {
                    var list = JsonSerializer.Deserialize<List<SiemRule>>(File.ReadAllText(Path_));
                    if (list != null) return list;
                }
            }
            catch { }
            return new List<SiemRule>();
        }

        public static void Save(IEnumerable<SiemRule> rules)
        {
            try
            {
                Directory.CreateDirectory(System.IO.Path.GetDirectoryName(Path_)!);
                File.WriteAllText(Path_, JsonSerializer.Serialize(rules, new JsonSerializerOptions { WriteIndented = true }));
            }
            catch { }
        }
    }
}
