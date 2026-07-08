using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using PROSCANNERCONT.Models;

namespace PROSCANNERCONT.Services.Siem
{
    /// <summary>Persists the user's named saved searches (per user), like Kibana saved objects.</summary>
    public static class SiemSavedSearchStore
    {
        private static readonly string Path_ = System.IO.Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "PrivaCore", "siem_saved_searches.json");

        public static List<SiemSavedSearch> Load()
        {
            try
            {
                if (File.Exists(Path_))
                {
                    var list = JsonSerializer.Deserialize<List<SiemSavedSearch>>(File.ReadAllText(Path_));
                    if (list != null) return list;
                }
            }
            catch { }
            return new List<SiemSavedSearch>();
        }

        public static void SaveAll(IEnumerable<SiemSavedSearch> searches)
        {
            try
            {
                Directory.CreateDirectory(System.IO.Path.GetDirectoryName(Path_)!);
                File.WriteAllText(Path_, JsonSerializer.Serialize(searches, new JsonSerializerOptions { WriteIndented = true }));
            }
            catch { }
        }

        /// <summary>Add or replace a saved search by (case-insensitive) name, then persist. Returns the saved item.</summary>
        public static SiemSavedSearch Upsert(SiemSavedSearch s)
        {
            var list = Load();
            list.RemoveAll(x => string.Equals(x.Name, s.Name, StringComparison.OrdinalIgnoreCase));
            list.Insert(0, s);
            SaveAll(list);
            return s;
        }

        public static void Delete(string id)
        {
            var list = Load();
            list.RemoveAll(x => x.Id == id);
            SaveAll(list);
        }
    }
}
