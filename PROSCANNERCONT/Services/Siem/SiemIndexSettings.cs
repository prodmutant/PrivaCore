using System;
using System.IO;
using System.Text.Json;

namespace PROSCANNERCONT.Services.Siem
{
    /// <summary>
    /// Index / retention settings (the Elastic "Index Lifecycle Management" knobs): how many events
    /// to keep, how long to keep them, and whether to persist the index to disk across restarts.
    /// </summary>
    public sealed class SiemIndexSettings
    {
        public int Capacity { get; set; } = 200_000;       // max events held in the index (ring buffer)
        public int MaxAgeMinutes { get; set; } = 0;        // 0 = no age-based purge
        public bool PersistToDisk { get; set; } = false;   // snapshot the index to disk + reload on start
        public string HttpIngestToken { get; set; } = "";   // optional shared secret for the HTTP ingest endpoint ("" = off)

        private static readonly string Path_ = System.IO.Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "PrivaCore", "siem_index.json");

        public static SiemIndexSettings Load()
        {
            try
            {
                if (File.Exists(Path_))
                {
                    var s = JsonSerializer.Deserialize<SiemIndexSettings>(File.ReadAllText(Path_));
                    if (s != null) return s;
                }
            }
            catch { }
            return new SiemIndexSettings();
        }

        public void Save()
        {
            try
            {
                Directory.CreateDirectory(System.IO.Path.GetDirectoryName(Path_)!);
                File.WriteAllText(Path_, JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true }));
            }
            catch { }
        }
    }
}
