using System;
using System.IO;
using System.Text.Json;
using PROSCANNERCONT.Models;

namespace PROSCANNERCONT.Services.Siem
{
    /// <summary>Persists the user-defined SIEM processing pipeline (per user).</summary>
    public static class SiemPipelineStore
    {
        private static readonly string Path_ = System.IO.Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "PrivaCore", "siem_pipeline.json");

        public static SiemPipeline Load()
        {
            try
            {
                if (File.Exists(Path_))
                {
                    var p = JsonSerializer.Deserialize<SiemPipeline>(File.ReadAllText(Path_));
                    if (p != null) return p;
                }
            }
            catch { }
            return SiemPipeline.Default();
        }

        public static void Save(SiemPipeline pipeline)
        {
            try
            {
                Directory.CreateDirectory(System.IO.Path.GetDirectoryName(Path_)!);
                File.WriteAllText(Path_, JsonSerializer.Serialize(pipeline, new JsonSerializerOptions { WriteIndented = true }));
            }
            catch { }
        }
    }
}
