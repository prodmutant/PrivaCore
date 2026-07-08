using System;
using System.IO;
using System.Text.Json;

namespace PROSCANNERCONT.Services.Siem
{
    /// <summary>Remembers whether the SIEM welcome/how-to overlay should be shown on startup.</summary>
    public static class SiemWelcome
    {
        private sealed class Prefs { public bool DontShow { get; set; } }

        private static readonly string Path_ = System.IO.Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "PrivaCore", "siem_welcome.json");

        public static bool ShouldShow()
        {
            try
            {
                if (File.Exists(Path_))
                {
                    var p = JsonSerializer.Deserialize<Prefs>(File.ReadAllText(Path_));
                    return p == null || !p.DontShow;
                }
            }
            catch { }
            return true;   // show by default
        }

        public static void SetDontShow(bool dontShow)
        {
            try
            {
                Directory.CreateDirectory(System.IO.Path.GetDirectoryName(Path_)!);
                File.WriteAllText(Path_, JsonSerializer.Serialize(new Prefs { DontShow = dontShow }));
            }
            catch { }
        }
    }
}
