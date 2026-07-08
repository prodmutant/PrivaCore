using System;
using System.Collections.Generic;

namespace PROSCANNERCONT.Models
{
    /// <summary>
    /// A named, persisted Discover state — the SIEM equivalent of a Kibana "saved search".
    /// Captures the query string, the chosen document columns, and the time range so the whole
    /// Discover view can be restored later.
    /// </summary>
    public sealed class SiemSavedSearch
    {
        public string Id { get; set; } = Guid.NewGuid().ToString("N");
        public string Name { get; set; } = "";
        public string Query { get; set; } = "";
        public List<string> Columns { get; set; } = new();
        public int RangeMinutes { get; set; } = 15;   // 0 = All time
        public DateTime Created { get; set; } = DateTime.Now;

        public string RangeText => RangeMinutes switch
        {
            0 => "All time",
            >= 1440 => $"{RangeMinutes / 1440}d",
            >= 60 => $"{RangeMinutes / 60}h",
            _ => $"{RangeMinutes}m",
        };
    }
}
