using System;

namespace PROSCANNERCONT.Models
{
    /// <summary>
    /// One pinned item on the investigation Timeline (Elastic "Timeline"): a snapshot of an event or
    /// alert the analyst pinned, plus a free-text note. Entries are shown in chronological order.
    /// </summary>
    public sealed class SiemTimelineEntry
    {
        public string Id { get; set; } = Guid.NewGuid().ToString("N");
        public DateTime Time { get; set; } = DateTime.Now;     // the event's own timestamp
        public DateTime Pinned { get; set; } = DateTime.Now;
        public string Severity { get; set; } = "Info";
        public string Label { get; set; } = "";                // event type / rule name
        public string Summary { get; set; } = "";
        public string Note { get; set; } = "";

        public string TimeText => Time.ToString("MMM dd, HH:mm:ss.fff");
        public string SeverityColor => Severity.ToLowerInvariant() switch
        {
            "critical" => "#F85149",
            "high" => "#FF7B72",
            "medium" => "#E3B341",
            "low" => "#58A6FF",
            _ => "#8B949E",
        };
    }
}
