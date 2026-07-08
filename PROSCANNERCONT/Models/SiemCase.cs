using System;
using System.Collections.Generic;
using System.Linq;

namespace PROSCANNERCONT.Models
{
    public enum SiemCaseStatus { Open, InProgress, Closed }

    /// <summary>One piece of evidence attached to a case (a snapshot of an alert/event).</summary>
    public sealed class SiemCaseItem
    {
        public DateTime Time { get; set; } = DateTime.Now;
        public string Severity { get; set; } = "";
        public string RuleName { get; set; } = "";
        public string Summary { get; set; } = "";

        public string TimeText => Time.ToString("MMM dd, HH:mm:ss");
    }

    /// <summary>A free-text comment on a case.</summary>
    public sealed class SiemCaseComment
    {
        public DateTime Time { get; set; } = DateTime.Now;
        public string Author { get; set; } = "analyst";
        public string Text { get; set; } = "";

        public string TimeText => Time.ToString("MMM dd, HH:mm");
    }

    /// <summary>
    /// A SOC case (Elastic Security "Cases"): a tracked investigation that bundles attached
    /// alerts/events, comments, a status and a severity.
    /// </summary>
    public sealed class SiemCase
    {
        public string Id { get; set; } = Guid.NewGuid().ToString("N");
        public string Title { get; set; } = "";
        public string Description { get; set; } = "";
        public SiemCaseStatus Status { get; set; } = SiemCaseStatus.Open;
        public SiemSeverity Severity { get; set; } = SiemSeverity.Medium;
        public DateTime Created { get; set; } = DateTime.Now;
        public DateTime Updated { get; set; } = DateTime.Now;
        public List<SiemCaseItem> Items { get; set; } = new();
        public List<SiemCaseComment> Comments { get; set; } = new();

        public string StatusText => Status switch
        {
            SiemCaseStatus.Open => "Open",
            SiemCaseStatus.InProgress => "In progress",
            _ => "Closed",
        };

        public string StatusColor => Status switch
        {
            SiemCaseStatus.Open => "#F85149",
            SiemCaseStatus.InProgress => "#E3B341",
            _ => "#56D364",
        };

        public string SeverityText => Severity.ToString();
        public string SeverityColor => Severity switch
        {
            SiemSeverity.Critical => "#F85149",
            SiemSeverity.High => "#FF7B72",
            SiemSeverity.Medium => "#E3B341",
            SiemSeverity.Low => "#58A6FF",
            _ => "#8B949E",
        };

        public string SummaryLine => $"{Items.Count} item(s) · {Comments.Count} comment(s) · updated {Updated:MMM dd, HH:mm}";

        public void Touch() => Updated = DateTime.Now;
    }
}
