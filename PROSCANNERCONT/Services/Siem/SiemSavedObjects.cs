using System;
using System.Collections.Generic;
using System.Text.Json;
using PROSCANNERCONT.Models;

namespace PROSCANNERCONT.Services.Siem
{
    /// <summary>
    /// A portable bundle of SIEM "saved objects" (Kibana-style): detection rules, saved searches,
    /// dashboards, the pipeline and index settings.
    /// </summary>
    public sealed class SiemBundle
    {
        public int Version { get; set; } = 1;
        public DateTime Exported { get; set; } = DateTime.Now;
        public List<SiemRule>? Rules { get; set; }
        public List<SiemSavedSearch>? SavedSearches { get; set; }
        public SiemDashboardDoc? Dashboards { get; set; }
        public SiemPipeline? Pipeline { get; set; }
        public SiemIndexSettings? IndexSettings { get; set; }

        public int RuleCount => Rules?.Count ?? 0;
        public int SearchCount => SavedSearches?.Count ?? 0;
        public int DashboardCount => Dashboards?.Dashboards?.Count ?? 0;
    }

    /// <summary>Export / import of the SIEM configuration as one JSON bundle (backup &amp; sharing).</summary>
    public static class SiemSavedObjects
    {
        private static readonly JsonSerializerOptions Opts = new() { WriteIndented = true };

        public static SiemBundle BuildBundle() => new()
        {
            Rules = new List<SiemRule>(SiemRuleEngine.Instance.Rules),
            SavedSearches = SiemSavedSearchStore.Load(),
            Dashboards = SiemDashboardStore.Load(),
            Pipeline = SiemStoreProvider.Current.Pipeline,
            IndexSettings = SiemIndexSettings.Load(),
        };

        public static string Serialize(SiemBundle b) => JsonSerializer.Serialize(b, Opts);
        public static SiemBundle Deserialize(string json) => JsonSerializer.Deserialize<SiemBundle>(json) ?? new();

        public static string ExportJson() => Serialize(BuildBundle());

        /// <summary>Apply a bundle to the live stores (replace mode). Returns a human summary.</summary>
        public static string Apply(SiemBundle b)
        {
            int r = 0, s = 0, d = 0;
            if (b.Rules != null)
            {
                SiemRuleEngine.Instance.Rules.Clear();
                SiemRuleEngine.Instance.Rules.AddRange(b.Rules);
                SiemRuleEngine.Instance.Persist();
                r = b.Rules.Count;
            }
            if (b.SavedSearches != null) { SiemSavedSearchStore.SaveAll(b.SavedSearches); s = b.SavedSearches.Count; }
            if (b.Dashboards != null && b.Dashboards.Dashboards.Count > 0) { SiemDashboardStore.Save(b.Dashboards); d = b.Dashboards.Dashboards.Count; }
            if (b.Pipeline != null) { SiemStoreProvider.Current.Pipeline = b.Pipeline; SiemPipelineStore.Save(b.Pipeline); }
            if (b.IndexSettings != null)
            {
                b.IndexSettings.Save();
                SiemStoreProvider.Current.Capacity = b.IndexSettings.Capacity;
                SiemStoreProvider.Current.MaxAge = b.IndexSettings.MaxAgeMinutes > 0 ? TimeSpan.FromMinutes(b.IndexSettings.MaxAgeMinutes) : TimeSpan.Zero;
            }
            return $"Imported {r} rule(s), {s} saved search(es), {d} dashboard(s), pipeline & settings.";
        }

        public static string ImportJson(string json) => Apply(Deserialize(json));
    }
}
