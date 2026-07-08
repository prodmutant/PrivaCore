using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using PROSCANNERCONT.Models;

namespace PROSCANNERCONT.Services.Siem
{
    /// <summary>A set of named pipelines (C11): one "main" applied to ingestion, others reached via routing.</summary>
    public sealed class SiemPipelineSet
    {
        public List<SiemPipeline> Pipelines { get; set; } = new();

        public SiemPipeline Main()
        {
            var m = Pipelines.FirstOrDefault(p => string.Equals(p.Name, "main", StringComparison.OrdinalIgnoreCase));
            if (m == null) { m = Pipelines.FirstOrDefault() ?? new SiemPipeline { Name = "main" }; if (!Pipelines.Contains(m)) Pipelines.Add(m); }
            return m;
        }

        public SiemPipeline? ByName(string name)
            => Pipelines.FirstOrDefault(p => string.Equals(p.Name, name, StringComparison.OrdinalIgnoreCase));

        public IEnumerable<string> Names() => Pipelines.Select(p => p.Name);
    }

    /// <summary>
    /// Persists the named-pipeline set (C11). Migrates the legacy single-pipeline file into "main",
    /// and registers <see cref="SiemPipeline.NamedPipelineResolver"/> so CallPipeline routing resolves.
    /// </summary>
    public static class SiemPipelineSetStore
    {
        private static readonly string Path_ = System.IO.Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "PrivaCore", "siem_pipelines.json");

        private static SiemPipelineSet? _current;

        /// <summary>Load the set (migrating the legacy single pipeline if needed) and wire the router.</summary>
        public static SiemPipelineSet Load()
        {
            SiemPipelineSet set;
            try
            {
                if (File.Exists(Path_))
                {
                    var s = JsonSerializer.Deserialize<SiemPipelineSet>(File.ReadAllText(Path_));
                    set = s is { Pipelines.Count: > 0 } ? s : Migrate();
                }
                else set = Migrate();
            }
            catch { set = Migrate(); }

            // ensure a "main" exists and names are unique-ish
            var main = set.Main();
            if (string.IsNullOrWhiteSpace(main.Name)) main.Name = "main";

            _current = set;
            SiemPipeline.NamedPipelineResolver = name => _current?.ByName(name);
            // give processors a KQL → predicate compiler for SiemMatchField.Query conditional clauses
            SiemProcessor.QueryMatcherFactory ??= kql => { var q = SiemQuery.Parse(kql); return q.Matches; };
            return set;
        }

        private static SiemPipelineSet Migrate()
        {
            var legacy = SiemPipelineStore.Load();   // the old single pipeline (or a default)
            legacy.Name = "main";
            return new SiemPipelineSet { Pipelines = { legacy } };
        }

        public static void Save(SiemPipelineSet set)
        {
            _current = set;
            try
            {
                Directory.CreateDirectory(System.IO.Path.GetDirectoryName(Path_)!);
                File.WriteAllText(Path_, JsonSerializer.Serialize(set, new JsonSerializerOptions { WriteIndented = true }));
            }
            catch { }
            // keep the legacy file in sync with "main" for older code paths
            try { SiemPipelineStore.Save(set.Main()); } catch { }
        }
    }
}
