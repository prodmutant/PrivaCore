using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace PROSCANNERCONT.Models
{
    /// <summary>What a pipeline processor does to a matching event.</summary>
    public enum SiemProcessorType
    {
        Drop,          // discard matching events (noise reduction)
        KeepOnly,      // discard everything that does NOT match
        SetSeverity,   // override severity on matching events
        SetCategory,   // re-label the category on matching events
        AddTag,        // add/overwrite a field (key=value) on matching events
        RenameSource,  // replace the source on matching events
        ExtractRegex,  // run a regex with NAMED groups over a field → new fields
        Grok,          // grok: %{PATTERN:field} expression over a field → new fields (Logstash-style)
        RenameField,   // rename a field in the open bag (Field → Arg)
        RemoveField,   // drop a field from the open bag
        Lowercase,     // lowercase a field's value (normalisation)
        Dedupe,        // drop repeats of the same fingerprint within a window (Arg = seconds)
        IndicatorMatch,// threat-intel: tag + escalate events whose field matches a known-bad list (Arg)
        ParseTimestamp,// set the event time from a field (Field; Arg = optional .NET date format)
        GeoEnrich,     // GeoIP: add {prefix}.geo.* from an IP field (Field, default source.ip)
        Enrich,        // lookup-table enrich (asset/user/DNS): match Field against a key→fields table (Arg)
        CallPipeline,  // routing: on match, run a named pipeline (Arg) inline; may drop the event
    }

    /// <summary>Which field a processor's match clause tests. <see cref="Query"/> evaluates the value as a full KQL expression.</summary>
    public enum SiemMatchField { Any, Source, Host, Category, EventType, Message, Severity, Query }

    /// <summary>
    /// One stage in the SIEM processing pipeline (Logstash-style). Each processor has a
    /// match clause (field + value) and an action. Stages run top-to-bottom; a Drop/KeepOnly
    /// can remove the event from the stream entirely.
    /// </summary>
    public sealed class SiemProcessor
    {
        public string Id { get; set; } = Guid.NewGuid().ToString("N");
        public bool Enabled { get; set; } = true;
        public SiemProcessorType Type { get; set; } = SiemProcessorType.Drop;
        public SiemMatchField MatchField { get; set; } = SiemMatchField.Any;
        public string MatchValue { get; set; } = "";
        public string Arg { get; set; } = "";   // SetSeverity: severity name · SetCategory/RenameSource: value · AddTag: key=value · ExtractRegex: pattern · RenameField: new name · Dedupe: window seconds
        public string Field { get; set; } = ""; // ExtractRegex: source field to parse (default message) · Rename/Remove/Lowercase: target field · Dedupe: fingerprint field (default message)

        // Dedupe state — fingerprint → last-seen; never serialised (private field).
        private readonly Dictionary<string, DateTime> _seen = new();

        /// <summary>
        /// Compiles a KQL string into a predicate. Assigned by the SIEM side (so this model stays free
        /// of a compile-time dependency on the query engine for non-SIEM hosts like the IDS app, which
        /// link the Models folder but not the SIEM services). Null ⇒ no query engine present.
        /// </summary>
        public static Func<string, Func<SiemEvent, bool>>? QueryMatcherFactory;

        // Cached compiled predicate for SiemMatchField.Query — recompiled only when the value changes.
        private Func<SiemEvent, bool>? _matchPred;
        private string _matchQueryRaw = "";

        public bool Matches(SiemEvent e)
        {
            if (string.IsNullOrEmpty(MatchValue)) return true;   // empty clause = matches all
            if (MatchField == SiemMatchField.Query)
            {
                var factory = QueryMatcherFactory;
                if (factory == null) return true;   // no query engine on this host → treat as match-all
                if (_matchPred == null || _matchQueryRaw != MatchValue)
                { _matchQueryRaw = MatchValue; _matchPred = factory(MatchValue); }
                return _matchPred(e);
            }
            var v = MatchValue;
            bool Has(string? s) => !string.IsNullOrEmpty(s) && s.Contains(v, StringComparison.OrdinalIgnoreCase);
            return MatchField switch
            {
                SiemMatchField.Source => Has(e.Source),
                SiemMatchField.Host => Has(e.Host),
                SiemMatchField.Category => Has(e.Category),
                SiemMatchField.EventType => Has(e.EventType),
                SiemMatchField.Message => Has(e.Message),
                SiemMatchField.Severity => string.Equals(e.Severity.ToString(), v, StringComparison.OrdinalIgnoreCase),
                _ => Has(e.Source) || Has(e.Host) || Has(e.Category) || Has(e.EventType) || Has(e.Message),
            };
        }

        public string Summary()
        {
            string clause = string.IsNullOrEmpty(MatchValue) ? "every event"
                : MatchField == SiemMatchField.Query ? $"query [{MatchValue}]"
                : $"{MatchField.ToString().ToLowerInvariant()} ~ \"{MatchValue}\"";
            return Type switch
            {
                SiemProcessorType.Drop => $"Drop where {clause}",
                SiemProcessorType.KeepOnly => $"Keep only where {clause}",
                SiemProcessorType.SetSeverity => $"Set severity = {Arg} where {clause}",
                SiemProcessorType.SetCategory => $"Set category = {Arg} where {clause}",
                SiemProcessorType.AddTag => $"Add field {Arg} where {clause}",
                SiemProcessorType.RenameSource => $"Rename source → {Arg} where {clause}",
                SiemProcessorType.ExtractRegex => $"Extract /{Arg}/ from {(string.IsNullOrEmpty(Field) ? "message" : Field)} where {clause}",
                SiemProcessorType.Grok => $"Grok “{Arg}” from {(string.IsNullOrEmpty(Field) ? "message" : Field)} where {clause}",
                SiemProcessorType.RenameField => $"Rename field {Field} → {Arg} where {clause}",
                SiemProcessorType.RemoveField => $"Remove field {Field} where {clause}",
                SiemProcessorType.Lowercase => $"Lowercase {(string.IsNullOrEmpty(Field) ? "message" : Field)} where {clause}",
                SiemProcessorType.Dedupe => $"Dedupe by {(string.IsNullOrEmpty(Field) ? "message" : Field)} within {DedupeSeconds}s where {clause}",
                SiemProcessorType.IndicatorMatch => $"Threat-intel match {(string.IsNullOrEmpty(Field) ? "source.ip/dest.ip/user.name" : Field)} against {IndicatorSet.Count} indicator(s) where {clause}",
                SiemProcessorType.ParseTimestamp => $"Parse @timestamp from {(string.IsNullOrEmpty(Field) ? "message" : Field)} where {clause}",
                SiemProcessorType.GeoEnrich => $"GeoIP enrich {(string.IsNullOrEmpty(Field) ? "source.ip" : Field)} where {clause}",
                SiemProcessorType.Enrich => $"Enrich on {(string.IsNullOrEmpty(Field) ? "host.name" : Field)} from {EnrichTable.Count} lookup entr(y/ies) where {clause}",
                SiemProcessorType.CallPipeline => $"Route to pipeline “{(string.IsNullOrWhiteSpace(Arg) ? "?" : Arg)}” where {clause}",
                _ => clause,
            };
        }

        /// <summary>Add ECS geo fields from an IP field, using the cached GeoIP result (warms cache on miss).</summary>
        public void ApplyGeoEnrich(SiemEvent e)
        {
            var field = string.IsNullOrWhiteSpace(Field) ? "source.ip" : Field;
            var ip = e.Get(field);
            if (string.IsNullOrEmpty(ip)) return;
            string prefix = field.EndsWith(".ip", StringComparison.OrdinalIgnoreCase) ? field[..^3] : "source";
            if (PROSCANNERCONT.Services.GeoIpService.TryGetCached(ip, out var geo) && geo != null)
            {
                if (geo.Success)
                {
                    if (!string.IsNullOrEmpty(geo.Country)) e.Fields[$"{prefix}.geo.country_name"] = geo.Country;
                    if (!string.IsNullOrEmpty(geo.CountryCode)) e.Fields[$"{prefix}.geo.country_iso_code"] = geo.CountryCode;
                    if (!string.IsNullOrEmpty(geo.ASN)) e.Fields[$"{prefix}.as.organization"] = geo.ASN;
                    if (!string.IsNullOrEmpty(geo.ISP)) e.Fields[$"{prefix}.as.isp"] = geo.ISP;
                }
            }
            else PROSCANNERCONT.Services.GeoIpService.Prefetch(ip);   // warm cache; later events enrich
        }

        /// <summary>Set the event timestamp from a field's value (optionally with a .NET format in Arg).</summary>
        public void ApplyParseTimestamp(SiemEvent e)
        {
            var src = string.IsNullOrWhiteSpace(Field) ? e.Message : (e.Get(Field) ?? "");
            if (string.IsNullOrEmpty(src)) return;
            var ci = System.Globalization.CultureInfo.InvariantCulture;
            bool ok = string.IsNullOrWhiteSpace(Arg)
                ? DateTime.TryParse(src, ci, System.Globalization.DateTimeStyles.AssumeLocal, out var ts)
                : DateTime.TryParseExact(src, Arg, ci, System.Globalization.DateTimeStyles.AssumeLocal, out ts);
            if (ok) e.Timestamp = ts;
        }

        private HashSet<string>? _indicators;
        private string _indicatorsRaw = "";
        /// <summary>Parsed indicator set from <see cref="Arg"/> (comma/space/newline separated), cached.</summary>
        public HashSet<string> IndicatorSet
        {
            get
            {
                if (_indicators == null || _indicatorsRaw != Arg)
                {
                    _indicatorsRaw = Arg;
                    _indicators = new HashSet<string>(
                        (Arg ?? "").Split(new[] { ',', ';', ' ', '\t', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries),
                        StringComparer.OrdinalIgnoreCase);
                }
                return _indicators;
            }
        }

        /// <summary>
        /// Optional central threat-intel feed (managed on the Threat Intel tab). A service assigns this
        /// so <see cref="ApplyIndicatorMatch"/> matches against the shared indicator list as well as the
        /// processor's inline <see cref="Arg"/> — keeps the model free of a Services dependency.
        /// </summary>
        public static Func<IReadOnlyCollection<string>>? GlobalIndicatorSource;

        /// <summary>Tag (and escalate) an event if a watched field matches a known-bad indicator.</summary>
        public void ApplyIndicatorMatch(SiemEvent e)
        {
            var global = GlobalIndicatorSource?.Invoke();
            if (IndicatorSet.Count == 0 && (global == null || global.Count == 0)) return;
            var fields = string.IsNullOrWhiteSpace(Field)
                ? new[] { "source.ip", "destination.ip", "user.name", "file.hash.sha256", "url.domain", "dns.question.name" }
                : new[] { Field };
            foreach (var f in fields)
            {
                var v = e.Get(f);
                if (string.IsNullOrEmpty(v)) continue;
                if (IndicatorSet.Contains(v) || (global != null && global.Contains(v)))
                {
                    e.Fields["threat.matched"] = "true";
                    e.Fields["threat.indicator"] = v;
                    e.Fields["threat.indicator.field"] = f;
                    if ((int)e.Severity < (int)SiemSeverity.High) e.Severity = SiemSeverity.High;
                    return;
                }
            }
        }

        private Dictionary<string, List<KeyValuePair<string, string>>>? _enrich;
        private string _enrichRaw = "";
        /// <summary>
        /// Parsed enrich lookup table from <see cref="Arg"/>: one entry per line as
        /// <c>keyValue =&gt; field1=val1; field2=val2</c>. Cached until Arg changes.
        /// </summary>
        public Dictionary<string, List<KeyValuePair<string, string>>> EnrichTable
        {
            get
            {
                if (_enrich == null || _enrichRaw != Arg)
                {
                    _enrichRaw = Arg;
                    _enrich = new(StringComparer.OrdinalIgnoreCase);
                    foreach (var line in (Arg ?? "").Split('\n'))
                    {
                        var l = line.Trim();
                        int arrow = l.IndexOf("=>", StringComparison.Ordinal);
                        if (arrow <= 0) continue;
                        var key = l[..arrow].Trim();
                        if (key.Length == 0) continue;
                        var fields = new List<KeyValuePair<string, string>>();
                        foreach (var pair in l[(arrow + 2)..].Split(new[] { ';', ',' }, StringSplitOptions.RemoveEmptyEntries))
                        {
                            int eq = pair.IndexOf('=');
                            if (eq <= 0) continue;
                            fields.Add(new(pair[..eq].Trim(), pair[(eq + 1)..].Trim()));
                        }
                        if (fields.Count > 0) _enrich[key] = fields;
                    }
                }
                return _enrich;
            }
        }

        /// <summary>Add lookup-table fields to an event whose key field matches a table entry (asset/user/DNS enrich).</summary>
        public void ApplyEnrich(SiemEvent e)
        {
            if (EnrichTable.Count == 0) return;
            var keyField = string.IsNullOrWhiteSpace(Field) ? "host.name" : Field;
            var v = e.Get(keyField);
            if (string.IsNullOrEmpty(v) || !EnrichTable.TryGetValue(v, out var fields)) return;
            foreach (var kv in fields) e.Fields[kv.Key] = kv.Value;
        }

        public int DedupeSeconds => int.TryParse(Arg, out var s) && s > 0 ? s : 60;

        /// <summary>True if this fingerprint was seen within the dedupe window (and records it).</summary>
        public bool IsDuplicate(SiemEvent e)
        {
            var key = string.IsNullOrWhiteSpace(Field) ? e.Message : (e.Get(Field) ?? "");
            var now = DateTime.Now;
            var window = TimeSpan.FromSeconds(DedupeSeconds);
            if (_seen.TryGetValue(key, out var last) && (now - last) < window) { _seen[key] = now; return true; }
            _seen[key] = now;
            if (_seen.Count > 20_000)   // bound the memory; drop the oldest half
                foreach (var k in new List<string>(_seen.Keys))
                    if ((now - _seen[k]) > window) _seen.Remove(k);
            return false;
        }

        private SiemGrok.CompiledGrok? _grok;
        private string _grokRaw = "";
        /// <summary>Grok-parse a source field (Field, default message) using the <see cref="Arg"/> expression; lifts captures into fields.</summary>
        public void ApplyGrok(SiemEvent e)
        {
            if (string.IsNullOrWhiteSpace(Arg)) return;
            if (_grok == null || _grokRaw != Arg) { _grokRaw = Arg; _grok = SiemGrok.Compile(Arg); }
            var src = string.IsNullOrWhiteSpace(Field) ? e.Message : (e.Get(Field) ?? "");
            if (string.IsNullOrEmpty(src)) return;
            _grok.TryExtract(src, e.Fields);
        }

        public void ApplyLowercase(SiemEvent e)
        {
            if (string.IsNullOrWhiteSpace(Field) || Field == "message") { e.Message = e.Message.ToLowerInvariant(); return; }
            if (e.Fields.TryGetValue(Field, out var v)) e.Fields[Field] = v.ToLowerInvariant();
        }
    }

    /// <summary>
    /// The SIEM ingestion pipeline: an ordered set of processors applied to every event
    /// as it enters the store. Returns the (possibly transformed) event, or null to drop it.
    /// Configurable by the user — the heart of the "compose your own data flow" idea.
    /// </summary>
    public sealed class SiemPipeline
    {
        public string Name { get; set; } = "main";
        public bool Enabled { get; set; } = true;
        public List<SiemProcessor> Processors { get; set; } = new();

        /// <summary>
        /// Resolves a named pipeline for the <see cref="SiemProcessorType.CallPipeline"/> routing
        /// processor (assigned by the pipeline-set service so the model stays Services-free).
        /// </summary>
        public static Func<string, SiemPipeline?>? NamedPipelineResolver;

        /// <summary>Run the event through the pipeline. Returns null if dropped.</summary>
        public SiemEvent? Process(SiemEvent e) => Process(e, 0);

        private SiemEvent? Process(SiemEvent e, int depth)
        {
            if (!Enabled) return e;
            if (depth > 8) return e;   // routing recursion guard
            foreach (var p in Processors)
            {
                if (!p.Enabled) continue;
                bool m = p.Matches(e);
                switch (p.Type)
                {
                    case SiemProcessorType.Drop:
                        if (m) return null; break;
                    case SiemProcessorType.KeepOnly:
                        if (!m) return null; break;
                    case SiemProcessorType.SetSeverity:
                        if (m && Enum.TryParse<SiemSeverity>(p.Arg, true, out var s)) e.Severity = s; break;
                    case SiemProcessorType.SetCategory:
                        if (m && !string.IsNullOrWhiteSpace(p.Arg)) e.Category = p.Arg; break;
                    case SiemProcessorType.RenameSource:
                        if (m && !string.IsNullOrWhiteSpace(p.Arg)) e.Source = p.Arg; break;
                    case SiemProcessorType.AddTag:
                        if (m && p.Arg.Contains('='))
                        {
                            int i = p.Arg.IndexOf('=');
                            e.Fields[p.Arg[..i].Trim()] = p.Arg[(i + 1)..].Trim();
                        }
                        break;
                    case SiemProcessorType.ExtractRegex:
                        if (m) ExtractRegex(e, p);
                        break;
                    case SiemProcessorType.Grok:
                        if (m) p.ApplyGrok(e);
                        break;
                    case SiemProcessorType.RenameField:
                        if (m && !string.IsNullOrWhiteSpace(p.Field) && !string.IsNullOrWhiteSpace(p.Arg)
                            && e.Fields.TryGetValue(p.Field, out var rv))
                        { e.Fields.Remove(p.Field); e.Fields[p.Arg] = rv; }
                        break;
                    case SiemProcessorType.RemoveField:
                        if (m && !string.IsNullOrWhiteSpace(p.Field)) e.Fields.Remove(p.Field);
                        break;
                    case SiemProcessorType.Lowercase:
                        if (m) p.ApplyLowercase(e);
                        break;
                    case SiemProcessorType.Dedupe:
                        if (m && p.IsDuplicate(e)) return null;
                        break;
                    case SiemProcessorType.IndicatorMatch:
                        if (m) p.ApplyIndicatorMatch(e);
                        break;
                    case SiemProcessorType.ParseTimestamp:
                        if (m) p.ApplyParseTimestamp(e);
                        break;
                    case SiemProcessorType.GeoEnrich:
                        if (m) p.ApplyGeoEnrich(e);
                        break;
                    case SiemProcessorType.Enrich:
                        if (m) p.ApplyEnrich(e);
                        break;
                    case SiemProcessorType.CallPipeline:
                        if (m && !string.IsNullOrWhiteSpace(p.Arg))
                        {
                            var target = NamedPipelineResolver?.Invoke(p.Arg);
                            if (target != null && !ReferenceEquals(target, this))
                            {
                                var routed = target.Process(e, depth + 1);
                                if (routed == null) return null;   // routed pipeline dropped it
                                e = routed;
                            }
                        }
                        break;
                }
            }
            return e;
        }

        /// <summary>Grok-style extraction: run a named-group regex over a source field, lifting groups into fields.</summary>
        private static void ExtractRegex(SiemEvent e, SiemProcessor p)
        {
            if (string.IsNullOrWhiteSpace(p.Arg)) return;
            var src = string.IsNullOrWhiteSpace(p.Field) ? e.Message : (e.Get(p.Field) ?? "");
            if (string.IsNullOrEmpty(src)) return;
            try
            {
                var rx = new Regex(p.Arg, RegexOptions.CultureInvariant);
                var m = rx.Match(src);
                if (!m.Success) return;
                foreach (var name in rx.GetGroupNames())
                {
                    if (int.TryParse(name, out _)) continue;   // skip unnamed/numbered groups
                    var g = m.Groups[name];
                    if (g.Success) e.Fields[name] = g.Value;
                }
            }
            catch { /* a bad pattern must not break ingestion */ }
        }

        public static SiemPipeline Default() => new();
    }
}
