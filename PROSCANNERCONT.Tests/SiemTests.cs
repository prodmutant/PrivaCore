using System;
using System.Linq;
using FluentAssertions;
using PROSCANNERCONT.Models;
using PROSCANNERCONT.Services.Siem;
using Xunit;

namespace PROSCANNERCONT.Tests;

/// <summary>SIEM engine: the processing pipeline and the multi-machine roll-up.</summary>
[Collection("Siem singleton")]
public class SiemTests : IDisposable
{
    private readonly SiemStore _store = SiemStore.Instance;

    public SiemTests() { _store.Clear(); _store.Pipeline = new SiemPipeline(); }
    public void Dispose() { _store.Clear(); _store.Pipeline = new SiemPipeline(); }

    private static SiemEvent Ev(SiemSeverity sev, string cat, string host = "boxA")
        => new() { Severity = sev, Category = cat, Host = host, Source = host, EventType = cat, Message = $"{cat} on {host}" };

    [Fact]
    public void Pipeline_drops_matching_events()
    {
        _store.Pipeline.Processors.Add(new SiemProcessor
        { Type = SiemProcessorType.Drop, MatchField = SiemMatchField.Category, MatchValue = "Noise" });

        _store.Add(Ev(SiemSeverity.Info, "Noise"));
        _store.Add(Ev(SiemSeverity.High, "Auth"));

        var snap = _store.Snapshot();
        snap.Should().HaveCount(1);
        snap[0].Category.Should().Be("Auth");
        _store.TotalDropped.Should().BeGreaterThan(0);
    }

    [Fact]
    public void Pipeline_keep_only_discards_everything_else()
    {
        _store.Pipeline.Processors.Add(new SiemProcessor
        { Type = SiemProcessorType.KeepOnly, MatchField = SiemMatchField.Severity, MatchValue = "Critical" });

        _store.Add(Ev(SiemSeverity.Info, "Auth"));
        _store.Add(Ev(SiemSeverity.Critical, "Threat"));

        _store.Snapshot().Should().ContainSingle(e => e.Severity == SiemSeverity.Critical);
    }

    [Fact]
    public void Pipeline_overrides_severity_and_tags()
    {
        _store.Pipeline.Processors.Add(new SiemProcessor
        { Type = SiemProcessorType.SetSeverity, MatchField = SiemMatchField.Category, MatchValue = "Auth", Arg = "Critical" });
        _store.Pipeline.Processors.Add(new SiemProcessor
        { Type = SiemProcessorType.AddTag, MatchField = SiemMatchField.Category, MatchValue = "Auth", Arg = "team=soc" });

        _store.Add(Ev(SiemSeverity.Low, "Auth"));

        var e = _store.Snapshot().Single();
        e.Severity.Should().Be(SiemSeverity.Critical);
        e.Fields.Should().Contain(kv => kv.Key == "team" && kv.Value == "soc");
    }

    [Fact]
    public void Disabled_processor_is_ignored()
    {
        _store.Pipeline.Processors.Add(new SiemProcessor
        { Enabled = false, Type = SiemProcessorType.Drop, MatchField = SiemMatchField.Any, MatchValue = "" });

        _store.Add(Ev(SiemSeverity.Info, "Auth"));
        _store.Snapshot().Should().HaveCount(1);
    }

    [Fact]
    public void Relayed_events_bypass_the_pipeline()
    {
        _store.Pipeline.Processors.Add(new SiemProcessor
        { Type = SiemProcessorType.Drop, MatchField = SiemMatchField.Any, MatchValue = "" });

        _store.Add(Ev(SiemSeverity.Info, "Auth"), applyPipeline: false);   // came from a remote collector

        _store.Snapshot().Should().HaveCount(1);
    }

    [Fact]
    public void Pipeline_extract_regex_lifts_named_groups_into_fields()
    {
        _store.Pipeline.Processors.Add(new SiemProcessor
        {
            Type = SiemProcessorType.ExtractRegex, MatchField = SiemMatchField.Any, MatchValue = "",
            Field = "message", Arg = @"user (?<user>\w+) from (?<ip>[\d.]+)",
        });
        _store.Add(new SiemEvent { Message = "user jdoe from 10.0.0.5", Category = "auth" });
        var e = _store.Snapshot().Single();
        e.Fields.Should().Contain(kv => kv.Key == "user" && kv.Value == "jdoe");
        e.Fields.Should().Contain(kv => kv.Key == "ip" && kv.Value == "10.0.0.5");
    }

    [Fact]
    public void Pipeline_rename_and_remove_field()
    {
        _store.Pipeline.Processors.Add(new SiemProcessor { Type = SiemProcessorType.RenameField, Field = "old", Arg = "new" });
        _store.Pipeline.Processors.Add(new SiemProcessor { Type = SiemProcessorType.RemoveField, Field = "junk" });
        var ev = Ev(SiemSeverity.Info, "Auth");
        ev.Fields["old"] = "v"; ev.Fields["junk"] = "x";
        _store.Add(ev);
        var e = _store.Snapshot().Single();
        e.Fields.Should().ContainKey("new").And.NotContainKey("old");
        e.Fields.Should().NotContainKey("junk");
    }

    [Fact]
    public void Pipeline_lowercase_normalises_a_field()
    {
        _store.Pipeline.Processors.Add(new SiemProcessor { Type = SiemProcessorType.Lowercase, Field = "user.name" });
        var ev = Ev(SiemSeverity.Info, "Auth");
        ev.Fields["user.name"] = "ADMIN";
        _store.Add(ev);
        _store.Snapshot().Single().Fields["user.name"].Should().Be("admin");
    }

    [Fact]
    public void Pipeline_dedupe_drops_repeats_within_window()
    {
        _store.Pipeline.Processors.Add(new SiemProcessor
        { Type = SiemProcessorType.Dedupe, Field = "message", Arg = "60" });

        _store.Add(new SiemEvent { Message = "same line", Category = "x" });
        _store.Add(new SiemEvent { Message = "same line", Category = "x" });   // duplicate → dropped
        _store.Add(new SiemEvent { Message = "different", Category = "x" });

        var snap = _store.Snapshot();
        snap.Should().HaveCount(2);
        _store.TotalDropped.Should().BeGreaterThan(0);
    }

    [Fact]
    public void Pipeline_indicator_match_tags_and_escalates()
    {
        _store.Pipeline.Processors.Add(new SiemProcessor
        { Type = SiemProcessorType.IndicatorMatch, Field = "source.ip", Arg = "1.2.3.4, 9.9.9.9" });

        var bad = Ev(SiemSeverity.Low, "Net"); bad.Fields["source.ip"] = "9.9.9.9";
        var ok = Ev(SiemSeverity.Low, "Net"); ok.Fields["source.ip"] = "10.0.0.1";
        _store.Add(bad);
        _store.Add(ok);

        var matched = _store.Snapshot().Single(e => e.Fields.ContainsKey("threat.matched"));
        matched.Fields["threat.indicator"].Should().Be("9.9.9.9");
        matched.Severity.Should().Be(SiemSeverity.High);   // escalated from Low
        _store.Snapshot().Count(e => e.Fields.ContainsKey("threat.matched")).Should().Be(1);
    }

    [Fact]
    public void Pipeline_call_routes_to_a_named_pipeline()
    {
        // a "threats" pipeline that escalates, reached from main via CallPipeline
        var threats = new SiemPipeline { Name = "threats" };
        threats.Processors.Add(new SiemProcessor { Type = SiemProcessorType.SetSeverity, MatchField = SiemMatchField.Any, MatchValue = "", Arg = "Critical" });
        SiemPipeline.NamedPipelineResolver = name => name == "threats" ? threats : null;
        try
        {
            _store.Pipeline.Processors.Add(new SiemProcessor
            { Type = SiemProcessorType.CallPipeline, MatchField = SiemMatchField.Category, MatchValue = "threat", Arg = "threats" });

            var bad = Ev(SiemSeverity.Low, "threat");
            var ok = Ev(SiemSeverity.Low, "auth");
            _store.Add(bad);
            _store.Add(ok);

            _store.Snapshot().Single(e => e.Category == "threat").Severity.Should().Be(SiemSeverity.Critical);
            _store.Snapshot().Single(e => e.Category == "auth").Severity.Should().Be(SiemSeverity.Low);
        }
        finally { SiemPipeline.NamedPipelineResolver = null; }
    }

    [Fact]
    public void Pipeline_call_can_drop_via_routed_pipeline()
    {
        var dropper = new SiemPipeline { Name = "drop-all" };
        dropper.Processors.Add(new SiemProcessor { Type = SiemProcessorType.Drop, MatchField = SiemMatchField.Any, MatchValue = "" });
        SiemPipeline.NamedPipelineResolver = name => name == "drop-all" ? dropper : null;
        try
        {
            _store.Pipeline.Processors.Add(new SiemProcessor
            { Type = SiemProcessorType.CallPipeline, MatchField = SiemMatchField.Category, MatchValue = "noise", Arg = "drop-all" });

            _store.Add(Ev(SiemSeverity.Info, "noise"));
            _store.Add(Ev(SiemSeverity.Info, "keep"));

            _store.Snapshot().Should().ContainSingle();
            _store.Snapshot().Single().Category.Should().Be("keep");
        }
        finally { SiemPipeline.NamedPipelineResolver = null; }
    }

    [Fact]
    public void Pipeline_enrich_adds_lookup_table_fields()
    {
        _store.Pipeline.Processors.Add(new SiemProcessor
        {
            Type = SiemProcessorType.Enrich, Field = "host.name",
            Arg = "DC01 => asset.owner=IT; asset.criticality=high\nWS42 => asset.owner=jdoe; asset.criticality=low",
        });

        var e = Ev(SiemSeverity.Info, "System"); e.Host = "DC01";
        var other = Ev(SiemSeverity.Info, "System"); other.Host = "UNKNOWN";
        _store.Add(e);
        _store.Add(other);

        var enriched = _store.Snapshot().Single(x => x.Host == "DC01");
        enriched.Fields["asset.owner"].Should().Be("IT");
        enriched.Fields["asset.criticality"].Should().Be("high");
        _store.Snapshot().Single(x => x.Host == "UNKNOWN").Fields.Should().NotContainKey("asset.owner");
    }

    [Fact]
    public void Pipeline_indicator_match_checks_common_fields_when_no_field_set()
    {
        _store.Pipeline.Processors.Add(new SiemProcessor
        { Type = SiemProcessorType.IndicatorMatch, Field = "", Arg = "evil.example.com" });
        var e = Ev(SiemSeverity.Info, "Web"); e.Fields["url.domain"] = "evil.example.com";
        _store.Add(e);
        _store.Snapshot().Single().Fields["threat.matched"].Should().Be("true");
    }

    [Fact]
    public void Pipeline_geo_enrich_adds_ecs_geo_fields_from_cache()
    {
        PROSCANNERCONT.Services.GeoIpService.SeedCacheForTests("8.8.8.8",
            new PROSCANNERCONT.Services.GeoIpResult { Success = true, Country = "United States", CountryCode = "US", ASN = "AS15169 Google LLC", ISP = "Google" });

        _store.Pipeline.Processors.Add(new SiemProcessor { Type = SiemProcessorType.GeoEnrich, Field = "source.ip" });
        var e = Ev(SiemSeverity.Info, "Net"); e.Fields["source.ip"] = "8.8.8.8";
        _store.Add(e);

        var stored = _store.Snapshot().Single();
        stored.Fields["source.geo.country_iso_code"].Should().Be("US");
        stored.Fields["source.geo.country_name"].Should().Be("United States");
        stored.Fields["source.as.organization"].Should().Be("AS15169 Google LLC");
    }

    [Fact]
    public void Pipeline_geo_enrich_uncached_does_not_throw()
    {
        _store.Pipeline.Processors.Add(new SiemProcessor { Type = SiemProcessorType.GeoEnrich, Field = "source.ip" });
        var e = Ev(SiemSeverity.Info, "Net"); e.Fields["source.ip"] = "203.0.113.200";   // not cached → prefetch, no geo this pass
        var act = () => _store.Add(e);
        act.Should().NotThrow();
        _store.Snapshot().Single().Fields.Should().NotContainKey("source.geo.country_iso_code");
    }

    [Fact]
    public void Clone_is_a_deep_copy_for_dry_run()
    {
        var e = Ev(SiemSeverity.Low, "Auth"); e.Fields["user.name"] = "jdoe";
        var copy = e.Clone();
        copy.Fields["user.name"] = "changed"; copy.Severity = SiemSeverity.Critical;
        e.Fields["user.name"].Should().Be("jdoe");      // original untouched
        e.Severity.Should().Be(SiemSeverity.Low);
    }

    [Fact]
    public void Pipeline_parse_timestamp_sets_event_time()
    {
        _store.Pipeline.Processors.Add(new SiemProcessor
        { Type = SiemProcessorType.ParseTimestamp, Field = "ts", Arg = "yyyy-MM-dd HH:mm:ss" });
        var e = Ev(SiemSeverity.Info, "Auth");
        e.Fields["ts"] = "2026-03-04 05:06:07";
        _store.Add(e);
        var stored = _store.Snapshot().Single();
        stored.Timestamp.Should().Be(new System.DateTime(2026, 3, 4, 5, 6, 7));
    }

    [Fact]
    public void Pipeline_bad_regex_does_not_throw()
    {
        _store.Pipeline.Processors.Add(new SiemProcessor { Type = SiemProcessorType.ExtractRegex, Field = "message", Arg = "(?<bad" });
        var act = () => _store.Add(new SiemEvent { Message = "anything" });
        act.Should().NotThrow();
        _store.Snapshot().Should().HaveCount(1);
    }

    [Fact]
    public void SourceStats_roll_up_per_machine()
    {
        _store.Add(Ev(SiemSeverity.Critical, "Threat", "DC01"));
        _store.Add(Ev(SiemSeverity.High, "Auth", "DC01"));
        _store.Add(Ev(SiemSeverity.Info, "Log", "WEB02"));

        var stats = _store.SourceStats(null);
        stats.Should().HaveCount(2);
        var dc = stats.Single(s => s.Host == "DC01");
        dc.Events.Should().Be(2);
        dc.Critical.Should().Be(1);
        dc.High.Should().Be(1);
    }
}
