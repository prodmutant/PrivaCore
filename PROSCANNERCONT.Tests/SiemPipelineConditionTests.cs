using FluentAssertions;
using PROSCANNERCONT.Models;
using PROSCANNERCONT.Services.Siem;
using Xunit;

namespace PROSCANNERCONT.Tests;

/// <summary>Full-KQL conditional match clauses (SiemMatchField.Query) → real branching/routing (C9).</summary>
public class SiemPipelineConditionTests
{
    public SiemPipelineConditionTests()
        => SiemProcessor.QueryMatcherFactory = kql => SiemQuery.Parse(kql).Matches;

    private static SiemEvent Ev(SiemSeverity sev, string host, string cat, params (string, string)[] fields)
    {
        var e = new SiemEvent { Severity = sev, Host = host, Source = host, Category = cat, EventType = cat, Message = $"{cat} on {host}" };
        foreach (var (k, v) in fields) e.Fields[k] = v;
        return e;
    }

    [Fact]
    public void Query_match_clause_uses_full_kql()
    {
        var p = new SiemProcessor { MatchField = SiemMatchField.Query, MatchValue = "severity:>=high AND host:DC*" };
        p.Matches(Ev(SiemSeverity.Critical, "DC01", "auth")).Should().BeTrue();
        p.Matches(Ev(SiemSeverity.Low, "DC01", "auth")).Should().BeFalse();      // fails severity
        p.Matches(Ev(SiemSeverity.Critical, "WEB02", "auth")).Should().BeFalse(); // fails host
    }

    [Fact]
    public void Query_clause_supports_cidr()
    {
        var p = new SiemProcessor { MatchField = SiemMatchField.Query, MatchValue = "source.ip:10.0.0.0/8" };
        p.Matches(Ev(SiemSeverity.Info, "a", "net", ("source.ip", "10.5.5.5"))).Should().BeTrue();
        p.Matches(Ev(SiemSeverity.Info, "a", "net", ("source.ip", "192.168.1.1"))).Should().BeFalse();
    }

    [Fact]
    public void Conditional_drop_only_removes_matching_events()
    {
        var pipeline = new SiemPipeline();
        pipeline.Processors.Add(new SiemProcessor
        {
            Type = SiemProcessorType.Drop,
            MatchField = SiemMatchField.Query,
            MatchValue = "category:noise OR severity:info",
        });
        pipeline.Process(Ev(SiemSeverity.Info, "a", "auth")).Should().BeNull();      // info → dropped
        pipeline.Process(Ev(SiemSeverity.High, "a", "noise")).Should().BeNull();     // noise → dropped
        pipeline.Process(Ev(SiemSeverity.High, "a", "auth")).Should().NotBeNull();   // kept
    }

    [Fact]
    public void Conditional_routing_to_named_pipeline_on_kql()
    {
        var enrich = new SiemPipeline { Name = "enrich-web" };
        enrich.Processors.Add(new SiemProcessor { Type = SiemProcessorType.AddTag, Arg = "routed=true" });
        SiemPipeline.NamedPipelineResolver = name => name == "enrich-web" ? enrich : null;
        try
        {
            var main = new SiemPipeline();
            main.Processors.Add(new SiemProcessor
            {
                Type = SiemProcessorType.CallPipeline,
                Arg = "enrich-web",
                MatchField = SiemMatchField.Query,
                MatchValue = "category:web AND http.response.status_code:>=500",
            });

            var hit = main.Process(Ev(SiemSeverity.Medium, "w", "web", ("http.response.status_code", "503")));
            hit!.Get("routed").Should().Be("true");

            var miss = main.Process(Ev(SiemSeverity.Medium, "w", "web", ("http.response.status_code", "200")));
            miss!.Fields.Should().NotContainKey("routed");
        }
        finally { SiemPipeline.NamedPipelineResolver = null; }
    }

    [Fact]
    public void Empty_query_value_matches_all()
        => new SiemProcessor { MatchField = SiemMatchField.Query, MatchValue = "" }
            .Matches(Ev(SiemSeverity.Info, "a", "x")).Should().BeTrue();
}
