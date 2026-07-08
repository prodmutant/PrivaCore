using System.Collections.Generic;
using FluentAssertions;
using PROSCANNERCONT.Models;
using Xunit;

namespace PROSCANNERCONT.Tests;

/// <summary>The grok engine (%{PATTERN:field} → named-group regex) + the Grok pipeline processor.</summary>
public class SiemGrokTests
{
    private static Dictionary<string, string> Extract(string grok, string input)
    {
        var into = new Dictionary<string, string>();
        SiemGrok.Compile(grok).TryExtract(input, into);
        return into;
    }

    [Fact]
    public void Extracts_ip_user_and_message()
    {
        var f = Extract("%{IP:source.ip} - %{USER:user.name} \\[%{GREEDYDATA:msg}\\]",
                        "10.0.0.5 - jdoe [failed password]");
        f["source.ip"].Should().Be("10.0.0.5");
        f["user.name"].Should().Be("jdoe");
        f["msg"].Should().Be("failed password");
    }

    [Fact]
    public void Field_names_with_dots_map_back_correctly()
    {
        // dots aren't legal in .NET regex group names — the engine must map synthetic groups back
        var f = Extract("%{NUMBER:http.response.status_code}", "status=404");
        f.Should().ContainKey("http.response.status_code");
        f["http.response.status_code"].Should().Be("404");
    }

    [Fact]
    public void Ipv6_matches_via_ip_pattern()
        => Extract("%{IP:source.ip}", "2001:db8::1 connected")["source.ip"].Should().Be("2001:db8::1");

    [Fact]
    public void Pattern_without_semantic_captures_nothing()
    {
        var into = new Dictionary<string, string>();
        SiemGrok.Compile("%{WORD} %{IP:dest.ip}").TryExtract("GET 10.0.0.1", into);
        into.Should().ContainSingle().Which.Key.Should().Be("dest.ip");
    }

    [Fact]
    public void Non_matching_input_extracts_nothing()
        => Extract("%{IP:source.ip}", "no address here").Should().BeEmpty();

    [Fact]
    public void Unknown_pattern_degrades_gracefully()
    {
        // %{NOPE} is unknown → emitted as a literal; the rest still works, nothing throws
        var compiled = SiemGrok.Compile("%{NOPE:x} %{WORD:verb}");
        var into = new Dictionary<string, string>();
        var act = () => compiled.TryExtract("anything GET", into);
        act.Should().NotThrow();
    }

    [Fact]
    public void Bad_expression_is_invalid_not_throwing()
    {
        // an unbalanced literal regex group must not throw at compile time
        var compiled = SiemGrok.Compile("%{IP:ip} (unclosed");
        compiled.IsValid.Should().BeFalse();
        compiled.TryExtract("10.0.0.1 x", new Dictionary<string, string>()).Should().BeFalse();
    }

    [Fact]
    public void Grok_processor_lifts_fields_into_the_event()
    {
        var pipeline = new SiemPipeline();
        pipeline.Processors.Add(new SiemProcessor
        {
            Type = SiemProcessorType.Grok,
            Arg = "%{IP:source.ip} %{USER:user.name}",
            // Field blank → parse the message
        });
        var e = new SiemEvent { Message = "192.168.1.50 alice" };
        var outE = pipeline.Process(e);
        outE.Should().NotBeNull();
        outE!.Get("source.ip").Should().Be("192.168.1.50");
        outE.Get("user.name").Should().Be("alice");
    }

    [Fact]
    public void Grok_processor_respects_the_match_clause()
    {
        var pipeline = new SiemPipeline();
        pipeline.Processors.Add(new SiemProcessor
        {
            Type = SiemProcessorType.Grok,
            MatchField = SiemMatchField.Category, MatchValue = "web",
            Arg = "%{NUMBER:http.response.status_code}",
        });
        // non-matching category → not parsed
        var skipped = pipeline.Process(new SiemEvent { Category = "auth", Message = "code 500" });
        skipped!.Fields.Should().NotContainKey("http.response.status_code");
        // matching category → parsed
        var hit = pipeline.Process(new SiemEvent { Category = "web", Message = "code 500" });
        hit!.Get("http.response.status_code").Should().Be("500");
    }
}
