using System;
using System.Text.Json;
using FluentAssertions;
using PROSCANNERCONT.Models;
using PROSCANNERCONT.Services.Siem;
using PROSCANNERCONT.Services.Siem.Elastic;
using Xunit;

namespace PROSCANNERCONT.Tests;

/// <summary>
/// The KQL → Elasticsearch DSL translation layer + the SiemEvent↔ES document mapper — the
/// load-bearing, cluster-independent parts of the ElasticSiemStore skeleton.
/// </summary>
public class SiemEsTranslatorTests
{
    private static JsonElement Dsl(string? q)
        => JsonDocument.Parse(JsonSerializer.Serialize(SiemEsQueryTranslator.ToQueryDsl(q))).RootElement;

    [Fact]
    public void Empty_query_is_match_all()
        => Dsl("").TryGetProperty("match_all", out _).Should().BeTrue();

    [Fact]
    public void Field_value_becomes_a_match()
    {
        var d = Dsl("host:DC01");
        d.GetProperty("match").GetProperty("host.name").GetProperty("query").GetString().Should().Be("DC01");
    }

    [Fact]
    public void Wildcard_becomes_a_case_insensitive_wildcard()
    {
        var d = Dsl("user.name:adm*");
        var w = d.GetProperty("wildcard").GetProperty("user.name");
        w.GetProperty("value").GetString().Should().Be("adm*");
        w.GetProperty("case_insensitive").GetBoolean().Should().BeTrue();
    }

    [Fact]
    public void Cidr_value_becomes_a_term_query()
    {
        // ES accepts CIDR directly in a term query on an `ip` field
        Dsl("source.ip:10.0.0.0/24").GetProperty("term").GetProperty("source.ip").GetString()
            .Should().Be("10.0.0.0/24");
    }

    [Fact]
    public void Non_cidr_slash_value_stays_a_match()
    {
        // a "/"-bearing value that isn't a real CIDR must not be mistaken for one
        Dsl("url.path:/admin/login").GetProperty("match").GetProperty("url.path")
            .GetProperty("query").GetString().Should().Be("/admin/login");
    }

    [Fact]
    public void Severity_range_maps_to_numeric_level()
    {
        var d = Dsl("severity:>=high");
        d.GetProperty("range").GetProperty(SiemEsDocument.SeverityLevelField).GetProperty("gte").GetInt32()
            .Should().Be((int)SiemSeverity.High);
    }

    [Fact]
    public void Numeric_range_becomes_a_range_query()
    {
        var d = Dsl("network.bytes>=1000");
        d.GetProperty("range").GetProperty("network.bytes").GetProperty("gte").GetDouble().Should().Be(1000);
    }

    [Fact]
    public void Negation_wraps_in_must_not()
    {
        var d = Dsl("-host:DC01");
        d.GetProperty("bool").GetProperty("must_not").GetArrayLength().Should().Be(1);
    }

    [Fact]
    public void Or_uses_should_with_minimum_should_match()
    {
        var d = Dsl("host:DC01 OR host:WEB02");
        var b = d.GetProperty("bool");
        b.GetProperty("should").GetArrayLength().Should().Be(2);
        b.GetProperty("minimum_should_match").GetInt32().Should().Be(1);
    }

    [Fact]
    public void Adjacent_terms_and_grouping_use_must()
    {
        var d = Dsl("(host:DC01 OR host:WEB02) AND severity:>=high");
        var must = d.GetProperty("bool").GetProperty("must");
        must.GetArrayLength().Should().Be(2);
    }

    [Fact]
    public void Free_text_becomes_multi_match()
    {
        var d = Dsl("\"failed logon\"");
        d.GetProperty("multi_match").GetProperty("query").GetString().Should().Be("failed logon");
    }

    [Fact]
    public void Search_body_adds_timestamp_range_size_and_sort()
    {
        var range = SiemRange.Rolling(TimeSpan.FromMinutes(15));
        var body = JsonDocument.Parse(JsonSerializer.Serialize(
            SiemEsQueryTranslator.ToSearchBody("host:DC01", range, 250))).RootElement;

        body.GetProperty("size").GetInt32().Should().Be(250);
        body.GetProperty("sort").GetArrayLength().Should().Be(1);
        // the query is wrapped in a bool with a @timestamp range filter
        body.GetProperty("query").GetProperty("bool").GetProperty("filter")[0]
            .GetProperty("range").TryGetProperty(SiemEsDocument.TimestampField, out _).Should().BeTrue();
    }

    [Fact]
    public void SiemQuery_preserves_its_raw_text()
        => SiemQuery.Parse("host:DC01 severity:>=high").Raw.Should().Be("host:DC01 severity:>=high");

    [Fact]
    public void Document_mapper_round_trips_an_event()
    {
        var e = new SiemEvent
        {
            Timestamp = new DateTime(2026, 6, 21, 10, 30, 0, DateTimeKind.Local),
            Source = "WinEventLog", Host = "DC01", Severity = SiemSeverity.High,
            Category = "authentication", EventType = "4625 Failed Logon", Message = "bad password",
        };
        e.Fields["source.ip"] = "10.0.0.5";
        e.Fields["user.name"] = "jdoe";

        var source = SiemEsDocument.ToSource(e);
        source[SiemEsDocument.SeverityLevelField].Should().Be((int)SiemSeverity.High);   // numeric severity emitted

        var json = JsonDocument.Parse(JsonSerializer.Serialize(source)).RootElement;
        var back = SiemEsDocument.FromSource(json);

        back.Host.Should().Be("DC01");
        back.Source.Should().Be("WinEventLog");
        back.Severity.Should().Be(SiemSeverity.High);
        back.Category.Should().Be("authentication");
        back.EventType.Should().Be("4625 Failed Logon");
        back.Message.Should().Be("bad password");
        back.Fields["source.ip"].Should().Be("10.0.0.5");
        back.Fields["user.name"].Should().Be("jdoe");
        back.Timestamp.Should().BeCloseTo(e.Timestamp, TimeSpan.FromSeconds(1));
    }
}
