using FluentAssertions;
using PROSCANNERCONT.Models;
using PROSCANNERCONT.Services.Siem;
using Xunit;

namespace PROSCANNERCONT.Tests;

/// <summary>The KQL-ish query language: booleans, grouping, wildcards, ranges, negation.</summary>
public class SiemQueryTests
{
    private static SiemEvent Ev(SiemSeverity sev, string host, string cat, params (string, string)[] fields)
    {
        var e = new SiemEvent { Severity = sev, Host = host, Source = host, Category = cat, EventType = cat, Message = $"{cat} on {host}" };
        foreach (var (k, v) in fields) e.Fields[k] = v;
        return e;
    }

    [Fact]
    public void Empty_query_matches_everything()
    {
        SiemQuery.Parse("").IsEmpty.Should().BeTrue();
        SiemQuery.Parse(null).Matches(Ev(SiemSeverity.Info, "a", "x")).Should().BeTrue();
    }

    [Fact]
    public void Field_filter_is_contains_by_default()
    {
        var q = SiemQuery.Parse("host:DC");
        q.Matches(Ev(SiemSeverity.Info, "DC01", "auth")).Should().BeTrue();
        q.Matches(Ev(SiemSeverity.Info, "WEB02", "auth")).Should().BeFalse();
    }

    [Fact]
    public void Implicit_and_between_terms()
    {
        var q = SiemQuery.Parse("host:DC01 category:auth");
        q.Matches(Ev(SiemSeverity.Info, "DC01", "auth")).Should().BeTrue();
        q.Matches(Ev(SiemSeverity.Info, "DC01", "network")).Should().BeFalse();
    }

    [Fact]
    public void Or_operator()
    {
        var q = SiemQuery.Parse("host:DC01 OR host:WEB02");
        q.Matches(Ev(SiemSeverity.Info, "DC01", "auth")).Should().BeTrue();
        q.Matches(Ev(SiemSeverity.Info, "WEB02", "auth")).Should().BeTrue();
        q.Matches(Ev(SiemSeverity.Info, "APP05", "auth")).Should().BeFalse();
    }

    [Fact]
    public void Grouping_changes_precedence()
    {
        // (DC01 OR WEB02) AND severity>=high
        var q = SiemQuery.Parse("(host:DC01 OR host:WEB02) AND severity:>=high");
        q.Matches(Ev(SiemSeverity.High, "DC01", "auth")).Should().BeTrue();
        q.Matches(Ev(SiemSeverity.Low, "DC01", "auth")).Should().BeFalse();   // fails severity
        q.Matches(Ev(SiemSeverity.Critical, "APP05", "auth")).Should().BeFalse(); // fails host
    }

    [Fact]
    public void Not_keyword_and_dash_negation()
    {
        SiemQuery.Parse("NOT host:DC01").Matches(Ev(SiemSeverity.Info, "DC01", "auth")).Should().BeFalse();
        SiemQuery.Parse("-host:DC01").Matches(Ev(SiemSeverity.Info, "WEB02", "auth")).Should().BeTrue();
    }

    [Fact]
    public void Wildcards_match_patterns()
    {
        var q = SiemQuery.Parse("user.name:adm*");
        q.Matches(Ev(SiemSeverity.Info, "a", "x", ("user.name", "admin"))).Should().BeTrue();
        q.Matches(Ev(SiemSeverity.Info, "a", "x", ("user.name", "jdoe"))).Should().BeFalse();

        SiemQuery.Parse("host:DC0?").Matches(Ev(SiemSeverity.Info, "DC01", "x")).Should().BeTrue();
        SiemQuery.Parse("host:DC0?").Matches(Ev(SiemSeverity.Info, "DC011", "x")).Should().BeFalse();
    }

    [Fact]
    public void Numeric_range_on_any_field()
    {
        var q = SiemQuery.Parse("network.bytes>=1000");
        q.Matches(Ev(SiemSeverity.Info, "a", "x", ("network.bytes", "2048"))).Should().BeTrue();
        q.Matches(Ev(SiemSeverity.Info, "a", "x", ("network.bytes", "500"))).Should().BeFalse();
    }

    [Fact]
    public void Severity_range()
    {
        var q = SiemQuery.Parse("severity:>=high");
        q.Matches(Ev(SiemSeverity.Critical, "a", "x")).Should().BeTrue();
        q.Matches(Ev(SiemSeverity.Medium, "a", "x")).Should().BeFalse();
    }

    [Fact]
    public void Quoted_phrase_as_field_value()
    {
        var q = SiemQuery.Parse("message:\"auth on DC01\"");
        q.Matches(Ev(SiemSeverity.Info, "DC01", "auth")).Should().BeTrue();
    }

    [Fact]
    public void Complex_combination()
    {
        var q = SiemQuery.Parse("category:auth AND (severity:>=high OR host:DC01) AND -host:WEB02");
        q.Matches(Ev(SiemSeverity.Low, "DC01", "auth")).Should().BeTrue();    // host:DC01 branch
        q.Matches(Ev(SiemSeverity.High, "APP05", "auth")).Should().BeTrue();  // severity branch
        q.Matches(Ev(SiemSeverity.High, "WEB02", "auth")).Should().BeFalse(); // excluded host
        q.Matches(Ev(SiemSeverity.Low, "APP05", "auth")).Should().BeFalse();  // neither branch
    }

    [Fact]
    public void Cidr_match_ipv4()
    {
        var q = SiemQuery.Parse("source.ip:10.0.0.0/24");
        q.Matches(Ev(SiemSeverity.Info, "a", "x", ("source.ip", "10.0.0.5"))).Should().BeTrue();
        q.Matches(Ev(SiemSeverity.Info, "a", "x", ("source.ip", "10.0.0.255"))).Should().BeTrue();
        q.Matches(Ev(SiemSeverity.Info, "a", "x", ("source.ip", "10.0.1.5"))).Should().BeFalse();
        q.Matches(Ev(SiemSeverity.Info, "a", "x", ("source.ip", "192.168.0.5"))).Should().BeFalse();
    }

    [Fact]
    public void Cidr_does_not_substring_match_like_plain_value()
    {
        // a /32 must be an exact host match — not the substring behaviour of plain values
        var q = SiemQuery.Parse("source.ip:10.0.0.1/32");
        q.Matches(Ev(SiemSeverity.Info, "a", "x", ("source.ip", "10.0.0.1"))).Should().BeTrue();
        q.Matches(Ev(SiemSeverity.Info, "a", "x", ("source.ip", "10.0.0.10"))).Should().BeFalse();
    }

    [Fact]
    public void Cidr_match_ipv6()
    {
        var q = SiemQuery.Parse("source.ip:\"2001:db8::/32\"");
        q.Matches(Ev(SiemSeverity.Info, "a", "x", ("source.ip", "2001:db8::1"))).Should().BeTrue();
        q.Matches(Ev(SiemSeverity.Info, "a", "x", ("source.ip", "2001:db9::1"))).Should().BeFalse();
        // an IPv4 candidate must not match an IPv6 network
        q.Matches(Ev(SiemSeverity.Info, "a", "x", ("source.ip", "10.0.0.1"))).Should().BeFalse();
    }

    [Fact]
    public void Slash_value_that_is_not_cidr_falls_back_to_contains()
    {
        var q = SiemQuery.Parse("url.path:/admin/login");
        q.Matches(Ev(SiemSeverity.Info, "a", "x", ("url.path", "/admin/login"))).Should().BeTrue();
        q.Matches(Ev(SiemSeverity.Info, "a", "x", ("url.path", "/home"))).Should().BeFalse();
    }

    [Fact]
    public void Cidr_negation_and_grouping()
    {
        var q = SiemQuery.Parse("category:auth AND -source.ip:10.0.0.0/8");
        q.Matches(Ev(SiemSeverity.Info, "a", "auth", ("source.ip", "192.168.1.1"))).Should().BeTrue();
        q.Matches(Ev(SiemSeverity.Info, "a", "auth", ("source.ip", "10.5.5.5"))).Should().BeFalse();
    }

    [Fact]
    public void Malformed_query_does_not_throw()
    {
        var act = () => SiemQuery.Parse("((host:DC01 OR").Matches(Ev(SiemSeverity.Info, "DC01", "x"));
        act.Should().NotThrow();
    }
}
