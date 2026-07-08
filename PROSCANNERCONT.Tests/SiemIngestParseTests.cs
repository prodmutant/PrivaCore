using System.Linq;
using FluentAssertions;
using PROSCANNERCONT.Models;
using PROSCANNERCONT.Services.Siem;
using Xunit;

namespace PROSCANNERCONT.Tests;

/// <summary>Ingestion parsers: RFC3164/RFC5424 syslog and HTTP JSON ingest.</summary>
public class SiemIngestParseTests
{
    [Fact]
    public void Http_ingest_open_when_no_token_configured()
        => SiemHttpIngest.TokenAccepted("", null, null).Should().BeTrue();

    [Fact]
    public void Http_ingest_accepts_matching_x_ingest_token()
        => SiemHttpIngest.TokenAccepted("s3cret", "s3cret", null).Should().BeTrue();

    [Fact]
    public void Http_ingest_accepts_matching_bearer_token()
        => SiemHttpIngest.TokenAccepted("s3cret", null, "Bearer s3cret").Should().BeTrue();

    [Fact]
    public void Http_ingest_rejects_wrong_or_missing_token()
    {
        SiemHttpIngest.TokenAccepted("s3cret", "nope", null).Should().BeFalse();
        SiemHttpIngest.TokenAccepted("s3cret", null, null).Should().BeFalse();
        SiemHttpIngest.TokenAccepted("s3cret", "", "Bearer ").Should().BeFalse();
    }

    [Fact]
    public void Rfc3164_syslog_parses_priority_and_message()
    {
        var e = SiemSyslog.Parse("<34>Oct 11 22:14:15 mymachine su: failed", "10.0.0.5");
        e.Category.Should().Be("syslog");
        e.Severity.Should().Be(SiemSeverity.Critical);   // pri 34 → severity 2
        e.Fields["log.syslog.facility.code"].Should().Be("4");
        e.Message.Should().Contain("su:");
    }

    [Fact]
    public void Rfc5424_syslog_extracts_host_app_and_message()
    {
        var e = SiemSyslog.Parse("<165>1 2026-06-21T10:00:00Z webhost01 nginx 1234 ID47 - GET /login 200", "10.0.0.9");
        e.EventType.Should().Contain("rfc5424");
        e.Host.Should().Be("webhost01");
        e.Fields["process.name"].Should().Be("nginx");
        e.Message.Should().Be("GET /login 200");
    }

    [Fact]
    public void Rfc5424_skips_structured_data_block()
    {
        var e = SiemSyslog.Parse("<165>1 2026-06-21T10:00:00Z host app 1 ID1 [exampleSDID@123 x=\"y\"] the message", "1.1.1.1");
        e.Message.Should().Be("the message");
    }

    [Fact]
    public void Http_ingest_parses_single_object()
    {
        var events = SiemHttpIngest.Parse("{\"message\":\"hi\",\"severity\":\"high\",\"host\":\"DC01\",\"category\":\"auth\",\"user.name\":\"admin\"}");
        events.Should().ContainSingle();
        var e = events[0];
        e.Message.Should().Be("hi");
        e.Severity.Should().Be(SiemSeverity.High);
        e.Host.Should().Be("DC01");
        e.Category.Should().Be("auth");
        e.Fields["user.name"].Should().Be("admin");
    }

    [Fact]
    public void Http_ingest_parses_array_and_nested_fields()
    {
        var events = SiemHttpIngest.Parse("[{\"message\":\"a\"},{\"message\":\"b\",\"fields\":{\"source.ip\":\"1.2.3.4\"}}]");
        events.Should().HaveCount(2);
        events[1].Fields["source.ip"].Should().Be("1.2.3.4");
    }

    [Fact]
    public void Http_ingest_maps_numeric_severity()
    {
        SiemHttpIngest.Parse("{\"severity\":4}")[0].Severity.Should().Be(SiemSeverity.Critical);
        SiemHttpIngest.Parse("{\"severity\":\"warning\"}")[0].Severity.Should().Be(SiemSeverity.Medium);
    }
}
