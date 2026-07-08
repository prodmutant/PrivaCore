using System.Linq;
using FluentAssertions;
using PROSCANNERCONT.Models;
using PROSCANNERCONT.Services.Siem;
using Xunit;

namespace PROSCANNERCONT.Tests;

/// <summary>The prebuilt integrations catalog (ELK Integrations): parser-stage bundles per source.</summary>
[Collection("Siem singleton")]
public class SiemIntegrationsTests
{
    [Fact]
    public void Catalog_has_named_integrations_that_build_stages()
    {
        SiemIntegrations.All.Should().NotBeEmpty();
        SiemIntegrations.All.Should().OnlyContain(i => !string.IsNullOrWhiteSpace(i.Name) && i.Build().Count > 0);
    }

    [Fact]
    public void Sshd_integration_parses_a_failed_login_line()
    {
        var pipeline = new SiemPipeline();
        pipeline.Processors.AddRange(SiemIntegrations.Get("sshd")!.Build());

        var e = new SiemEvent
        {
            Source = "sshd",
            Message = "Mar 10 13:33:01 web01 sshd[2211]: Failed password for invalid user admin from 203.0.113.7 port 4444 ssh2",
        };
        var result = pipeline.Process(e);

        result.Should().NotBeNull();
        result!.Fields["user_name"].Should().Be("admin");
        result.Fields["source_ip"].Should().Be("203.0.113.7");
        result.Fields["event_outcome"].Should().Be("Failed");
        result.Category.Should().Be("authentication");
        result.Severity.Should().Be(SiemSeverity.Medium);
    }

    [Fact]
    public void Nginx_integration_extracts_request_fields()
    {
        var pipeline = new SiemPipeline();
        pipeline.Processors.AddRange(SiemIntegrations.Get("nginx")!.Build());

        var e = new SiemEvent
        {
            Source = "nginx",
            Message = "192.168.1.5 - - [10/Mar/2026:13:55:36 +0000] \"GET /admin/login HTTP/1.1\" 200 1234",
        };
        var result = pipeline.Process(e);

        result!.Fields["source_ip"].Should().Be("192.168.1.5");
        result.Fields["http_request_method"].Should().Be("GET");
        result.Fields["url_path"].Should().Be("/admin/login");
        result.Fields["http_response_status_code"].Should().Be("200");
        result.Category.Should().Be("web");
    }
}
