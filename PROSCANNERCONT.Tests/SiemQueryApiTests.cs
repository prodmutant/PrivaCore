using System.Text.Json;
using FluentAssertions;
using PROSCANNERCONT.Models;
using PROSCANNERCONT.Services.Siem;
using Xunit;

namespace PROSCANNERCONT.Tests;

/// <summary>The external query API (Elasticsearch _search-style JSON over the active store).</summary>
public class SiemQueryApiTests
{
    private static SiemStore FreshStore()
    {
        var s = SiemStore.Instance;
        s.Clear();
        s.Pipeline = new SiemPipeline();   // no transforms
        return s;
    }

    private static void Add(SiemStore s, SiemSeverity sev, string host, string cat)
        => s.Add(new SiemEvent { Severity = sev, Host = host, Source = host, Category = cat, EventType = cat, Message = $"{cat} on {host}" });

    private static JsonElement Run(ISiemStore s, string? q, int? size = null, int? minutes = null)
        => JsonDocument.Parse(SiemQueryApi.BuildResponse(s, q, size, minutes)).RootElement;

    [Fact]
    public void Empty_query_returns_all_with_total()
    {
        var s = FreshStore();
        Add(s, SiemSeverity.Low, "DC01", "auth");
        Add(s, SiemSeverity.High, "WEB02", "network");

        var r = Run(s, "");
        r.GetProperty("total").GetInt32().Should().Be(2);
        r.GetProperty("count").GetInt32().Should().Be(2);
        r.GetProperty("hits").GetArrayLength().Should().Be(2);
    }

    [Fact]
    public void Query_filters_hits()
    {
        var s = FreshStore();
        Add(s, SiemSeverity.Low, "DC01", "auth");
        Add(s, SiemSeverity.Critical, "WEB02", "network");

        var r = Run(s, "severity:>=high");
        r.GetProperty("total").GetInt32().Should().Be(1);
        r.GetProperty("query").GetString().Should().Be("severity:>=high");
        var hit = r.GetProperty("hits")[0];
        hit.GetProperty("host.name").GetString().Should().Be("WEB02");
        hit.GetProperty("log.level").GetString().Should().Be("Critical");
    }

    [Fact]
    public void Size_caps_returned_hits_but_not_total()
    {
        var s = FreshStore();
        for (int i = 0; i < 10; i++) Add(s, SiemSeverity.Info, "H" + i, "auth");

        var r = Run(s, "category:auth", size: 3);
        r.GetProperty("total").GetInt32().Should().Be(10);
        r.GetProperty("count").GetInt32().Should().Be(3);
        r.GetProperty("hits").GetArrayLength().Should().Be(3);
    }

    [Fact]
    public void Size_is_clamped_to_max()
    {
        var s = FreshStore();
        var r = Run(s, "", size: 999999);
        // no events, but the call must succeed and not blow past MaxSize (smoke: count is 0)
        r.GetProperty("count").GetInt32().Should().Be(0);
    }

    [Fact]
    public void Query_string_overload_reads_q_size_minutes()
    {
        var s = FreshStore();
        Add(s, SiemSeverity.High, "DC01", "auth");
        var nv = new System.Collections.Specialized.NameValueCollection { { "q", "host:DC01" }, { "size", "5" }, { "minutes", "60" } };
        var r = JsonDocument.Parse(SiemQueryApi.BuildResponse(s, nv)).RootElement;
        r.GetProperty("total").GetInt32().Should().Be(1);
        r.GetProperty("hits")[0].GetProperty("host.name").GetString().Should().Be("DC01");
    }
}
