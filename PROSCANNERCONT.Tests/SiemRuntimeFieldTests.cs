using System;
using System.Linq;
using FluentAssertions;
using PROSCANNERCONT.Models;
using PROSCANNERCONT.Services.Siem;
using Xunit;

namespace PROSCANNERCONT.Tests;

/// <summary>Runtime / scripted fields: template interpolation, read-time resolution, and cycle safety.</summary>
public class SiemRuntimeFieldTests
{
    private static SiemEvent Ev(params (string, string)[] fields)
    {
        var e = new SiemEvent { Host = "DC01", Source = "WinEventLog", Message = "hi" };
        foreach (var (k, v) in fields) e.Fields[k] = v;
        return e;
    }

    [Fact]
    public void Compute_interpolates_fields()
    {
        var rf = new SiemRuntimeField { Name = "user.session", Template = "{user.name}@{host.name}" };
        rf.Compute(Ev(("user.name", "jdoe"))).Should().Be("jdoe@DC01");
    }

    [Fact]
    public void Compute_missing_field_becomes_empty()
        => new SiemRuntimeField { Name = "x", Template = "[{nope}]" }.Compute(Ev()).Should().Be("[]");

    [Fact]
    public void Resolver_hook_makes_runtime_field_readable_via_Get()
    {
        var origR = SiemEvent.RuntimeFieldResolver;
        var origN = SiemEvent.RuntimeFieldNames;
        SiemEvent.RuntimeFieldResolver = (e, name) => name == "user.session" ? $"{e.Get("user.name")}@{e.Host}" : null;
        SiemEvent.RuntimeFieldNames = () => new[] { "user.session" };
        try
        {
            var e = Ev(("user.name", "alice"));
            e.Get("user.session").Should().Be("alice@DC01");
            // appears in the flat document (so it can be a Discover column / queried)
            e.AllFields().Should().Contain(kv => kv.Key == "user.session" && kv.Value == "alice@DC01");
            // and it's queryable through the KQL engine
            SiemQuery.Parse("user.session:alice@DC01").Matches(e).Should().BeTrue();
        }
        finally { SiemEvent.RuntimeFieldResolver = origR; SiemEvent.RuntimeFieldNames = origN; }
    }

    [Fact]
    public void Real_field_shadows_a_runtime_field_of_the_same_name()
    {
        var origR = SiemEvent.RuntimeFieldResolver;
        SiemEvent.RuntimeFieldResolver = (_, name) => name == "user.name" ? "RUNTIME" : null;
        try
        {
            var e = Ev(("user.name", "real"));
            e.Get("user.name").Should().Be("real");   // the bag wins
        }
        finally { SiemEvent.RuntimeFieldResolver = origR; }
    }

    [Fact]
    public void Store_resolves_and_is_cycle_safe()
    {
        var store = SiemRuntimeFieldStore.Instance;
        var before = store.All();
        try
        {
            store.AddOrUpdate(new SiemRuntimeField { Name = "combo", Template = "{source}|{host}" });
            store.AddOrUpdate(new SiemRuntimeField { Name = "loop", Template = "{loop}" });   // self-referential

            var e = Ev();
            e.Get("combo").Should().Be("WinEventLog|DC01");
            // a self-referential runtime field must not stack-overflow — the guard yields empty
            var act = () => e.Get("loop");
            act.Should().NotThrow();
            e.Get("loop").Should().BeNullOrEmpty();
        }
        finally
        {
            // restore the user's real list
            store.Remove(new SiemRuntimeField { Name = "combo" });
            store.Remove(new SiemRuntimeField { Name = "loop" });
            foreach (var f in before.AsEnumerable().Reverse()) store.AddOrUpdate(f);
        }
    }
}
