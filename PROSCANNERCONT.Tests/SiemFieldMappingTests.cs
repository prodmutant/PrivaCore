using System.Linq;
using FluentAssertions;
using PROSCANNERCONT.Services.Siem;
using Xunit;

namespace PROSCANNERCONT.Tests;

/// <summary>Explicit field type mappings overriding the dynamic inference (B11).</summary>
public class SiemFieldMappingTests
{
    [Fact]
    public void Inference_is_used_when_no_override()
    {
        // a plain ".bytes" name infers Number, free text infers keyword/text
        SiemFieldTypes.FromName("network.bytes").Should().Be(SiemFieldType.Number);
        SiemFieldTypes.FromName("user.name").Should().Be(SiemFieldType.Keyword);
    }

    [Fact]
    public void Override_hook_wins_over_inference_in_FromName_and_Infer()
    {
        var orig = SiemFieldTypes.Override;
        SiemFieldTypes.Override = name => name == "user.name" ? SiemFieldType.Ip : (SiemFieldType?)null;
        try
        {
            SiemFieldTypes.FromName("user.name").Should().Be(SiemFieldType.Ip);
            // even with sample values that look like text, the pinned type wins
            SiemFieldTypes.Infer("user.name", new[] { "alice", "bob" }).Should().Be(SiemFieldType.Ip);
            // unmapped fields still infer normally
            SiemFieldTypes.FromName("source.port").Should().Be(SiemFieldType.Number);
        }
        finally { SiemFieldTypes.Override = orig; }
    }

    [Fact]
    public void Store_pins_and_unpins_a_field_type()
    {
        var store = SiemFieldMappingStore.Instance;
        var before = store.All();
        try
        {
            store.Set("custom.field", SiemFieldType.Ip);
            store.Get("custom.field").Should().Be(SiemFieldType.Ip);
            SiemFieldTypes.FromName("custom.field").Should().Be(SiemFieldType.Ip);   // override is live

            store.Remove("custom.field");
            store.Get("custom.field").Should().BeNull();
            SiemFieldTypes.FromName("custom.field").Should().Be(SiemFieldType.Keyword);   // back to inference
        }
        finally
        {
            store.Remove("custom.field");
            foreach (var kv in before) store.Set(kv.Key, kv.Value);   // restore the user's real mappings
        }
    }
}
