using System.Collections.Generic;
using FluentAssertions;
using PROSCANNERCONT.Models;
using PROSCANNERCONT.Services.Siem;
using Xunit;

namespace PROSCANNERCONT.Tests;

/// <summary>Saved-objects bundle: serialize / deserialize round-trip.</summary>
public class SiemSavedObjectsTests
{
    [Fact]
    public void Bundle_round_trips_through_json()
    {
        var bundle = new SiemBundle
        {
            Rules = new List<SiemRule>
            {
                new() { Name = "Brute force", Query = "event.outcome:failure", Threshold = 10, MitreId = "T1110" },
            },
            SavedSearches = new List<SiemSavedSearch>
            {
                new() { Name = "Failed logons", Query = "event.outcome:failure", RangeMinutes = 15 },
            },
            Pipeline = new SiemPipeline { Processors = { new SiemProcessor { Type = SiemProcessorType.Drop, MatchValue = "noise" } } },
            IndexSettings = new SiemIndexSettings { Capacity = 12345, MaxAgeMinutes = 60 },
        };

        var json = SiemSavedObjects.Serialize(bundle);
        var back = SiemSavedObjects.Deserialize(json);

        back.RuleCount.Should().Be(1);
        back.Rules![0].MitreId.Should().Be("T1110");
        back.SearchCount.Should().Be(1);
        back.Pipeline!.Processors.Should().ContainSingle().Which.MatchValue.Should().Be("noise");
        back.IndexSettings!.Capacity.Should().Be(12345);
    }

    [Fact]
    public void Deserialize_of_garbage_is_safe_empty()
    {
        var b = SiemSavedObjects.Deserialize("{}");
        b.RuleCount.Should().Be(0);
        b.SearchCount.Should().Be(0);
    }
}
