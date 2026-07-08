using System;
using System.IO;
using FluentAssertions;
using PROSCANNERCONT.Services.Siem;
using Xunit;

namespace PROSCANNERCONT.Tests;

/// <summary>The collector-side file tailer: incremental whole-line reads, partial-line hold, rotation reset.</summary>
public class SiemFileTailTests : IDisposable
{
    private readonly string _path = Path.Combine(Path.GetTempPath(), "siem_tail_" + Guid.NewGuid().ToString("N") + ".log");

    public void Dispose() { try { File.Delete(_path); } catch { } }

    private void Append(string s) => File.AppendAllText(_path, s);

    [Fact]
    public void Reads_only_new_complete_lines()
    {
        File.WriteAllText(_path, "old line that predates the tail\n");
        var tail = new SiemFileTail(_path);          // starts at EOF → ignores existing content

        tail.ReadNew().Should().BeEmpty();

        Append("alpha\nbravo\n");
        tail.ReadNew().Should().Equal("alpha", "bravo");

        tail.ReadNew().Should().BeEmpty();           // nothing new
    }

    [Fact]
    public void Partial_line_is_held_until_its_newline_arrives()
    {
        File.WriteAllText(_path, "");
        var tail = new SiemFileTail(_path);

        Append("partial");                            // no newline yet
        tail.ReadNew().Should().BeEmpty();

        Append(" continued\n");                        // now the line is complete
        tail.ReadNew().Should().Equal("partial continued");
    }

    [Fact]
    public void Handles_crlf_and_skips_blank_lines()
    {
        File.WriteAllText(_path, "");
        var tail = new SiemFileTail(_path);
        Append("one\r\n\r\ntwo\r\n");
        tail.ReadNew().Should().Equal("one", "two");
    }

    [Fact]
    public void Truncation_resets_and_rereads_from_start()
    {
        File.WriteAllText(_path, "");
        var tail = new SiemFileTail(_path);
        Append("first message line\n");
        tail.ReadNew().Should().Equal("first message line");

        // truncate/rotate to a shorter file (length < last offset) → re-read from the start
        File.WriteAllText(_path, "new\n");
        tail.ReadNew().Should().Equal("new");
    }

    [Fact]
    public void From_start_reads_existing_content()
    {
        File.WriteAllText(_path, "a\nb\n");
        var tail = new SiemFileTail(_path, fromStart: true);
        tail.ReadNew().Should().Equal("a", "b");
    }
}
