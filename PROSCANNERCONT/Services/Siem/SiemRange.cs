using System;

namespace PROSCANNERCONT.Services.Siem
{
    /// <summary>
    /// A time range for SIEM queries: either <b>rolling</b> (last N, evaluated live against "now") or
    /// <b>absolute</b> (a fixed from/to). A null SiemRange means "all time". Replaces the old bare
    /// <c>TimeSpan?</c> window so Discover can do absolute ranges and histogram zoom.
    /// </summary>
    public sealed class SiemRange
    {
        public TimeSpan? Window { get; init; }      // rolling: From = now - Window, To = now
        public DateTime? AbsFrom { get; init; }     // absolute bounds (take precedence)
        public DateTime? AbsTo { get; init; }

        public bool IsAbsolute => AbsFrom.HasValue && AbsTo.HasValue;

        public DateTime From => IsAbsolute ? AbsFrom!.Value : DateTime.Now - (Window ?? TimeSpan.Zero);
        public DateTime To => IsAbsolute ? AbsTo!.Value : DateTime.Now;
        public TimeSpan Span => To - From;

        public bool Contains(DateTime t)
        {
            if (IsAbsolute) return t >= AbsFrom!.Value && t <= AbsTo!.Value;
            if (Window == null) return true;                       // all time
            return t >= DateTime.Now - Window.Value;               // rolling, live
        }

        /// <summary>A rolling range, or null for "all time".</summary>
        public static SiemRange? Rolling(TimeSpan? window) => window.HasValue ? new SiemRange { Window = window } : null;

        public static SiemRange Absolute(DateTime from, DateTime to)
            => from <= to ? new SiemRange { AbsFrom = from, AbsTo = to } : new SiemRange { AbsFrom = to, AbsTo = from };

        /// <summary>A TimeSpan is implicitly a rolling range (keeps existing call sites working).</summary>
        public static implicit operator SiemRange(TimeSpan window) => new() { Window = window };

        public string Label()
        {
            if (IsAbsolute) return $"{AbsFrom:MMM dd HH:mm} → {AbsTo:MMM dd HH:mm}";
            if (Window == null) return "all time";
            return Window.Value.TotalMinutes >= 60 ? $"last {Window.Value.TotalHours:0}h" : $"last {Window.Value.TotalMinutes:0}m";
        }
    }
}
