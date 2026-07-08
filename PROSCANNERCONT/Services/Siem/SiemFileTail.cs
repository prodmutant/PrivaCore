using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace PROSCANNERCONT.Services.Siem
{
    /// <summary>
    /// Tails a log file (Filebeat-style): on each <see cref="ReadNew"/> it returns the complete lines
    /// appended since the previous call, tracking a byte offset. Only whole lines (terminated by '\n')
    /// are emitted — a partial trailing line waits for its newline. Truncation/rotation (file shorter
    /// than the offset) resets to the start. Pure I/O + offset state, so it's unit-testable.
    /// </summary>
    public sealed class SiemFileTail
    {
        public string Path { get; }
        private long _offset;

        /// <param name="fromStart">When false (default) only lines written after construction are tailed; true reads the whole file first.</param>
        public SiemFileTail(string path, bool fromStart = false)
        {
            Path = path;
            _offset = fromStart ? 0 : SafeLength();
        }

        public long Offset => _offset;

        /// <summary>Return the complete lines appended since the last call (empty if none / on error).</summary>
        public List<string> ReadNew()
        {
            var lines = new List<string>();
            try
            {
                long len = SafeLength();
                if (len < _offset) _offset = 0;        // truncated or rotated → re-read from the top
                if (len <= _offset) return lines;

                using var fs = new FileStream(Path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                fs.Seek(_offset, SeekOrigin.Begin);
                var buf = new byte[len - _offset];
                int read = fs.Read(buf, 0, buf.Length);
                var text = Encoding.UTF8.GetString(buf, 0, read);

                int lastNl = text.LastIndexOf('\n');
                if (lastNl < 0) return lines;          // no complete line yet — don't advance

                var complete = text[..lastNl];
                _offset += Encoding.UTF8.GetByteCount(text[..(lastNl + 1)]);
                foreach (var raw in complete.Split('\n'))
                {
                    var line = raw.TrimEnd('\r');
                    if (line.Length > 0) lines.Add(line);
                }
            }
            catch { /* locked/deleted mid-read — try again next tick */ }
            return lines;
        }

        private long SafeLength()
        {
            try { var fi = new FileInfo(Path); return fi.Exists ? fi.Length : 0; }
            catch { return 0; }
        }
    }
}
