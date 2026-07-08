using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using SharpPcap;
using SharpPcap.LibPcap;

namespace PROSCANNERCONT.Services
{
    /// <summary>
    /// Reads a .pcap or .pcapng file and replays the packets back through
    /// SharpPcap's OnPacketArrival event, so the existing IDS engine and
    /// traffic-analysis dissector pipeline can process them without any
    /// special-case "offline" code path.
    ///
    /// Replays as fast as possible by default; an optional real-time flag
    /// honours the original packet timestamps so you can demo a capture at
    /// the speed it was actually recorded.
    /// </summary>
    /// <summary>Snapshot of a replayed packet — copied out of the ref-struct PacketCapture.</summary>
    public sealed class ReplayedPacket
    {
        public byte[] Data { get; init; } = Array.Empty<byte>();
        public DateTime Timestamp { get; init; }
        public int LinkLayerType { get; init; }
    }

    public sealed class PcapReplayService
    {
        public event Action<ReplayedPacket>? PacketReplayed;
        public event Action<int, int>? Progress;
        public event Action<string>? Completed;

        public bool RealtimePacing { get; set; } = false;

        public async Task ReplayAsync(string pcapPath, CancellationToken ct = default)
        {
            if (!File.Exists(pcapPath)) throw new FileNotFoundException(pcapPath);

            await Task.Run(() =>
            {
                int processed = 0;
                int approxTotal = (int)(new FileInfo(pcapPath).Length / 200);
                using var device = new CaptureFileReaderDevice(pcapPath);
                device.Open();

                DateTime? lastReal = null;
                DateTime? lastPkt  = null;

                device.OnPacketArrival += (s, e) =>
                {
                    try
                    {
                        // Copy the ref-struct PacketCapture into a heap-safe snapshot
                        // before raising the event — handler may run on another thread.
                        var raw = e.GetPacket();
                        var snap = new ReplayedPacket
                        {
                            Data = raw.Data,
                            Timestamp = raw.Timeval.Date,
                            LinkLayerType = (int)raw.LinkLayerType,
                        };

                        if (RealtimePacing && lastPkt.HasValue && lastReal.HasValue)
                        {
                            var delta = snap.Timestamp - lastPkt.Value;
                            var realElapsed = DateTime.UtcNow - lastReal.Value;
                            var sleep = delta - realElapsed;
                            if (sleep > TimeSpan.Zero && sleep < TimeSpan.FromSeconds(5))
                                Thread.Sleep(sleep);
                        }
                        lastPkt  = snap.Timestamp;
                        lastReal = DateTime.UtcNow;

                        PacketReplayed?.Invoke(snap);
                        processed++;
                        if (processed % 100 == 0) Progress?.Invoke(processed, approxTotal);
                    }
                    catch (Exception ex)
                    {
                        AppLogger.Log.Debug(ex, "[PcapReplay] handler threw on packet {N}", processed);
                    }
                };

                try { device.Capture(); }
                catch (Exception ex) { AppLogger.Log.Warning(ex, "[PcapReplay] capture loop ended"); }
                finally { try { device.Close(); } catch { } }

                Completed?.Invoke($"Replayed {processed} packets from {Path.GetFileName(pcapPath)}");
            }, ct).ConfigureAwait(false);
        }
    }
}
