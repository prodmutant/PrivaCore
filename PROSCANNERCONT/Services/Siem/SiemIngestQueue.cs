using System;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;
using PROSCANNERCONT.Models;

namespace PROSCANNERCONT.Services.Siem
{
    /// <summary>
    /// A bounded ingest queue providing back-pressure on the collector side: receivers (syslog / HTTP /
    /// agents) <see cref="Enqueue"/> events instead of writing the store directly, and a single background
    /// worker drains them into the store. When the queue is full, new events are dropped and counted
    /// (rather than blocking the network thread or exhausting memory). Decouples bursty intake from
    /// store/pipeline processing. Internal events (alerts) still write the store directly.
    /// </summary>
    public sealed class SiemIngestQueue
    {
        private readonly ConcurrentQueue<(SiemEvent e, bool pipeline)> _q = new();
        private readonly Action<SiemEvent, bool> _sink;
        private readonly bool _autoStart;
        private readonly SemaphoreSlim _signal = new(0);
        private readonly object _startLock = new();
        private CancellationTokenSource? _cts;

        private int _depth;
        private int _peak;
        private long _enqueued, _dropped, _processed;

        /// <summary>Max events that may sit in the queue before new ones are dropped (back-pressure).</summary>
        public int Capacity { get; set; } = 100_000;

        public int Depth => Volatile.Read(ref _depth);
        public int PeakDepth => Volatile.Read(ref _peak);
        public long TotalEnqueued => Interlocked.Read(ref _enqueued);
        public long TotalDropped => Interlocked.Read(ref _dropped);
        public long TotalProcessed => Interlocked.Read(ref _processed);

        /// <param name="autoStart">When true (default), the background drain starts on first Enqueue. Tests pass false to drain synchronously.</param>
        public SiemIngestQueue(Action<SiemEvent, bool> sink, bool autoStart = true) { _sink = sink; _autoStart = autoStart; }

        /// <summary>The app-wide queue that drains into the active store (runs its pipeline by default).</summary>
        public static SiemIngestQueue Instance { get; } = new((e, pipeline) => SiemStoreProvider.Current.Add(e, pipeline));

        /// <summary>Queue an event for ingestion. Returns false (and counts a drop) if the queue is full.</summary>
        public bool Enqueue(SiemEvent e, bool applyPipeline = true)
        {
            if (Volatile.Read(ref _depth) >= Capacity) { Interlocked.Increment(ref _dropped); return false; }
            if (_autoStart) EnsureStarted();
            _q.Enqueue((e, applyPipeline));
            int d = Interlocked.Increment(ref _depth);
            Interlocked.Increment(ref _enqueued);
            // record the high-water mark
            int peak;
            while (d > (peak = Volatile.Read(ref _peak)) && Interlocked.CompareExchange(ref _peak, d, peak) != peak) { }
            _signal.Release();
            return true;
        }

        /// <summary>Start the background drain (idempotent). Auto-invoked on first <see cref="Enqueue"/>.</summary>
        public void Start() => EnsureStarted();

        private void EnsureStarted()
        {
            if (_cts != null) return;
            lock (_startLock)
            {
                if (_cts != null) return;
                _cts = new CancellationTokenSource();
                var ct = _cts.Token;
                _ = Task.Run(() => DrainLoop(ct));
            }
        }

        public void Stop()
        {
            lock (_startLock) { _cts?.Cancel(); _cts = null; }
        }

        private async Task DrainLoop(CancellationToken ct)
        {
            while (!ct.IsCancellationRequested)
            {
                try { await _signal.WaitAsync(ct).ConfigureAwait(false); }
                catch (OperationCanceledException) { break; }
                DrainOnce();
            }
        }

        /// <summary>Drain every currently-queued event into the sink. Returns how many were processed. (Also drives tests synchronously.)</summary>
        public int DrainOnce()
        {
            int n = 0;
            while (_q.TryDequeue(out var item))
            {
                Interlocked.Decrement(ref _depth);
                try { _sink(item.e, item.pipeline); } catch { /* a bad event must not stop the drain */ }
                Interlocked.Increment(ref _processed);
                n++;
            }
            return n;
        }
    }
}
