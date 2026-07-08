using System.Buffers.Binary;
using System.Text.Json;

namespace PrivaCore.ModuleSdk;

/// <summary>
/// One message on the module wire. Covers the handshake (probe / login), the
/// pairing-code enrolment gate, and the post-login data-flow channel (events
/// pushed module → controller, commands controller → module).
/// </summary>
public class ModuleMessage
{
    public string Op { get; set; } = "";   // probe | login_init | login_proof | event | command | ack | ping

    // probe
    public string? Module { get; set; }
    public bool Running { get; set; }
    public string? Name { get; set; }

    // auth
    public string? Username { get; set; }
    public string? Pairing { get; set; }   // deployment enrolment secret (extra verification)
    public string? Salt { get; set; }
    public int Iterations { get; set; }
    public string? Nonce { get; set; }
    public string? Proof { get; set; }
    public string? Token { get; set; }

    // data flow
    public string? EventName { get; set; }                 // e.g. "alert", "stat", "command"
    public Dictionary<string, object>? Data { get; set; }  // arbitrary event/command payload

    public bool Ok { get; set; }
    public string? Error { get; set; }

    public string? Str(string key)
        => Data != null && Data.TryGetValue(key, out var v) && v != null ? v.ToString() : null;
}

/// <summary>Length-framed JSON channel: [4-byte big-endian length][UTF-8 JSON]. Thread-safe sends.</summary>
public sealed class ModuleChannel : IDisposable
{
    private const int MaxFrame = 16 * 1024 * 1024;
    private readonly Stream _stream;
    private readonly SemaphoreSlim _writeLock = new(1, 1);

    public ModuleChannel(Stream stream) => _stream = stream;

    public async Task SendAsync(ModuleMessage msg, CancellationToken ct = default)
    {
        var body = JsonSerializer.SerializeToUtf8Bytes(msg);
        var prefix = new byte[4];
        BinaryPrimitives.WriteInt32BigEndian(prefix, body.Length);
        await _writeLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await _stream.WriteAsync(prefix, ct).ConfigureAwait(false);
            await _stream.WriteAsync(body, ct).ConfigureAwait(false);
            await _stream.FlushAsync(ct).ConfigureAwait(false);
        }
        finally { _writeLock.Release(); }
    }

    public async Task<ModuleMessage?> ReceiveAsync(CancellationToken ct = default)
    {
        var prefix = await ReadExactlyAsync(4, ct).ConfigureAwait(false);
        if (prefix is null) return null;
        int len = BinaryPrimitives.ReadInt32BigEndian(prefix);
        if (len <= 0 || len > MaxFrame) throw new InvalidDataException($"bad frame {len}");
        var body = await ReadExactlyAsync(len, ct).ConfigureAwait(false);
        if (body is null) return null;
        return JsonSerializer.Deserialize<ModuleMessage>(body);
    }

    private async Task<byte[]?> ReadExactlyAsync(int count, CancellationToken ct)
    {
        var buf = new byte[count];
        int read = 0;
        while (read < count)
        {
            int n = await _stream.ReadAsync(buf.AsMemory(read, count - read), ct).ConfigureAwait(false);
            if (n == 0) return read == 0 ? null : throw new EndOfStreamException();
            read += n;
        }
        return buf;
    }

    public void Dispose() { _writeLock.Dispose(); _stream.Dispose(); }
}
