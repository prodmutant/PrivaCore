using System.Net.Sockets;

namespace PrivaCore.ModuleSdk;

public record ProbeResult(bool Reachable, bool Running, string? HostName, string? Error);
public record LoginResult(bool Success, string? Token, string? Error);

/// <summary>
/// Controller-side client. Flow: ConnectAndProbeAsync → LoginAsync (pairing code +
/// challenge/response) → stay connected and receive live events via
/// <see cref="EventReceived"/> while sending commands with SendCommandAsync.
/// </summary>
public sealed class ModuleClient : IDisposable
{
    private TcpClient? _tcp;
    private ModuleChannel? _channel;
    private CancellationTokenSource? _cts;

    public event Action<ModuleMessage>? EventReceived;
    public event Action? Disconnected;
    public bool IsConnected { get; private set; }

    public async Task<ProbeResult> ConnectAndProbeAsync(string host, int port, string moduleKey,
                                                        int timeoutMs = 4000, CancellationToken ct = default)
    {
        try
        {
            _tcp = new TcpClient();
            using (var cts = CancellationTokenSource.CreateLinkedTokenSource(ct))
            {
                cts.CancelAfter(timeoutMs);
                await _tcp.ConnectAsync(host, port, cts.Token).ConfigureAwait(false);
            }
            _channel = new ModuleChannel(_tcp.GetStream());
            await _channel.SendAsync(new ModuleMessage { Op = "probe", Module = moduleKey }, ct).ConfigureAwait(false);
            var resp = await _channel.ReceiveAsync(ct).ConfigureAwait(false);
            if (resp is null) return new ProbeResult(false, false, null, "no response from host");
            return new ProbeResult(true, resp.Running, resp.Name,
                resp.Running ? null : $"reachable, but the '{moduleKey}' module is not running there");
        }
        catch (OperationCanceledException) { return new ProbeResult(false, false, null, "connection timed out"); }
        catch (SocketException ex) { return new ProbeResult(false, false, null, $"cannot reach host ({ex.SocketErrorCode})"); }
        catch (Exception ex) { return new ProbeResult(false, false, null, ex.Message); }
    }

    public async Task<LoginResult> LoginAsync(string username, string password, string pairing, CancellationToken ct = default)
    {
        if (_channel is null) return new LoginResult(false, null, "not connected");
        try
        {
            await _channel.SendAsync(new ModuleMessage { Op = "login_init", Username = username, Pairing = pairing }, ct);
            var init = await _channel.ReceiveAsync(ct);
            if (init is { Ok: false }) return new LoginResult(false, null, init.Error ?? "login rejected");
            if (init?.Salt is null || init.Nonce is null) return new LoginResult(false, null, "login handshake failed");

            var proof = ModuleAuth.ComputeProof(password, init.Salt, init.Iterations, init.Nonce);
            await _channel.SendAsync(new ModuleMessage { Op = "login_proof", Proof = proof }, ct);
            var done = await _channel.ReceiveAsync(ct);

            if (done is { Ok: true })
            {
                IsConnected = true;
                _cts = new CancellationTokenSource();
                _ = ReceiveLoopAsync(_cts.Token);
                return new LoginResult(true, done.Token, null);
            }
            return new LoginResult(false, null, done?.Error ?? "login failed");
        }
        catch (Exception ex) { return new LoginResult(false, null, ex.Message); }
    }

    public Task SendCommandAsync(string command, Dictionary<string, object>? data = null, CancellationToken ct = default)
        => _channel?.SendAsync(new ModuleMessage { Op = "command", EventName = command, Data = data }, ct) ?? Task.CompletedTask;

    private async Task ReceiveLoopAsync(CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested && _channel != null)
            {
                var msg = await _channel.ReceiveAsync(ct).ConfigureAwait(false);
                if (msg is null) break;
                if (msg.Op == "event") EventReceived?.Invoke(msg);
            }
        }
        catch { }
        finally { IsConnected = false; Disconnected?.Invoke(); }
    }

    public void Dispose()
    {
        IsConnected = false;
        _cts?.Cancel();
        _channel?.Dispose();
        _tcp?.Dispose();
    }
}
