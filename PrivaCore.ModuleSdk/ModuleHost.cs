using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;

namespace PrivaCore.ModuleSdk;

/// <summary>An authenticated controller currently connected to this module.</summary>
public sealed class ModuleConnection
{
    public Guid Id { get; } = Guid.NewGuid();
    public string Username { get; init; } = "";
    public string Remote { get; init; } = "";
    public DateTime SinceUtc { get; } = DateTime.UtcNow;
    internal ModuleChannel Channel { get; init; } = null!;
}

/// <summary>
/// Runs inside a standalone module app. Listens for controllers, enforces the
/// pairing code + challenge/response login, then exposes a live data-flow channel:
/// the module pushes events with <see cref="Broadcast"/>, and receives commands
/// via <see cref="CommandReceived"/>.
/// </summary>
public sealed class ModuleHost
{
    private readonly string _moduleKey;
    private readonly string _name;
    private readonly ModuleHostConfig _config;
    private readonly ConcurrentDictionary<Guid, ModuleConnection> _clients = new();
    private TcpListener? _listener;
    private CancellationTokenSource? _cts;

    public bool IsRunning { get; private set; }
    /// <summary>True if the inbound firewall rule was opened (needs admin). If false, other machines may be blocked.</summary>
    public bool FirewallOpened { get; private set; }
    public int ConnectedCount => _clients.Count;
    public IReadOnlyCollection<ModuleConnection> Connections => _clients.Values.ToArray();

    public event Action<string>? Log;
    public event Action? ClientsChanged;
    public event Action<ModuleConnection, ModuleMessage>? CommandReceived;

    public ModuleHost(string moduleKey, string name, ModuleHostConfig config)
    { _moduleKey = moduleKey; _name = name; _config = config; }

    public void Start()
    {
        if (IsRunning) return;
        // Open the firewall so other machines can reach us (best-effort; needs admin).
        FirewallOpened = NetworkReach.TryOpenFirewall($"PrivaCore {_moduleKey} {_config.ListenPort}", _config.ListenPort);
        _cts = new CancellationTokenSource();
        _listener = new TcpListener(IPAddress.Any, _config.ListenPort);   // all interfaces, not just localhost
        _listener.Start();
        IsRunning = true;
        Log?.Invoke($"Listening on 0.0.0.0:{_config.ListenPort} (firewall opened: {FirewallOpened})");
        _ = AcceptLoopAsync(_cts.Token);
    }

    public void Stop()
    {
        _cts?.Cancel();
        try { _listener?.Stop(); } catch { }
        _listener = null; IsRunning = false;
        _clients.Clear(); ClientsChanged?.Invoke();
    }

    /// <summary>Push a live event to a single connection (e.g. a Fleet policy to one agent).</summary>
    public void SendTo(ModuleConnection conn, string eventName, Dictionary<string, object> data)
    {
        var msg = new ModuleMessage { Op = "event", EventName = eventName, Data = data };
        _ = conn.Channel.SendAsync(msg).ContinueWith(_ => { }, TaskScheduler.Default);
    }

    /// <summary>Push a live event to every connected controller (data flow).</summary>
    public void Broadcast(string eventName, Dictionary<string, object> data)
    {
        var msg = new ModuleMessage { Op = "event", EventName = eventName, Data = data };
        foreach (var c in _clients.Values)
            _ = c.Channel.SendAsync(msg).ContinueWith(_ => { }, TaskScheduler.Default);
    }

    private async Task AcceptLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested && _listener != null)
        {
            TcpClient client;
            try { client = await _listener.AcceptTcpClientAsync(ct).ConfigureAwait(false); }
            catch { break; }
            _ = HandleAsync(client, ct);
        }
    }

    private async Task HandleAsync(TcpClient tcp, CancellationToken ct)
    {
        var remote = tcp.Client.RemoteEndPoint?.ToString() ?? "?";
        var channel = new ModuleChannel(tcp.GetStream());
        string? nonce = null;
        bool pairingOk = false;
        ModuleConnection? conn = null;
        try
        {
            while (!ct.IsCancellationRequested)
            {
                var msg = await channel.ReceiveAsync(ct).ConfigureAwait(false);
                if (msg is null) break;

                switch (msg.Op)
                {
                    case "probe":
                        await channel.SendAsync(new ModuleMessage
                        { Op = "probe", Ok = true, Running = msg.Module == null || msg.Module == _moduleKey, Name = _name }, ct);
                        break;

                    case "login_init":
                        pairingOk = _config.CheckPairing(msg.Pairing ?? "");
                        if (!pairingOk)
                        {
                            await channel.SendAsync(new ModuleMessage { Op = "login_init", Ok = false, Error = "invalid pairing code" }, ct);
                            break;
                        }
                        var cred = (_config.Credential != null &&
                                    string.Equals(_config.Credential.Username, msg.Username, StringComparison.OrdinalIgnoreCase))
                                    ? _config.Credential : null;
                        nonce = Convert.ToBase64String(ModuleAuth.NewRandomBytes(32));
                        await channel.SendAsync(new ModuleMessage
                        {
                            Op = "login_init", Ok = true,
                            Salt = cred?.Salt ?? Convert.ToBase64String(ModuleAuth.NewRandomBytes(16)),
                            Iterations = cred?.Iterations ?? ModuleAuth.DefaultIterations,
                            Nonce = nonce,
                        }, ct);
                        break;

                    case "login_proof":
                        bool ok = pairingOk && nonce != null && _config.Credential != null &&
                                  ModuleAuth.VerifyProof(_config.Credential.StoredKey, nonce, msg.Proof ?? "");
                        await channel.SendAsync(new ModuleMessage
                        { Op = "login_proof", Ok = ok, Token = ok ? ModuleAuth.NewSessionToken() : null,
                          Error = ok ? null : "invalid username, password, or pairing code" }, ct);
                        if (ok)
                        {
                            conn = new ModuleConnection { Username = _config.Credential!.Username, Remote = remote, Channel = channel };
                            _clients[conn.Id] = conn;
                            Log?.Invoke($"{conn.Username} connected from {remote}");
                            ClientsChanged?.Invoke();
                        }
                        break;

                    case "command":
                        if (conn != null) CommandReceived?.Invoke(conn, msg);
                        break;

                    case "ping":
                        await channel.SendAsync(new ModuleMessage { Op = "ack", Ok = true }, ct);
                        break;
                }
            }
        }
        catch { }
        finally
        {
            if (conn != null && _clients.TryRemove(conn.Id, out _))
            { Log?.Invoke($"{conn.Username} disconnected ({remote})"); ClientsChanged?.Invoke(); }
            channel.Dispose();
        }
    }
}
