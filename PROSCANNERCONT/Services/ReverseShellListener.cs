using System;
using System.Collections.Concurrent;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using PROSCANNERCONT.Models;

namespace PROSCANNERCONT.Services
{
    public class ReverseShellListener : IDisposable
    {
        private TcpListener?            _listener;
        private CancellationTokenSource _cts = new();

        // keyed by session Id
        private readonly ConcurrentDictionary<string, ActiveSession> _sessions = new();

        public bool IsListening { get; private set; }
        public int  Port        { get; private set; }

        public event Action<string>?                   LogLine;
        public event Action<ListenerSession>?          SessionOpened;
        public event Action<string>?                   SessionClosed;
        public event Action<string, string>?           DataReceived;  // (sessionId, data)

        // =====================================================================
        // Start / Stop
        // =====================================================================
        public void Start(int port)
        {
            if (IsListening) Stop();

            _cts      = new CancellationTokenSource();
            Port      = port;
            _listener = new TcpListener(IPAddress.Any, port);
            _listener.Start();
            IsListening = true;

            Log($"[*] Listener started on 0.0.0.0:{port}");
            Log($"[*] Waiting for incoming connections...");

            Task.Run(() => AcceptLoop(_cts.Token));
        }

        public void Stop()
        {
            if (!IsListening) return;
            _cts.Cancel();
            _listener?.Stop();
            IsListening = false;

            foreach (var s in _sessions.Values) s.Close();
            _sessions.Clear();
            Log("[!] Listener stopped.");
        }

        // =====================================================================
        // Accept loop
        // =====================================================================
        private async Task AcceptLoop(CancellationToken ct)
        {
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    var client = await _listener!.AcceptTcpClientAsync(ct);
                    var ep     = (IPEndPoint?)client.Client.RemoteEndPoint;
                    var meta   = new ListenerSession
                    {
                        RemoteIp   = ep?.Address.ToString() ?? "unknown",
                        RemotePort = ep?.Port ?? 0
                    };

                    Log($"[+] Connection from {meta.RemoteIp}:{meta.RemotePort}  (session {meta.Id})");
                    SessionOpened?.Invoke(meta);

                    var session = new ActiveSession(meta.Id, client);
                    _sessions[meta.Id] = session;

                    _ = Task.Run(() => ReadLoop(session, ct));
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) when (!ct.IsCancellationRequested)
                {
                    Log($"[!] Accept error: {ex.Message}");
                }
            }
        }

        // =====================================================================
        // Read loop per session
        // =====================================================================
        private async Task ReadLoop(ActiveSession session, CancellationToken ct)
        {
            var buf = new byte[4096];
            try
            {
                var stream = session.Stream;
                while (!ct.IsCancellationRequested && session.Client.Connected)
                {
                    int n = await stream.ReadAsync(buf, 0, buf.Length, ct);
                    if (n == 0) break;

                    var text = Encoding.UTF8.GetString(buf, 0, n);
                    DataReceived?.Invoke(session.Id, text);
                }
            }
            catch (OperationCanceledException) { }
            catch { }
            finally
            {
                session.Close();
                _sessions.TryRemove(session.Id, out _);
                Log($"[-] Session {session.Id} disconnected.");
                SessionClosed?.Invoke(session.Id);
            }
        }

        // =====================================================================
        // Send command to a session
        // =====================================================================
        public async Task SendAsync(string sessionId, string command)
        {
            if (!_sessions.TryGetValue(sessionId, out var session)) return;
            try
            {
                var data = Encoding.UTF8.GetBytes(command + "\n");
                await session.Stream.WriteAsync(data);
                await session.Stream.FlushAsync();
            }
            catch (Exception ex)
            {
                Log($"[!] Send error on {sessionId}: {ex.Message}");
            }
        }

        public bool HasSession(string id) => _sessions.ContainsKey(id);

        private void Log(string line) => LogLine?.Invoke(line);

        public void Dispose() => Stop();

        // =====================================================================
        private class ActiveSession
        {
            public string    Id     { get; }
            public TcpClient Client { get; }
            public NetworkStream Stream { get; }

            public ActiveSession(string id, TcpClient client)
            {
                Id     = id;
                Client = client;
                Stream = client.GetStream();
            }

            public void Close()
            {
                try { Stream.Close(); } catch { }
                try { Client.Close(); } catch { }
            }
        }
    }
}
