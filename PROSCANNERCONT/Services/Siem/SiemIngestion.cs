using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using PROSCANNERCONT.Models;

namespace PROSCANNERCONT.Services.Siem
{
    /// <summary>
    /// SIEM ingestion (the "Logstash/Beats" layer): pulls events into <see cref="SiemStore"/>
    /// from real Windows Event Logs, an inbound syslog listener, and an optional synthetic
    /// generator (handy for demos / quiet machines). Each source can be toggled independently.
    /// </summary>
    public sealed class SiemIngestion
    {
        public static SiemIngestion Instance { get; } = new();

        public bool WinEventLogOn { get; private set; }
        public bool SyslogOn { get; private set; }
        public bool GeneratorOn { get; private set; }
        public int SyslogPort { get; set; } = 5514;

        public event Action? StateChanged;

        private readonly List<EventLogWatcher> _winWatchers = new();
        private UdpClient? _syslog;
        private CancellationTokenSource? _syslogCts;
        private System.Timers.Timer? _gen;
        private readonly Random _rng = new();
        private readonly string _host = Environment.MachineName;

        // ── Windows Event Log ──
        public void StartWinEventLog()
        {
            if (WinEventLogOn) return;
            foreach (var log in new[] { "Security", "System", "Application" })
            {
                try
                {
                    var query = new EventLogQuery(log, PathType.LogName, "*[System[(Level=1 or Level=2 or Level=3 or Level=4)]]");
                    var w = new EventLogWatcher(query);
                    w.EventRecordWritten += (_, a) => { if (a.EventRecord != null) Ingest(a.EventRecord, log); };
                    w.Enabled = true;
                    _winWatchers.Add(w);
                }
                catch { /* e.g. Security log needs admin — skip that log */ }
            }
            WinEventLogOn = _winWatchers.Count > 0;
            StateChanged?.Invoke();
        }

        public void StopWinEventLog()
        {
            foreach (var w in _winWatchers) { try { w.Enabled = false; w.Dispose(); } catch { } }
            _winWatchers.Clear();
            WinEventLogOn = false;
            StateChanged?.Invoke();
        }

        private void Ingest(EventRecord rec, string log)
        {
            string msg;
            try { msg = rec.FormatDescription() ?? ""; } catch { msg = ""; }
            if (msg.Length > 600) msg = msg[..600];
            var sev = (rec.Level) switch { 1 => SiemSeverity.Critical, 2 => SiemSeverity.High, 3 => SiemSeverity.Medium, _ => SiemSeverity.Info };
            int id = rec.Id;
            SiemIngestQueue.Instance.Enqueue(new SiemEvent
            {
                Timestamp = rec.TimeCreated ?? DateTime.Now,
                Source = "WinEventLog",
                Host = _host,
                Severity = SecurityIdSeverity(id, sev),
                Category = log,
                EventType = $"{id} {SecurityIdName(id)}".Trim(),
                Message = string.IsNullOrWhiteSpace(msg) ? (rec.ProviderName ?? log) : msg,
                Fields = new()
                {
                    ["host.name"] = _host,
                    ["winlog.provider_name"] = rec.ProviderName ?? "",
                    ["winlog.event_id"] = id.ToString(),
                    ["winlog.channel"] = log,
                    ["event.code"] = id.ToString(),
                    ["event.dataset"] = "windows.event_log",
                    ["log.level"] = SecurityIdSeverity(id, sev).ToString(),
                },
            });
        }

        private static string SecurityIdName(int id) => id switch
        {
            4624 => "Successful Logon", 4625 => "Failed Logon", 4634 => "Logoff", 4648 => "Explicit-Cred Logon",
            4672 => "Special Privileges", 4720 => "User Created", 4726 => "User Deleted", 4728 => "Added to Group",
            4740 => "Account Locked Out", 1102 => "Audit Log Cleared", 7045 => "Service Installed", _ => "",
        };
        private static SiemSeverity SecurityIdSeverity(int id, SiemSeverity fallback) => id switch
        {
            4625 or 4740 => SiemSeverity.High, 1102 or 4728 or 4672 => SiemSeverity.High,
            4720 or 4726 or 7045 or 4648 => SiemSeverity.Medium, _ => fallback,
        };

        // ── Syslog listener ──
        public void StartSyslog(int port)
        {
            if (SyslogOn) return;
            SyslogPort = port;
            try { _syslog = new UdpClient(port); }
            catch { SyslogOn = false; StateChanged?.Invoke(); return; }
            _syslogCts = new CancellationTokenSource();
            SyslogOn = true;
            _ = SyslogLoop(_syslogCts.Token);
            StateChanged?.Invoke();
        }

        public void StopSyslog()
        {
            _syslogCts?.Cancel();
            try { _syslog?.Close(); } catch { }
            _syslog = null; SyslogOn = false;
            StateChanged?.Invoke();
        }

        private async System.Threading.Tasks.Task SyslogLoop(CancellationToken ct)
        {
            while (!ct.IsCancellationRequested && _syslog != null)
            {
                UdpReceiveResult r;
                try { r = await _syslog.ReceiveAsync(ct); }
                catch { break; }
                var text = Encoding.UTF8.GetString(r.Buffer);
                SiemIngestQueue.Instance.Enqueue(SiemSyslog.Parse(text, r.RemoteEndPoint.Address.ToString()));
            }
        }

        // ── Syslog over TCP (newline-delimited) ──
        public bool SyslogTcpOn { get; private set; }
        public int SyslogTcpPort { get; set; } = 5514;
        private TcpListener? _syslogTcp;
        private CancellationTokenSource? _syslogTcpCts;

        public void StartSyslogTcp(int port)
        {
            if (SyslogTcpOn) return;
            SyslogTcpPort = port;
            try { _syslogTcp = new TcpListener(IPAddress.Any, port); _syslogTcp.Start(); }
            catch { _syslogTcp = null; SyslogTcpOn = false; StateChanged?.Invoke(); return; }
            _syslogTcpCts = new CancellationTokenSource();
            SyslogTcpOn = true;
            _ = SyslogTcpAccept(_syslogTcpCts.Token);
            StateChanged?.Invoke();
        }

        public void StopSyslogTcp()
        {
            _syslogTcpCts?.Cancel();
            try { _syslogTcp?.Stop(); } catch { }
            _syslogTcp = null; SyslogTcpOn = false;
            StateChanged?.Invoke();
        }

        private async System.Threading.Tasks.Task SyslogTcpAccept(CancellationToken ct)
        {
            while (!ct.IsCancellationRequested && _syslogTcp != null)
            {
                TcpClient client;
                try { client = await _syslogTcp.AcceptTcpClientAsync(ct); }
                catch { break; }
                _ = SyslogTcpClient(client, ct);
            }
        }

        private async System.Threading.Tasks.Task SyslogTcpClient(TcpClient client, CancellationToken ct)
        {
            var ip = (client.Client.RemoteEndPoint as IPEndPoint)?.Address.ToString() ?? "tcp";
            try
            {
                using (client)
                using (var sr = new System.IO.StreamReader(client.GetStream(), Encoding.UTF8))
                {
                    string? line;
                    while (!ct.IsCancellationRequested && (line = await sr.ReadLineAsync()) != null)
                        if (line.Length > 0) SiemIngestQueue.Instance.Enqueue(SiemSyslog.Parse(line, ip));
                }
            }
            catch { }
        }

        // ── HTTP JSON ingest endpoint ──
        public bool HttpOn { get; private set; }
        public int HttpPort { get; set; } = 9721;
        /// <summary>
        /// Optional shared secret for the HTTP ingest endpoint. When non-empty, POSTs must present it
        /// as <c>X-Ingest-Token: &lt;token&gt;</c> or <c>Authorization: Bearer &lt;token&gt;</c> or they are
        /// rejected with 401. Empty (default) = unauthenticated, trusted-network behaviour (unchanged).
        /// </summary>
        public string HttpToken { get; set; } = "";
        private System.Net.HttpListener? _http;
        private CancellationTokenSource? _httpCts;

        public void StartHttp(int port)
        {
            if (HttpOn) return;
            HttpPort = port;
            _http = new System.Net.HttpListener();
            // try all-interfaces (needs admin/urlacl); fall back to localhost
            foreach (var prefix in new[] { $"http://+:{port}/", $"http://localhost:{port}/" })
            {
                try
                {
                    _http.Prefixes.Clear();
                    _http.Prefixes.Add(prefix);
                    _http.Start();
                    break;
                }
                catch { _http = new System.Net.HttpListener(); }
            }
            if (!_http.IsListening) { _http = null; HttpOn = false; StateChanged?.Invoke(); return; }
            _httpCts = new CancellationTokenSource();
            HttpOn = true;
            _ = HttpLoop(_httpCts.Token);
            StateChanged?.Invoke();
        }

        public void StopHttp()
        {
            _httpCts?.Cancel();
            try { _http?.Stop(); _http?.Close(); } catch { }
            _http = null; HttpOn = false;
            StateChanged?.Invoke();
        }

        private async System.Threading.Tasks.Task HttpLoop(CancellationToken ct)
        {
            while (!ct.IsCancellationRequested && _http != null && _http.IsListening)
            {
                System.Net.HttpListenerContext ctx;
                try { ctx = await _http.GetContextAsync(); }
                catch { break; }
                _ = System.Threading.Tasks.Task.Run(() => HandleHttp(ctx));
            }
        }

        private void HandleHttp(System.Net.HttpListenerContext ctx)
        {
            string? json = null;            // a full JSON body to return verbatim (the query API)
            int count = 0; string status = "ok";
            try
            {
                if (!TokenOk(ctx.Request))
                {
                    status = "unauthorized";
                    ctx.Response.StatusCode = 401;
                }
                else if (ctx.Request.HttpMethod == "GET" &&
                         (ctx.Request.Url?.AbsolutePath ?? "/").TrimEnd('/').EndsWith("/search", StringComparison.OrdinalIgnoreCase))
                {
                    // external query API:  GET /api/search?q=&size=&minutes=
                    json = SiemQueryApi.BuildResponse(SiemStoreProvider.Current, ctx.Request.QueryString);
                }
                else if (ctx.Request.HttpMethod == "POST")
                {
                    using var sr = new System.IO.StreamReader(ctx.Request.InputStream, ctx.Request.ContentEncoding);
                    var body = sr.ReadToEnd();
                    var ip = ctx.Request.RemoteEndPoint?.Address.ToString() ?? "http";
                    foreach (var e in SiemHttpIngest.Parse(body, ip)) { SiemIngestQueue.Instance.Enqueue(e); count++; }
                }
                else status = "POST a JSON event/array to ingest, or GET /api/search?q=… to query";
            }
            catch (Exception ex) { status = "error: " + ex.Message; }
            try
            {
                var resp = Encoding.UTF8.GetBytes(json ?? $"{{\"ingested\":{count},\"status\":\"{status}\"}}");
                ctx.Response.ContentType = "application/json";
                ctx.Response.OutputStream.Write(resp, 0, resp.Length);
                ctx.Response.Close();
            }
            catch { }
        }

        /// <summary>True if no token is configured, or the request presents the matching token (constant-time).</summary>
        private bool TokenOk(System.Net.HttpListenerRequest req)
            => SiemHttpIngest.TokenAccepted(HttpToken, req.Headers["X-Ingest-Token"], req.Headers["Authorization"]);

        // ── File tailing (collector-side Filebeat) ──
        private readonly Dictionary<string, SiemFileTail> _tails = new(StringComparer.OrdinalIgnoreCase);
        private System.Timers.Timer? _tailTimer;
        private readonly object _tailLock = new();

        public bool FileTailOn { get { lock (_tailLock) return _tails.Count > 0; } }
        public List<string> TailedFiles() { lock (_tailLock) return _tails.Keys.ToList(); }

        /// <summary>Start tailing a local log file; new lines are ingested as events. No-op if already tailed or missing.</summary>
        public void AddTailedFile(string path)
        {
            if (string.IsNullOrWhiteSpace(path) || !System.IO.File.Exists(path)) return;
            lock (_tailLock)
            {
                if (_tails.ContainsKey(path)) return;
                _tails[path] = new SiemFileTail(path);
                if (_tailTimer == null)
                {
                    _tailTimer = new System.Timers.Timer(1500) { AutoReset = true };
                    _tailTimer.Elapsed += (_, _) => PollTails();
                    _tailTimer.Start();
                }
            }
            StateChanged?.Invoke();
        }

        public void RemoveTailedFile(string path)
        {
            lock (_tailLock)
            {
                _tails.Remove(path);
                if (_tails.Count == 0) { _tailTimer?.Stop(); _tailTimer?.Dispose(); _tailTimer = null; }
            }
            StateChanged?.Invoke();
        }

        private void PollTails()
        {
            List<SiemFileTail> tails; lock (_tailLock) tails = _tails.Values.ToList();
            foreach (var t in tails)
            {
                var name = System.IO.Path.GetFileName(t.Path);
                foreach (var line in t.ReadNew())
                {
                    var e = new SiemEvent
                    {
                        Timestamp = DateTime.Now, Source = "file:" + name, Host = _host,
                        Category = "file", EventType = "file.line", Message = line,
                    };
                    e.Fields["log.file.path"] = t.Path;
                    SiemIngestQueue.Instance.Enqueue(e);
                }
            }
        }

        // ── Synthetic generator (demo / quiet machines) ──
        public void StartGenerator()
        {
            if (GeneratorOn) return;
            _gen = new System.Timers.Timer(1400) { AutoReset = true };
            _gen.Elapsed += (_, _) => { for (int i = 0, n = _rng.Next(1, 4); i < n; i++) SiemIngestQueue.Instance.Enqueue(Synthesize()); };
            _gen.Start();
            GeneratorOn = true;
            StateChanged?.Invoke();
        }

        public void StopGenerator()
        {
            _gen?.Stop(); _gen?.Dispose(); _gen = null;
            GeneratorOn = false;
            StateChanged?.Invoke();
        }

        private static readonly string[] _users  = { "jdoe", "asmith", "admin", "svc_sql", "mwilson", "root", "guest", "backup", "kpatel", "rlee" };
        private static readonly string[] _hosts   = { "DC01", "WEB02", "APP05", "DB01", "WKS-114", "FILESRV", "PROXY01" };
        private static readonly string[] _procs   = { "powershell.exe", "cmd.exe", "rundll32.exe", "wmic.exe", "mshta.exe", "chrome.exe", "svchost.exe", "explorer.exe", "sshd", "nginx" };
        private static readonly string[] _osList  = { "Windows Server 2022", "Windows 11", "Ubuntu 22.04", "Debian 12", "RHEL 9" };
        private static readonly string[] _geos    = { "US", "DE", "RU", "CN", "BR", "NL", "GB", "IN", "FR", "KP" };
        private static readonly string[] _agents  = { "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "curl/8.4.0", "python-requests/2.31", "Go-http-client/2.0" };
        private static readonly string[] _methods = { "GET", "POST", "PUT", "DELETE" };
        private static readonly string[] _uris    = { "/login", "/api/users", "/admin", "/wp-login.php", "/.env", "/api/orders", "/health" };

        private string Ip() => $"{_rng.Next(10, 223)}.{_rng.Next(0, 255)}.{_rng.Next(0, 255)}.{_rng.Next(1, 254)}";
        private string Pick(string[] a) => a[_rng.Next(a.Length)];
        private string Mac() => string.Join(":", Enumerable.Range(0, 6).Select(_ => _rng.Next(0, 256).ToString("x2")));

        private SiemEvent Synthesize()
        {
            string srcIp = Ip(), user = Pick(_users), host = Pick(_hosts), os = Pick(_osList), geo = Pick(_geos);
            int srcPort = _rng.Next(1024, 65535);
            int pick = _rng.Next(100);

            if (pick < 30)
                return New(SiemSeverity.Info, "authentication", "4624 Successful Logon", host, srcIp,
                    $"User {user} successfully logged on to {host} from {srcIp}.",
                    ("user.name", user), ("source.ip", srcIp), ("source.port", srcPort.ToString()),
                    ("event.outcome", "success"), ("event.action", "logon"), ("winlog.event_id", "4624"),
                    ("logon.type", Pick(new[] { "2 Interactive", "3 Network", "10 RemoteInteractive" })),
                    ("host.os.name", os), ("source.geo.country_iso_code", geo), ("auth.method", "password"));

            if (pick < 50)
                return New(SiemSeverity.High, "authentication", "4625 Failed Logon", host, srcIp,
                    $"Failed logon for {user} from {srcIp} — bad password.",
                    ("user.name", user), ("source.ip", srcIp), ("source.port", srcPort.ToString()),
                    ("event.outcome", "failure"), ("event.action", "logon"), ("winlog.event_id", "4625"),
                    ("error.code", "0xC000006A"), ("source.geo.country_iso_code", geo), ("auth.failure_reason", "bad password"));

            if (pick < 64)
            {
                var proc = Pick(_procs); int pid = _rng.Next(400, 30000);
                return New(SiemSeverity.Info, "process", "ProcessCreate", host, host,
                    $"Process {proc} (pid {pid}) started by {user} on {host}.",
                    ("process.name", proc), ("process.pid", pid.ToString()), ("process.parent.name", "explorer.exe"),
                    ("user.name", user), ("process.command_line", $"\"C:\\Windows\\System32\\{proc}\" -k netsvcs"),
                    ("host.os.name", os), ("event.action", "process_started"));
            }

            if (pick < 76)
            {
                int dstPort = new[] { 22, 80, 443, 3389, 445, 8080 }[_rng.Next(6)];
                long bytes = _rng.Next(200, 2_000_000);
                return New(SiemSeverity.Low, "network", "FirewallBlock", host, srcIp,
                    $"Firewall blocked {srcIp}:{srcPort} → {host}:{dstPort}.",
                    ("source.ip", srcIp), ("source.port", srcPort.ToString()), ("destination.ip", Ip()),
                    ("destination.port", dstPort.ToString()), ("network.protocol", Pick(new[] { "tcp", "udp" })),
                    ("network.bytes", bytes.ToString()), ("event.action", "denied"), ("rule.name", "Block-Inbound-WAN"),
                    ("source.geo.country_iso_code", geo));
            }

            if (pick < 85)
            {
                int code = new[] { 200, 301, 403, 404, 500 }[_rng.Next(5)];
                string method = Pick(_methods), uri = Pick(_uris);
                return New(code >= 500 ? SiemSeverity.Medium : SiemSeverity.Info, "web", "HTTP Request", host, srcIp,
                    $"{method} {uri} → {code} from {srcIp}",
                    ("source.ip", srcIp), ("http.request.method", method), ("url.path", uri),
                    ("http.response.status_code", code.ToString()), ("user_agent.original", Pick(_agents)),
                    ("http.response.bytes", _rng.Next(120, 90000).ToString()), ("destination.port", "443"),
                    ("source.geo.country_iso_code", geo));
            }

            if (pick < 91)
                return New(SiemSeverity.Medium, "network", "PortScan", host, srcIp,
                    $"Possible port scan from {srcIp} — {_rng.Next(50, 400)} ports in 10s.",
                    ("source.ip", srcIp), ("scan.port_count", _rng.Next(50, 400).ToString()), ("network.protocol", "tcp"),
                    ("event.action", "port_scan"), ("source.geo.country_iso_code", geo), ("threat.tactic.name", "Reconnaissance"));

            if (pick < 97)
                return New(SiemSeverity.High, "threat", "BruteForce", host, srcIp,
                    $"Brute-force on {host}: {_rng.Next(15, 120)} failed logons from {srcIp}.",
                    ("source.ip", srcIp), ("user.name", user), ("auth.failures", _rng.Next(15, 120).ToString()),
                    ("event.action", "credential_access"), ("threat.technique.id", "T1110"),
                    ("threat.technique.name", "Brute Force"), ("source.geo.country_iso_code", geo));

            return New(SiemSeverity.Critical, "threat", "MalwareDetected", host, host,
                $"Malware '{Pick(new[] { "Emotet", "Mimikatz", "Cobalt Strike", "WannaCry" })}' detected on {host}.",
                ("threat.software.name", Pick(new[] { "Emotet", "Mimikatz", "Cobalt Strike", "WannaCry" })),
                ("file.path", $"C:\\Users\\{user}\\AppData\\Local\\Temp\\{_rng.Next(1000, 9999)}.exe"),
                ("file.hash.sha256", Convert.ToHexString(ModuleHashStub())), ("process.pid", _rng.Next(400, 30000).ToString()),
                ("user.name", user), ("event.action", "malware_detected"), ("threat.technique.id", "T1059"), ("host.os.name", os));
        }

        private byte[] ModuleHashStub() { var b = new byte[16]; _rng.NextBytes(b); return b; }

        private SiemEvent New(SiemSeverity sev, string cat, string type, string host, string src, string msg, params (string, string)[] fields)
        {
            var e = new SiemEvent { Severity = sev, Category = cat, EventType = type, Message = msg, Source = src, Host = host };
            e.Fields["host.name"] = host;
            e.Fields["event.dataset"] = "generator";
            foreach (var (k, v) in fields) e.Fields[k] = v;
            return e;
        }

        public void StopAll() { StopWinEventLog(); StopSyslog(); StopSyslogTcp(); StopGenerator(); StopHttp(); }
    }
}
