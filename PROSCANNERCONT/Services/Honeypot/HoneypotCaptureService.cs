using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using PROSCANNERCONT.Models;

namespace PROSCANNERCONT.Services.Honeypot
{
    /// <summary>How a decoy presents itself (custom banner / served website).</summary>
    public sealed class DecoyOptions
    {
        /// <summary>Banner for Telnet/SSH/FTP.</summary>
        public string? Banner { get; set; }
        /// <summary>HTML the HTTP decoy serves as a real-looking website (empty = fake login / 401 prompt).</summary>
        public string? HttpHtml { get; set; }
    }

    /// <summary>One running decoy listener.</summary>
    public sealed class HoneypotListenerInfo
    {
        public HoneypotServiceKind Kind { get; init; }
        public int Port { get; init; }
        public DecoyOptions? Options { get; init; }
        public DateTime StartedUtc { get; } = DateTime.UtcNow;
        public long Hits { get; set; }
        public string KindName => Kind.ToString().ToUpperInvariant();

        /// <summary>The addresses this decoy is reachable on (it binds all interfaces): "ip:port  ip:port".</summary>
        public string Endpoints => HoneypotCaptureService.HostAddresses.Count == 0
            ? $"0.0.0.0:{Port}"
            : string.Join("   ", HoneypotCaptureService.HostAddresses.Select(ip => $"{ip}:{Port}"));
    }

    /// <summary>
    /// The software honeypot: TCP listeners that emulate services and RECORD every interaction
    /// (source, credentials tried, requests, payloads). This is the capture layer the old Hyper-V
    /// dashboard lacked — it turns "0 attack attempts" into real, searchable threat data. Emitting
    /// to the SIEM is done separately by <see cref="HoneypotSiemBridge"/> so this engine has no SIEM
    /// dependency and stays unit-testable.
    /// </summary>
    public sealed class HoneypotCaptureService
    {
        public static HoneypotCaptureService Instance { get; } = new();

        private const int MaxCapture = 4096;   // cap bytes read per interaction (anti-abuse)

        private sealed class Listener
        {
            public HoneypotListenerInfo Info = null!;
            public TcpListener Tcp = null!;
            public CancellationTokenSource Cts = null!;
        }

        private readonly ConcurrentDictionary<int, Listener> _listeners = new();
        private readonly object _lock = new();
        private readonly LinkedList<HoneypotHit> _hits = new();          // newest first
        private readonly ConcurrentDictionary<string, long> _bySource = new(StringComparer.OrdinalIgnoreCase);
        private readonly ConcurrentDictionary<string, long> _byUser = new(StringComparer.OrdinalIgnoreCase);
        private readonly ConcurrentDictionary<string, long> _byPass = new(StringComparer.Ordinal);
        private long _total;
        private long _creds;
        private long _throttled;

        // per-source connection rate limiter — a single attacker can't flood/fill the ring.
        private const int MaxConnPerMinute = 40;
        private readonly ConcurrentDictionary<string, (DateTime windowStart, int count)> _rate = new();
        private DateTime _lastRatePrune = DateTime.UtcNow;
        private bool _restoring;

        // Cardinality caps: an internet-exposed sensor sees unbounded distinct IPs/usernames/passwords.
        // The hit ring is already capped; these bound the aggregate stat maps (top-N is all we surface).
        private const int MaxStatKeys = 50_000;
        private int _trimming;   // 0/1 guard so only one thread trims at a time

        /// <summary>The host's reachable IPv4 addresses (decoys bind all interfaces, so they answer on each).</summary>
        public static IReadOnlyList<string> HostAddresses { get; private set; } = new List<string>();

        private static void RefreshHostAddresses()
        {
            try
            {
                var ips = PrivaCore.ModuleSdk.NetworkReach.LocalIPv4();
                ips.Add("127.0.0.1");
                HostAddresses = ips;
            }
            catch { }
        }

        public int Capacity { get; set; } = 5000;
        public long TotalHits => Interlocked.Read(ref _total);
        /// <summary>Number of interactions that carried credentials (the highest-value signal).</summary>
        public long CredentialHits => Interlocked.Read(ref _creds);
        /// <summary>Connections dropped by the per-source rate limiter.</summary>
        public long TotalThrottled => Interlocked.Read(ref _throttled);
        /// <summary>Distinct attacker source IPs seen.</summary>
        public int UniqueSources => _bySource.Count;
        public int ActiveListeners => _listeners.Count;

        /// <summary>Raised for every recorded interaction (the SIEM bridge and UI subscribe).</summary>
        public event Action<HoneypotHit>? HitRecorded;

        public IReadOnlyList<HoneypotListenerInfo> Listeners => _listeners.Values.Select(l => l.Info).OrderBy(i => i.Port).ToList();

        /// <summary>Start a decoy of <paramref name="kind"/> on <paramref name="port"/>. Returns false if the port is taken.</summary>
        public bool Start(HoneypotServiceKind kind, int port, DecoyOptions? options = null)
        {
            if (_listeners.ContainsKey(port)) return false;
            RefreshHostAddresses();
            TcpListener tcp;
            try { tcp = new TcpListener(IPAddress.Any, port); tcp.Start(); }
            catch { return false; }

            var l = new Listener
            {
                Info = new HoneypotListenerInfo { Kind = kind, Port = port, Options = options },
                Tcp = tcp,
                Cts = new CancellationTokenSource(),
            };
            if (!_listeners.TryAdd(port, l)) { try { tcp.Stop(); } catch { } return false; }
            _ = AcceptLoop(l);
            PersistDecoys();
            return true;
        }

        public void Stop(int port)
        {
            if (_listeners.TryRemove(port, out var l))
            {
                l.Cts.Cancel();
                try { l.Tcp.Stop(); } catch { }
                PersistDecoys();
            }
        }

        public void StopAll()
        {
            foreach (var p in _listeners.Keys.ToList()) Stop(p);
        }

        // ── persistence / always-on sensor ─────────────────────────────────────
        /// <summary>Load persisted decoys and start them (called at launch so the honeypot runs unattended).</summary>
        public HoneypotConfig StartConfigured()
        {
            var cfg = HoneypotConfig.Load();
            _restoring = true;
            try { foreach (var d in cfg.Decoys) Start(d.Kind, d.Port, new DecoyOptions { Banner = d.Banner, HttpHtml = d.HttpHtml }); }
            finally { _restoring = false; }
            PersistDecoys();
            return cfg;
        }

        private void PersistDecoys()
        {
            if (_restoring) return;   // don't rewrite the file for each decoy while restoring
            var cfg = HoneypotConfig.Load();   // preserve FeedSiem
            cfg.Decoys = _listeners.Values
                .Select(l => new DecoySpec { Kind = l.Info.Kind, Port = l.Info.Port, Banner = l.Info.Options?.Banner, HttpHtml = l.Info.Options?.HttpHtml })
                .OrderBy(d => d.Port).ToList();
            cfg.Save();
        }

        private void TrackCreds(HoneypotHit hit)
        {
            if (!string.IsNullOrEmpty(hit.Username)) Bump(_byUser, hit.Username);
            if (!string.IsNullOrEmpty(hit.Password)) Bump(_byPass, hit.Password);
        }

        /// <summary>Increment a stat counter, capping the map's cardinality so it can't grow without bound.</summary>
        private void Bump(ConcurrentDictionary<string, long> map, string key)
        {
            map.AddOrUpdate(key, 1, (_, c) => c + 1);
            if (map.Count > MaxStatKeys) TrimSmallest(map);
        }

        /// <summary>Best-effort eviction of the lowest-count keys (keeps the top talkers, drops the long tail).</summary>
        private void TrimSmallest(ConcurrentDictionary<string, long> map)
        {
            if (Interlocked.Exchange(ref _trimming, 1) == 1) return;   // another thread is already trimming
            try
            {
                int target = MaxStatKeys * 9 / 10;
                foreach (var kv in map.OrderBy(kv => kv.Value).Take(map.Count - target).ToList())
                    map.TryRemove(kv.Key, out _);
            }
            catch { }
            finally { Interlocked.Exchange(ref _trimming, 0); }
        }

        private bool RateOk(string ip)
        {
            var now = DateTime.UtcNow;
            var e = _rate.AddOrUpdate(ip,
                _ => (now, 1),
                (_, cur) => (now - cur.windowStart) > TimeSpan.FromMinutes(1) ? (now, 1) : (cur.windowStart, cur.count + 1));
            PruneRates(now);
            return e.count <= MaxConnPerMinute;
        }

        /// <summary>Drop rate-limiter entries whose 1-minute window has elapsed, so one entry per source
        /// IP doesn't persist forever. Runs at most once a minute regardless of connection volume.</summary>
        private void PruneRates(DateTime now)
        {
            if ((now - _lastRatePrune) < TimeSpan.FromMinutes(1)) return;
            _lastRatePrune = now;
            foreach (var kv in _rate)
                if ((now - kv.Value.windowStart) > TimeSpan.FromMinutes(1))
                    _rate.TryRemove(kv.Key, out _);
        }

        public List<HoneypotHit> RecentHits(int n = 500)
        {
            lock (_lock) return _hits.Take(n).ToList();
        }

        public List<(string ip, long count)> TopAttackers(int n = 10)
            => _bySource.OrderByDescending(kv => kv.Value).Take(n).Select(kv => (kv.Key, kv.Value)).ToList();

        /// <summary>Most-tried usernames — the credential-intelligence "wall".</summary>
        public List<(string user, long count)> TopUsernames(int n = 10)
            => _byUser.OrderByDescending(kv => kv.Value).Take(n).Select(kv => (kv.Key, kv.Value)).ToList();

        /// <summary>Most-tried passwords.</summary>
        public List<(string pass, long count)> TopPasswords(int n = 10)
            => _byPass.OrderByDescending(kv => kv.Value).Take(n).Select(kv => (kv.Key, kv.Value)).ToList();

        // ── accept + dispatch ──────────────────────────────────────────────────
        private async Task AcceptLoop(Listener l)
        {
            var ct = l.Cts.Token;
            while (!ct.IsCancellationRequested)
            {
                TcpClient client;
                try { client = await l.Tcp.AcceptTcpClientAsync(ct).ConfigureAwait(false); }
                catch { break; }
                _ = HandleClient(l, client, ct);
            }
        }

        private async Task HandleClient(Listener l, TcpClient client, CancellationToken ct)
        {
            var remote = client.Client.RemoteEndPoint as IPEndPoint;
            var ip = remote?.Address.ToString() ?? "?";
            var sport = remote?.Port ?? 0;
            if (!RateOk(ip)) { Interlocked.Increment(ref _throttled); try { client.Close(); } catch { } return; }
            try
            {
                client.ReceiveTimeout = 15000; client.SendTimeout = 15000;
                using var stream = client.GetStream();
                using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
                linked.CancelAfter(TimeSpan.FromSeconds(120));   // long enough for a shell session; still bounded

                // Emulators report one or more hits over the session (e.g. login, then each command).
                void Report(HoneypotHit h) { h.Service = l.Info.Kind; h.Port = l.Info.Port; h.SourceIp = ip; h.SourcePort = sport; Record(l, h); }
                var opts = l.Info.Options;
                switch (l.Info.Kind)
                {
                    case HoneypotServiceKind.Telnet: await EmulateTelnet(stream, Report, opts, linked.Token); break;
                    case HoneypotServiceKind.Ftp:    await EmulateFtp(stream, Report, opts, linked.Token); break;
                    case HoneypotServiceKind.Http:   await EmulateHttp(stream, Report, opts, linked.Token); break;
                    case HoneypotServiceKind.Ssh:    await EmulateSsh(stream, Report, opts, linked.Token); break;
                    case HoneypotServiceKind.Redis:  await EmulateRedis(stream, Report, linked.Token); break;
                    case HoneypotServiceKind.Smtp:   await EmulateSmtp(stream, Report, opts, linked.Token); break;
                    case HoneypotServiceKind.Mysql:  await EmulateMysql(stream, Report, opts, linked.Token); break;
                    case HoneypotServiceKind.Rdp:    await EmulateRdp(stream, Report, linked.Token); break;
                    default:                         await EmulateRaw(stream, Report, linked.Token); break;
                }
            }
            catch { /* attacker hung up / timeout — best effort */ }
            finally { try { client.Close(); } catch { } }
        }

        private void Record(Listener l, HoneypotHit hit)
        {
            HoneypotClassifier.Apply(hit);
            Interlocked.Increment(ref _total);
            if (hit.HasCredentials) Interlocked.Increment(ref _creds);
            TrackCreds(hit);
            l.Info.Hits++;
            Bump(_bySource, hit.SourceIp);
            lock (_lock)
            {
                _hits.AddFirst(hit);
                while (_hits.Count > Capacity) _hits.RemoveLast();
            }
            try { HitRecorded?.Invoke(hit); } catch { }
        }

        /// <summary>Console side: record a hit streamed from a remote honeypot sensor (no local listener).</summary>
        public void InjectRemote(HoneypotHit hit)
        {
            if (hit == null) return;
            HoneypotClassifier.Apply(hit);
            Interlocked.Increment(ref _total);
            if (hit.HasCredentials) Interlocked.Increment(ref _creds);
            TrackCreds(hit);
            Bump(_bySource, string.IsNullOrEmpty(hit.SourceIp) ? "?" : hit.SourceIp);
            lock (_lock)
            {
                _hits.AddFirst(hit);
                while (_hits.Count > Capacity) _hits.RemoveLast();
            }
            try { HitRecorded?.Invoke(hit); } catch { }
        }

        // ── emulators (deliberately shallow: enough to bait + capture, never to be useful) ──
        private static async Task EmulateTelnet(NetworkStream s, Action<HoneypotHit> report, DecoyOptions? opts, CancellationToken ct)
        {
            string user = "", pass = "";
            var banner = string.IsNullOrEmpty(opts?.Banner) ? "Ubuntu 22.04.3 LTS" : opts!.Banner!;
            try
            {
                await Write(s, $"\r\n{banner}\r\nlogin: ", ct);
                user = (await ReadLine(s, ct)).Trim();
                await Write(s, "Password: ", ct);
                pass = (await ReadLine(s, ct)).Trim();
                // Report the login immediately so a login-only probe is captured without waiting.
                report(new HoneypotHit
                {
                    Username = user, Password = pass,
                    Summary = $"telnet login {Safe(user)}/{Safe(pass)}",
                    Severity = "High",
                    Data = $"login={Safe(user)} pass={Safe(pass)}",
                });

                // "Accept" the login and drop them into a fake shell — report each command they run.
                await Write(s, $"\r\nWelcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)\r\n\r\n{ShellUser(user)}@svr-01:~$ ", ct);
                for (int i = 0; i < 25; i++)
                {
                    var cmd = (await ReadLine(s, ct)).Trim();
                    if (cmd is "exit" or "logout" or "quit") break;
                    if (cmd.Length == 0) { await Write(s, $"{ShellUser(user)}@svr-01:~$ ", ct); continue; }
                    report(new HoneypotHit { Summary = $"telnet cmd: {Safe(cmd)}", Severity = "Medium", Data = cmd });
                    await Write(s, FakeShellResponse(cmd) + $"{ShellUser(user)}@svr-01:~$ ", ct);
                }
            }
            catch { /* connection dropped — we already reported what we captured */ }
        }

        private static string ShellUser(string user) => string.IsNullOrWhiteSpace(user) ? "root" : Safe(user);

        /// <summary>Plausible fake output so the attacker keeps interacting (and we keep capturing).</summary>
        private static string FakeShellResponse(string cmd)
        {
            var c = cmd.ToLowerInvariant();
            if (c == "whoami") return "root\r\n";
            if (c == "id") return "uid=0(root) gid=0(root) groups=0(root)\r\n";
            if (c.StartsWith("uname")) return "Linux svr-01 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux\r\n";
            if (c == "pwd") return "/root\r\n";
            if (c.StartsWith("ls")) return "backup.tar.gz  db.sql  notes.txt\r\n";
            if (c.StartsWith("cat /etc/passwd")) return "root:x:0:0:root:/root:/bin/bash\r\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\r\n";
            if (c.StartsWith("wget") || c.StartsWith("curl")) return "\r\n";   // pretend the download ran
            return "";
        }

        private static async Task EmulateFtp(NetworkStream s, Action<HoneypotHit> report, DecoyOptions? opts, CancellationToken ct)
        {
            await Write(s, (string.IsNullOrEmpty(opts?.Banner) ? "220 (vsFTPd 3.0.5)" : opts!.Banner!) + "\r\n", ct);
            string user = "", pass = "";
            try
            {
                for (int i = 0; i < 4; i++)
                {
                    var line = (await ReadLine(s, ct)).Trim();
                    if (line.Length == 0) break;
                    if (line.StartsWith("USER ", StringComparison.OrdinalIgnoreCase)) { user = line[5..]; await Write(s, "331 Please specify the password.\r\n", ct); }
                    else if (line.StartsWith("PASS ", StringComparison.OrdinalIgnoreCase)) { pass = line[5..]; await Write(s, "530 Login incorrect.\r\n", ct); break; }
                    else await Write(s, "530 Please login with USER and PASS.\r\n", ct);
                }
            }
            catch { }
            report(new HoneypotHit
            {
                Username = user, Password = pass,
                Summary = $"ftp login {Safe(user)}/{Safe(pass)}",
                Severity = "High",
                Data = $"USER {Safe(user)} PASS {Safe(pass)}",
            });
        }

        private static async Task EmulateHttp(NetworkStream s, Action<HoneypotHit> report, DecoyOptions? opts, CancellationToken ct)
        {
            var raw = await ReadBlock(s, ct);
            var firstLine = raw.Split('\n').FirstOrDefault()?.Trim() ?? "";
            string? user = null, pass = null;
            ExtractHttpCreds(raw, ref user, ref pass);

            try
            {
                if (!string.IsNullOrEmpty(opts?.HttpHtml))
                {
                    // Serve the operator's website — still captures the request/credentials.
                    var html = opts!.HttpHtml!;
                    await WriteUtf8(s,
                        "HTTP/1.1 200 OK\r\n" +
                        "Server: Apache/2.4.57 (Ubuntu)\r\n" +
                        "Content-Type: text/html; charset=utf-8\r\n" +
                        $"Content-Length: {Encoding.UTF8.GetByteCount(html)}\r\nConnection: close\r\n\r\n{html}", ct);
                }
                else
                {
                    var body = "<html><body><h1>401 Unauthorized</h1></body></html>";
                    await Write(s,
                        "HTTP/1.1 401 Unauthorized\r\n" +
                        "WWW-Authenticate: Basic realm=\"Admin\"\r\n" +
                        "Server: Apache/2.4.57 (Ubuntu)\r\n" +
                        $"Content-Length: {body.Length}\r\nConnection: close\r\n\r\n{body}", ct);
                }
            }
            catch { }

            bool creds = user != null || pass != null;
            report(new HoneypotHit
            {
                Username = user, Password = pass,
                Summary = creds ? $"http auth {Safe(user ?? "")}/{Safe(pass ?? "")}"
                                : (firstLine.Length > 0 ? $"http {Safe(firstLine)}" : "http probe"),
                Severity = (creds || raw.Contains("POST", StringComparison.OrdinalIgnoreCase)) ? "High" : "Medium",
                Data = Trunc(raw, 800),
            });
        }

        /// <summary>Pull credentials from an HTTP request: Basic-auth header or a urlencoded login form body.</summary>
        private static void ExtractHttpCreds(string raw, ref string? user, ref string? pass)
        {
            foreach (var line in raw.Split('\n'))
            {
                var t = line.Trim();
                int bi = t.IndexOf("Basic ", StringComparison.OrdinalIgnoreCase);
                if (t.StartsWith("Authorization:", StringComparison.OrdinalIgnoreCase) && bi >= 0)
                {
                    try
                    {
                        var dec = Encoding.ASCII.GetString(Convert.FromBase64String(t[(bi + 6)..].Trim()));
                        int c = dec.IndexOf(':');
                        if (c >= 0) { user = dec[..c]; pass = dec[(c + 1)..]; return; }
                    }
                    catch { }
                }
            }
            int blank = raw.IndexOf("\r\n\r\n", StringComparison.Ordinal);
            var bodyPart = blank >= 0 ? raw[(blank + 4)..] : "";
            if (bodyPart.Contains('='))
            {
                foreach (var kv in bodyPart.Split('&'))
                {
                    var p = kv.Split('=', 2);
                    if (p.Length != 2) continue;
                    var k = p[0].Trim().ToLowerInvariant();
                    var v = Uri.UnescapeDataString(p[1].Trim());
                    if (k is "user" or "username" or "login" or "email") user = v;
                    else if (k is "pass" or "password" or "passwd" or "pwd") pass = v;
                }
            }
        }

        private static async Task EmulateSsh(NetworkStream s, Action<HoneypotHit> report, DecoyOptions? opts, CancellationToken ct)
        {
            await Write(s, (string.IsNullOrEmpty(opts?.Banner) ? "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4" : opts!.Banner!) + "\r\n", ct);
            var banner = (await ReadLine(s, ct)).Trim();
            report(new HoneypotHit
            {
                Summary = banner.Length > 0 ? $"ssh client {Safe(banner)}" : "ssh probe",
                Severity = "Medium",
                Data = Trunc(banner, 200),
            });
        }

        private static async Task EmulateRaw(NetworkStream s, Action<HoneypotHit> report, CancellationToken ct)
        {
            var raw = await ReadBlock(s, ct);
            report(new HoneypotHit
            {
                Summary = raw.Length > 0 ? $"tcp payload ({raw.Length}b)" : "tcp connect",
                Severity = "Low",
                Data = Trunc(raw, 800),
            });
        }

        // ── Redis (RESP): capture commands incl. the CONFIG SET / SLAVEOF RCE tricks ──
        private static async Task EmulateRedis(NetworkStream s, Action<HoneypotHit> report, CancellationToken ct)
        {
            try
            {
                for (int i = 0; i < 40; i++)
                {
                    var cmd = await ReadRedisCommand(s, ct);
                    if (string.IsNullOrEmpty(cmd)) break;
                    var up = cmd.ToUpperInvariant();
                    string? user = null, pass = null;
                    if (up.StartsWith("AUTH "))
                    {
                        var rest = cmd[5..].Trim();
                        var sp = rest.Split(' ', 2);
                        if (sp.Length == 2) { user = sp[0]; pass = sp[1]; } else pass = rest;
                    }
                    report(new HoneypotHit
                    {
                        Username = user, Password = pass,
                        Summary = $"redis: {Safe(cmd)}",
                        Severity = "Medium",
                        Data = cmd,
                    });
                    await Write(s, RedisResponse(up), ct);
                    if (up.StartsWith("QUIT")) break;
                }
            }
            catch { }
        }

        private static async Task<string> ReadRedisCommand(NetworkStream s, CancellationToken ct)
        {
            var line = (await ReadLine(s, ct)).Trim();
            if (line.Length == 0) return "";
            if (line[0] == '*')
            {
                if (!int.TryParse(line[1..], out var n) || n <= 0 || n > 64) return line;
                var parts = new List<string>();
                for (int i = 0; i < n; i++)
                {
                    _ = await ReadLine(s, ct);                 // "$<len>"
                    parts.Add((await ReadLine(s, ct)).Trim());  // the argument
                }
                return string.Join(" ", parts);
            }
            return line;   // inline command
        }

        private static string RedisResponse(string up)
        {
            if (up.StartsWith("PING")) return "+PONG\r\n";
            if (up.StartsWith("INFO"))
            {
                var info = "# Server\r\nredis_version:6.2.6\r\nos:Linux\r\n# Keyspace\r\ndb0:keys=3,expires=0\r\n";
                return $"${info.Length}\r\n{info}\r\n";
            }
            if (up.StartsWith("CONFIG GET")) return "*2\r\n$3\r\ndir\r\n$5\r\n/root\r\n";
            if (up.StartsWith("GET ")) return "$-1\r\n";
            return "+OK\r\n";
        }

        // ── SMTP: capture AUTH credentials + MAIL/RCPT relay probing ──
        private static async Task EmulateSmtp(NetworkStream s, Action<HoneypotHit> report, DecoyOptions? opts, CancellationToken ct)
        {
            var banner = string.IsNullOrEmpty(opts?.Banner) ? "mail.example.com ESMTP Postfix" : opts!.Banner!;
            string? from = null, to = null;
            try
            {
                await Write(s, $"220 {banner}\r\n", ct);
                for (int i = 0; i < 25; i++)
                {
                    var line = (await ReadLine(s, ct)).Trim();
                    if (line.Length == 0) break;
                    var up = line.ToUpperInvariant();
                    if (up.StartsWith("EHLO") || up.StartsWith("HELO")) await Write(s, "250-mail.example.com\r\n250 AUTH LOGIN PLAIN\r\n", ct);
                    else if (up.StartsWith("AUTH LOGIN"))
                    {
                        await Write(s, "334 VXNlcm5hbWU6\r\n", ct);   // base64("Username:")
                        var u = B64Decode((await ReadLine(s, ct)).Trim());
                        await Write(s, "334 UGFzc3dvcmQ6\r\n", ct);   // base64("Password:")
                        var p = B64Decode((await ReadLine(s, ct)).Trim());
                        report(new HoneypotHit { Username = u, Password = p, Summary = $"smtp auth {Safe(u)}/{Safe(p)}", Severity = "High", Data = $"AUTH LOGIN {Safe(u)}:{Safe(p)}" });
                        await Write(s, "535 5.7.8 Authentication credentials invalid\r\n", ct);
                    }
                    else if (up.StartsWith("AUTH PLAIN"))
                    {
                        var b64 = line.Length > 11 ? line[11..].Trim() : (await ReadLine(s, ct)).Trim();
                        var dec = B64Decode(b64);
                        var parts = dec.Split('\0');
                        string u = parts.Length >= 2 ? parts[^2] : "", p = parts.Length >= 1 ? parts[^1] : "";
                        report(new HoneypotHit { Username = u, Password = p, Summary = $"smtp auth {Safe(u)}/{Safe(p)}", Severity = "High", Data = $"AUTH PLAIN {Safe(u)}:{Safe(p)}" });
                        await Write(s, "535 5.7.8 Authentication credentials invalid\r\n", ct);
                    }
                    else if (up.StartsWith("MAIL FROM")) { from = line; await Write(s, "250 2.1.0 Ok\r\n", ct); }
                    else if (up.StartsWith("RCPT TO")) { to = line; await Write(s, "250 2.1.5 Ok\r\n", ct); }
                    else if (up.StartsWith("DATA")) { await Write(s, "354 End data with <CR><LF>.<CR><LF>\r\n", ct); for (int j = 0; j < 50; j++) { var d = await ReadLine(s, ct); if (d.Trim() == "." || d.Length == 0) break; } await Write(s, "250 2.0.0 Ok: queued\r\n", ct); }
                    else if (up.StartsWith("QUIT")) { await Write(s, "221 2.0.0 Bye\r\n", ct); break; }
                    else await Write(s, "250 2.0.0 Ok\r\n", ct);
                }
            }
            catch { }
            if (from != null || to != null)
                report(new HoneypotHit { Summary = $"smtp relay {Safe(from ?? "")} -> {Safe(to ?? "")}", Severity = "Medium", Data = $"{from} | {to}" });
        }

        private static string B64Decode(string b64)
        {
            try { return Encoding.UTF8.GetString(Convert.FromBase64String(b64.Trim())); } catch { return b64; }
        }

        // ── MySQL: send a handshake, capture the login username from the client's response ──
        private static async Task EmulateMysql(NetworkStream s, Action<HoneypotHit> report, DecoyOptions? opts, CancellationToken ct)
        {
            string? user = null;
            try
            {
                await s.WriteAsync(BuildMysqlGreeting(opts?.Banner), ct); await s.FlushAsync(ct);
                var buf = new byte[1024];
                int n = await s.ReadAsync(buf.AsMemory(0, buf.Length), ct);
                const int off = 4 + 4 + 4 + 1 + 23;   // packet header + capabilities/maxpkt/charset/reserved
                if (n > off)
                {
                    var sb = new StringBuilder();
                    for (int i = off; i < n && buf[i] != 0 && sb.Length < 64; i++) sb.Append((char)buf[i]);
                    user = sb.ToString();
                }
                await s.WriteAsync(BuildMysqlError(), ct); await s.FlushAsync(ct);
            }
            catch { }
            report(new HoneypotHit
            {
                Username = user,
                Summary = string.IsNullOrEmpty(user) ? "mysql probe" : $"mysql login user={Safe(user)}",
                Severity = "High",
                Data = string.IsNullOrEmpty(user) ? "mysql connect" : $"user={Safe(user)}",
            });
        }

        private static byte[] BuildMysqlGreeting(string? version)
        {
            version = string.IsNullOrEmpty(version) ? "5.7.40" : version;
            var p = new List<byte> { 10 };                       // protocol version
            p.AddRange(Encoding.ASCII.GetBytes(version)); p.Add(0);
            p.AddRange(new byte[] { 1, 0, 0, 0 });               // thread id
            p.AddRange(Encoding.ASCII.GetBytes("abcdefgh")); p.Add(0);   // salt part 1 + filler
            p.AddRange(new byte[] { 0xff, 0xf7 });               // capability lower
            p.Add(0x21);                                          // charset
            p.AddRange(new byte[] { 0x02, 0x00 });               // status
            p.AddRange(new byte[] { 0xff, 0x81 });               // capability upper
            p.Add(21);                                            // auth-data len
            p.AddRange(new byte[10]);                             // reserved
            p.AddRange(Encoding.ASCII.GetBytes("ijklmnopqrst")); p.Add(0);   // salt part 2
            p.AddRange(Encoding.ASCII.GetBytes("mysql_native_password")); p.Add(0);
            return Packet(p.ToArray(), 0);
        }

        private static byte[] BuildMysqlError()
        {
            var body = new List<byte> { 0xff, 0x15, 0x04, (byte)'#' };   // ERR + code 1045
            body.AddRange(Encoding.ASCII.GetBytes("28000"));
            body.AddRange(Encoding.ASCII.GetBytes("Access denied for user"));
            return Packet(body.ToArray(), 2);
        }

        private static byte[] Packet(byte[] body, byte seq)
        {
            var pkt = new byte[4 + body.Length];
            pkt[0] = (byte)(body.Length & 0xff);
            pkt[1] = (byte)((body.Length >> 8) & 0xff);
            pkt[2] = (byte)((body.Length >> 16) & 0xff);
            pkt[3] = seq;
            Array.Copy(body, 0, pkt, 4, body.Length);
            return pkt;
        }

        // ── RDP: capture the mstshash username from the connection request ──
        private static async Task EmulateRdp(NetworkStream s, Action<HoneypotHit> report, CancellationToken ct)
        {
            var raw = await ReadBlock(s, ct);
            string? user = null;
            int idx = raw.IndexOf("mstshash=", StringComparison.OrdinalIgnoreCase);
            if (idx >= 0)
            {
                int start = idx + 9;
                int end = raw.IndexOfAny(new[] { '\r', '\n', ' ', '\0' }, start);
                user = end > start ? raw[start..end] : raw[start..];
            }
            try { await s.WriteAsync(new byte[] { 0x03, 0x00, 0x00, 0x0b, 0x06, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00 }, ct); await s.FlushAsync(ct); } catch { }
            report(new HoneypotHit
            {
                Username = user,
                Summary = user != null ? $"rdp login user={Safe(user)}" : "rdp probe",
                Severity = "High",
                Data = Trunc(raw, 200),
            });
        }

        // ── low-level helpers ──────────────────────────────────────────────────
        private static async Task Write(NetworkStream s, string text, CancellationToken ct)
        {
            var b = Encoding.ASCII.GetBytes(text);
            await s.WriteAsync(b, ct); await s.FlushAsync(ct);
        }

        private static async Task WriteUtf8(NetworkStream s, string text, CancellationToken ct)
        {
            var b = Encoding.UTF8.GetBytes(text);
            await s.WriteAsync(b, ct); await s.FlushAsync(ct);
        }

        private static async Task<string> ReadLine(NetworkStream s, CancellationToken ct)
        {
            var sb = new StringBuilder();
            var one = new byte[1];
            while (sb.Length < 512)
            {
                int n;
                try { n = await s.ReadAsync(one, ct); } catch { break; }
                if (n == 0) break;
                char c = (char)one[0];
                if (c == '\n') break;
                if (c != '\r') sb.Append(c);
            }
            return sb.ToString();
        }

        private static async Task<string> ReadBlock(NetworkStream s, CancellationToken ct)
        {
            var buf = new byte[MaxCapture];
            int total = 0;
            try
            {
                // one read is enough to capture the request/banner; give the client a brief moment
                int n = await s.ReadAsync(buf.AsMemory(0, buf.Length), ct);
                total = Math.Max(0, n);
            }
            catch { }
            return Encoding.ASCII.GetString(buf, 0, total);
        }

        private static string Trunc(string s, int max) => s.Length <= max ? s : s[..max] + "…";
        private static string Safe(string s) => Trunc(s.Replace("\r", " ").Replace("\n", " "), 128);
    }
}
