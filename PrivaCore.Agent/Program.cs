using System.Threading.Channels;
using PROSCANNERCONT.Models;
using PrivaCore.Agent;
using PrivaCore.ModuleSdk;

// ── PrivaCore Agent ──────────────────────────────────────────────────────────
// Cross-platform log shipper. Forwards local events to a PrivaCore SIEM collector.

const string ModuleKey = "SIEM";
const string IngestCommand = "siem.ingest";   // matches SiemModuleBridge.CmdIngest on the collector

Console.WriteLine();
Console.WriteLine("  ┌──────────────────────────────────────────────┐");
Console.WriteLine("  │  PrivaCore Agent  ·  SIEM log shipper          │");
Console.WriteLine("  └──────────────────────────────────────────────┘");
Console.WriteLine();

string configPath = GetArg(args, "--config") ?? AgentConfig.DefaultPath;
bool forceSetup = args.Contains("--setup");

var loaded = AgentConfig.Load(configPath);
var cfg = loaded ?? new AgentConfig();
ApplyOverrides(cfg, args);

// Need setup only when explicitly asked, or when there is neither a config file nor
// enough command-line args to bootstrap a connection.
bool argsBootstrap = args.Contains("--host") || args.Contains("--pairing");
if (forceSetup || (loaded == null && !argsBootstrap))
{
    var done = InteractiveSetup(cfg);
    if (done == null) { Console.WriteLine("  Setup cancelled."); return; }
    cfg = done;
}
if (loaded == null || forceSetup)
{
    cfg.Save(configPath);
    Console.WriteLine($"  Saved config → {configPath}");
}
else if (cfg.MigratedFromPlaintext)
{
    cfg.Save(configPath);   // re-write the old plaintext config with secrets encrypted at rest
    Console.WriteLine($"  ↻ Encrypted plaintext credentials in {configPath} (DPAPI/AES at rest).");
}

Console.WriteLine($"  Collector : {cfg.CollectorHost}:{cfg.CollectorPort}");
Console.WriteLine($"  Identity  : {cfg.MachineName}  (user '{cfg.Username}')");
Console.WriteLine($"  Sources   : heartbeat={cfg.Heartbeat}  generator={cfg.DemoGenerator}  tail={cfg.TailFiles.Count} file(s)");
Console.WriteLine("  Press Ctrl+C to stop.");
Console.WriteLine();

// Bounded queue: never block a source; drop oldest under sustained backpressure.
var queue = Channel.CreateBounded<SiemEvent>(new BoundedChannelOptions(5000)
{ FullMode = BoundedChannelFullMode.DropOldest, SingleReader = true });

using var appCts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; appCts.Cancel(); };

// Sources run under their own token so a pushed policy can restart them live.
CancellationTokenSource? sourcesCts = null;
long shippedCount = 0;
RestartSources();
await ConnectionLoop(cfg, queue.Reader, appCts.Token);

Console.WriteLine("  Agent stopped.");
return;

// ── Fleet: (re)start sources + apply a pushed policy ───────────────────────────
void RestartSources()
{
    sourcesCts?.Cancel();
    sourcesCts = CancellationTokenSource.CreateLinkedTokenSource(appCts.Token);
    StartSources(cfg, queue.Writer, sourcesCts.Token);
}

void ApplyPolicy(AgentPolicy p)
{
    cfg.Heartbeat = p.Heartbeat;
    cfg.HeartbeatSeconds = p.HeartbeatSeconds;
    cfg.DemoGenerator = p.DemoGenerator;
    cfg.TailFiles = p.TailFiles ?? new();
    cfg.Save(configPath);
    Console.WriteLine($"  ⟳ policy applied from collector: heartbeat={cfg.Heartbeat} gen={cfg.DemoGenerator} tail={cfg.TailFiles.Count} file(s)");
    RestartSources();
}

AgentEnrollInfo EnrollInfo(AgentConfig c) => new()
{
    Name = c.MachineName,
    Host = c.MachineName,
    Os = RuntimeInfo(),
    Version = typeof(AgentConfig).Assembly.GetName().Version?.ToString() ?? "1.0",
    Sources = $"heartbeat={c.Heartbeat} gen={c.DemoGenerator} tail={c.TailFiles.Count}",
};

// ── sources ──────────────────────────────────────────────────────────────────
void StartSources(AgentConfig c, ChannelWriter<SiemEvent> w, CancellationToken ct)
{
    if (c.Heartbeat)
        _ = Task.Run(async () =>
        {
            while (!ct.IsCancellationRequested)
            {
                w.TryWrite(Make(c, SiemSeverity.Info, "Agent", "Heartbeat",
                    $"Agent online on {c.MachineName} ({RuntimeInfo()}).", ("os", RuntimeInfo())));
                try { await Task.Delay(TimeSpan.FromSeconds(Math.Max(5, c.HeartbeatSeconds)), ct); } catch { break; }
            }
        }, ct);

    foreach (var file in c.TailFiles)
        _ = Task.Run(() => TailFile(c, file, w, ct), ct);

    if (c.DemoGenerator)
        _ = Task.Run(async () =>
        {
            var rng = new Random();
            string[] users = { "jdoe", "admin", "svc_app", "root", "guest" };
            while (!ct.IsCancellationRequested)
            {
                string ip = $"{rng.Next(10, 200)}.{rng.Next(0, 255)}.{rng.Next(0, 255)}.{rng.Next(1, 254)}";
                int p = rng.Next(100);
                var ev = p switch
                {
                    < 45 => Make(c, SiemSeverity.Info, "Authentication", "Successful Logon", $"User {users[rng.Next(users.Length)]} logged on from {ip}."),
                    < 70 => Make(c, SiemSeverity.High, "Authentication", "Failed Logon", $"Failed logon for {users[rng.Next(users.Length)]} from {ip}."),
                    < 85 => Make(c, SiemSeverity.Low, "Network", "FirewallBlock", $"Blocked inbound from {ip}."),
                    < 96 => Make(c, SiemSeverity.Medium, "Network", "PortScan", $"Possible port scan from {ip}."),
                    _ => Make(c, SiemSeverity.Critical, "Threat", "MalwareDetected", $"Malware signature match from {ip}."),
                };
                w.TryWrite(ev);
                try { await Task.Delay(rng.Next(700, 2200), ct); } catch { break; }
            }
        }, ct);
}

async Task TailFile(AgentConfig c, string path, ChannelWriter<SiemEvent> w, CancellationToken ct)
{
    Console.WriteLine($"  tailing: {path}");
    long pos = 0;
    bool first = true;
    while (!ct.IsCancellationRequested)
    {
        try
        {
            if (File.Exists(path))
            {
                using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                if (first) { pos = fs.Length; first = false; }          // start at EOF — only NEW lines
                if (fs.Length < pos) pos = 0;                            // file rotated / truncated
                fs.Seek(pos, SeekOrigin.Begin);
                using var sr = new StreamReader(fs);
                string? line;
                while ((line = await sr.ReadLineAsync(ct)) != null)
                {
                    if (line.Length == 0) continue;
                    w.TryWrite(MakeFromLine(c, path, line));
                }
                pos = fs.Position;
            }
        }
        catch { /* transient IO — retry */ }
        try { await Task.Delay(1000, ct); } catch { break; }
    }
}

// ── connection ───────────────────────────────────────────────────────────────
async Task ConnectionLoop(AgentConfig c, ChannelReader<SiemEvent> r, CancellationToken ct)
{
    int backoff = 2;
    while (!ct.IsCancellationRequested)
    {
        using var client = new ModuleClient();
        try
        {
            Console.Write($"  connecting to {c.CollectorHost}:{c.CollectorPort} … ");
            var probe = await client.ConnectAndProbeAsync(c.CollectorHost, c.CollectorPort, ModuleKey, 5000, ct);
            if (!probe.Reachable) { Console.WriteLine($"unreachable ({probe.Error}). retry in {backoff}s"); }
            else if (!probe.Running) { Console.WriteLine($"reachable but SIEM not running there. retry in {backoff}s"); }
            else
            {
                var login = await client.LoginAsync(c.Username, c.Password, c.PairingCode, ct);
                if (!login.Success) { Console.WriteLine($"login rejected ({login.Error}). retry in {backoff}s"); }
                else
                {
                    Console.WriteLine($"connected to '{probe.HostName}'. shipping events.");
                    backoff = 2;
                    using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    client.Disconnected += () => linked.Cancel();

                    // Fleet: handle pushed policy, enroll, and check in periodically.
                    void OnEvent(ModuleMessage m)
                    {
                        if (m.EventName != AgentProtocol.EvtPolicy) return;
                        var pj = m.Str("policy"); if (pj == null) return;
                        try { var p = System.Text.Json.JsonSerializer.Deserialize<AgentPolicy>(pj); if (p != null) ApplyPolicy(p); } catch { }
                    }
                    client.EventReceived += OnEvent;
                    try
                    {
                        await client.SendCommandAsync(AgentProtocol.CmdEnroll,
                            new() { ["info"] = System.Text.Json.JsonSerializer.Serialize(EnrollInfo(c)) }, linked.Token);
                        _ = CheckinLoop(client, linked.Token);
                        await PumpAsync(client, r, linked.Token);
                    }
                    finally { client.EventReceived -= OnEvent; }
                    Console.WriteLine("  disconnected.");
                }
            }
        }
        catch (OperationCanceledException) { break; }
        catch (Exception ex) { Console.WriteLine($"error: {ex.Message}"); }

        try { await Task.Delay(TimeSpan.FromSeconds(backoff), ct); } catch { break; }
        backoff = Math.Min(30, backoff * 2);
    }
}

async Task PumpAsync(ModuleClient client, ChannelReader<SiemEvent> r, CancellationToken ct)
{
    var lastReport = DateTime.UtcNow;
    try
    {
        while (await r.WaitToReadAsync(ct))
            while (r.TryRead(out var ev))
            {
                var json = System.Text.Json.JsonSerializer.Serialize(ev);
                await client.SendCommandAsync(IngestCommand, new() { ["ev"] = json }, ct);
                shippedCount++;
                if ((DateTime.UtcNow - lastReport).TotalSeconds >= 10)
                { Console.WriteLine($"  … {shippedCount} events shipped"); lastReport = DateTime.UtcNow; }
            }
    }
    catch (OperationCanceledException) { }
    catch (Exception ex) { Console.WriteLine($"  send failed: {ex.Message}"); }
}

// Periodic Fleet check-in so the collector can show this agent as online with live counts.
async Task CheckinLoop(ModuleClient client, CancellationToken ct)
{
    try
    {
        while (!ct.IsCancellationRequested)
        {
            try { await client.SendCommandAsync(AgentProtocol.CmdCheckin, new() { ["sent"] = shippedCount.ToString() }, ct); }
            catch { break; }
            await Task.Delay(TimeSpan.FromSeconds(20), ct);
        }
    }
    catch (OperationCanceledException) { }
}

// ── event factory ──────────────────────────────────────────────────────────────
static SiemEvent Make(AgentConfig c, SiemSeverity sev, string cat, string type, string msg, params (string, string)[] fields)
{
    var e = new SiemEvent
    {
        Timestamp = DateTime.Now, Source = c.MachineName, Host = c.MachineName,
        Severity = sev, Category = cat, EventType = type, Message = msg,
    };
    e.Fields["agent"] = c.MachineName;
    foreach (var (k, v) in fields) e.Fields[k] = v;
    return e;
}

static SiemEvent MakeFromLine(AgentConfig c, string path, string line)
{
    var sev = SeverityOf(line);
    var e = Make(c, sev, "Log", Path.GetFileName(path), line.Length > 600 ? line[..600] : line);
    e.Fields["file"] = path;
    e.Raw = line;
    return e;
}

static SiemSeverity SeverityOf(string line)
{
    var l = line.ToLowerInvariant();
    if (l.Contains("critical") || l.Contains("fatal") || l.Contains("emergency") || l.Contains("panic")) return SiemSeverity.Critical;
    if (l.Contains("error") || l.Contains("fail") || l.Contains("denied") || l.Contains("refused")) return SiemSeverity.High;
    if (l.Contains("warn")) return SiemSeverity.Medium;
    if (l.Contains("notice")) return SiemSeverity.Low;
    return SiemSeverity.Info;
}

static string RuntimeInfo() => $"{System.Runtime.InteropServices.RuntimeInformation.OSDescription.Trim()} / {System.Runtime.InteropServices.RuntimeInformation.OSArchitecture}";

// ── helpers: args + interactive setup ────────────────────────────────────────
static string? GetArg(string[] args, string name)
{
    int i = Array.IndexOf(args, name);
    return i >= 0 && i + 1 < args.Length ? args[i + 1] : null;
}

static void ApplyOverrides(AgentConfig c, string[] args)
{
    if (GetArg(args, "--host") is { } h) c.CollectorHost = h;
    if (GetArg(args, "--port") is { } p && int.TryParse(p, out var port)) c.CollectorPort = port;
    if (GetArg(args, "--user") is { } u) c.Username = u;
    if (GetArg(args, "--pass") is { } pw) c.Password = pw;
    if (GetArg(args, "--pairing") is { } pc) c.PairingCode = pc;
    if (GetArg(args, "--name") is { } n) c.MachineName = n;
    if (GetArg(args, "--tail") is { } t) c.TailFiles = t.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();
    if (args.Contains("--gen")) c.DemoGenerator = true;
}

static AgentConfig? InteractiveSetup(AgentConfig? existing)
{
    if (Console.IsInputRedirected)
    {
        Console.WriteLine("  No agent-config.json found and no interactive console.");
        Console.WriteLine("  Provide one, or pass: --host <ip> --port <n> --user <u> --pass <p> --pairing <code> [--gen] [--tail f1,f2]");
        return null;
    }
    var c = existing ?? new AgentConfig();
    Console.WriteLine("  First-run setup (press Enter to accept the [default]).");
    c.CollectorHost = Ask("Collector host/IP", c.CollectorHost);
    c.CollectorPort = int.TryParse(Ask("Collector port", c.CollectorPort.ToString()), out var p) ? p : c.CollectorPort;
    c.Username = Ask("Username", c.Username);
    c.Password = AskSecret("Password");
    c.PairingCode = Ask("Pairing code", c.PairingCode);
    c.MachineName = Ask("This machine's name", c.MachineName);
    var tail = Ask("Log files to ship (comma-separated, blank = none)", string.Join(",", c.TailFiles));
    c.TailFiles = tail.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();
    c.DemoGenerator = Ask("Emit demo events for testing? (y/N)", c.DemoGenerator ? "y" : "n").Trim().StartsWith("y", StringComparison.OrdinalIgnoreCase);
    return c;
}

static string Ask(string label, string def)
{
    Console.Write($"  {label} [{def}]: ");
    var s = Console.ReadLine();
    return string.IsNullOrWhiteSpace(s) ? def : s.Trim();
}

static string AskSecret(string label)
{
    Console.Write($"  {label}: ");
    var sb = new System.Text.StringBuilder();
    ConsoleKeyInfo k;
    while ((k = Console.ReadKey(true)).Key != ConsoleKey.Enter)
    {
        if (k.Key == ConsoleKey.Backspace) { if (sb.Length > 0) sb.Length--; }
        else if (!char.IsControl(k.KeyChar)) sb.Append(k.KeyChar);
    }
    Console.WriteLine();
    return sb.ToString();
}
