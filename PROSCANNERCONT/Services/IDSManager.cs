using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using PacketDotNet;
using SharpPcap;
using PROSCANNERCONT.Models;
using PROSCANNERCONT.Utils;

namespace PROSCANNERCONT.Services
{
    public class IDSEngine : IDisposable
    {
        // â”€â”€ Events â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        public event EventHandler<IDSAlert>? AlertGenerated;
        public event EventHandler<IDSStats>? StatsUpdated;
        public event EventHandler<CorrelationGroup>? KillChainDetected;

        /// <summary>
        /// When set, this engine is a CONSOLE-side mirror of a remote sensor: control
        /// actions (start/stop, rule edits) are forwarded to the remote via this sink
        /// instead of executed locally. Cleared when disconnecting.
        /// </summary>
        public Func<string, System.Collections.Generic.Dictionary<string, object>?, bool>? RemoteControl;

        /// <summary>Monitoring started/stopped — for live two-way state sync.</summary>
        public event EventHandler? RunningChanged;
        /// <summary>Rule set changed (add/update/delete/toggle) — for live two-way sync.</summary>
        public event EventHandler? RulesChanged;

        /// <summary>Console mirror of the remote sensor's capture interfaces.</summary>
        public List<string>? RemoteInterfaces;
        /// <summary>Remote interface list arrived/changed.</summary>
        public event EventHandler? InterfacesChanged;
        public void ApplyRemoteInterfaces(List<string> ifaces) { RemoteInterfaces = ifaces; InterfacesChanged?.Invoke(this, EventArgs.Empty); }

        private void NotifyRunning()
        {
            RunningChanged?.Invoke(this, EventArgs.Empty);
            try { StatsUpdated?.Invoke(this, GetStats()); } catch { }
        }

        /// <summary>Console-side: apply running state pushed by the remote sensor (no local capture).</summary>
        public void ApplyRemoteRunning(bool running) { _running = running; NotifyRunning(); }

        /// <summary>Console-side: apply the rule set pushed by the remote sensor.</summary>
        public void ApplyRemoteRules(string json)
        {
            try
            {
                var list = JsonSerializer.Deserialize<List<IDSRule>>(json, _importOpts);
                if (list != null) lock (_rulesLock) { _rules.Clear(); _rules.AddRange(list); }
            }
            catch { }
            RulesChanged?.Invoke(this, EventArgs.Empty);
        }

        // â”€â”€ Persistence paths â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        private readonly string _alertsPath, _rulesPath, _settingsPath, _allowlistPath, _blockedPath;

        // â”€â”€ Core collections â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        private readonly ObservableCollection<IDSAlert> _alerts = new();
        private readonly List<IDSRule>          _rules         = new();
        private readonly List<AllowlistEntry>   _allowlist     = new();
        private readonly List<BlockedIpEntry>   _blockedIps    = new();

        private readonly object _rulesLock     = new();
        private readonly object _alertsLock    = new();
        private readonly object _allowlistLock = new();
        private readonly object _blockedLock   = new();

        // â”€â”€ Capture â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        private ICaptureDevice? _device;
        private CancellationTokenSource? _cts;
        private bool _running;

        // â”€â”€ Behavioral counters (existing) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        private readonly ConcurrentDictionary<string, SlidingCounter> _synCounters  = new();
        private readonly ConcurrentDictionary<string, SlidingCounter> _icmpCounters = new();
        private readonly ConcurrentDictionary<string, SlidingCounter> _udpCounters  = new();
        private readonly ConcurrentDictionary<string, HashSet<int>>   _portScanSets = new();
        private readonly ConcurrentDictionary<string, DateTime>  _portScanWindows   = new();
        private readonly ConcurrentDictionary<string, SlidingCounter> _bruteForce   = new();
        private readonly ConcurrentDictionary<string, DateTime>  _recentAlerts      = new();

        // â”€â”€ New: per-rule alert-threshold counters â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        private readonly ConcurrentDictionary<Guid, SlidingCounter> _ruleCounters = new();

        // â”€â”€ New: ARP spoofing tracker (IP â†’ last-seen MAC) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        private readonly ConcurrentDictionary<string, string> _arpTable = new();

        // â”€â”€ New: kill-chain correlation (srcIP â†’ recent alert categories)
        private readonly ConcurrentDictionary<string, List<(string cat, DateTime when)>> _srcCorr = new();

        // â”€â”€ New: DNS high-query-rate counter â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        private readonly ConcurrentDictionary<string, SlidingCounter> _dnsRateCounters = new();

        // â”€â”€ Compiled regex cache â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        private readonly ConcurrentDictionary<string, Regex> _regexCache = new();

        // â”€â”€ Counters â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        private long _totalPackets, _totalThreats, _sigMatches;
        private long _arpAlerts, _ja3Alerts, _correlationAlerts;

        private volatile bool _alertsDirty, _rulesDirty, _allowlistDirty, _blockedDirty;
        private DateTime _lastPrune = DateTime.UtcNow;

        // â”€â”€ Behavioral thresholds (configurable) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        public int SynFloodThreshold   { get; set; } = 200;
        public int SynFloodWindowSec   { get; set; } = 5;
        public int IcmpFloodThreshold  { get; set; } = 100;
        public int IcmpFloodWindowSec  { get; set; } = 10;
        public int UdpFloodThreshold   { get; set; } = 500;
        public int UdpFloodWindowSec   { get; set; } = 5;
        public int PortScanThreshold   { get; set; } = 25;
        public int PortScanWindowSec   { get; set; } = 10;
        public int BruteForceThreshold { get; set; } = 10;
        public int BruteForceWindowSec { get; set; } = 60;

        // â”€â”€ IPS mode: auto-block Critical source IPs â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        public bool IpsMode { get; set; } = false;

        // â”€â”€ Kill-chain correlation window â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        private const int KillChainWindowSeconds = 300;

        public bool IsRunning => _running;
        public IReadOnlyList<IDSAlert>        Alerts    { get { lock (_alertsLock)    return _alerts.ToList(); } }
        public IReadOnlyList<IDSRule>         Rules     { get { lock (_rulesLock)     return _rules.ToList(); } }
        public IReadOnlyList<AllowlistEntry>  Allowlist { get { lock (_allowlistLock) return _allowlist.ToList(); } }
        public IReadOnlyList<BlockedIpEntry>  Blocked   { get { lock (_blockedLock)   return _blockedIps.ToList(); } }

        // â”€â”€ Constructor â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        public IDSEngine()
        {
            string dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "PrivaCore", "IDS");
            Directory.CreateDirectory(dir);
            _alertsPath    = Path.Combine(dir, "alerts.json");
            _rulesPath     = Path.Combine(dir, "rules.json");
            _settingsPath  = Path.Combine(dir, "behavioral_settings.json");
            _allowlistPath = Path.Combine(dir, "allowlist.json");
            _blockedPath   = Path.Combine(dir, "blocked.json");

            LoadBehavioralSettings();
            LoadAlerts();
            LoadRules();
            if (_rules.Count == 0) LoadDefaultRules();
            LoadAllowlist();
            LoadBlocked();

            // Background save + prune loop
            _ = Task.Run(async () =>
            {
                while (true)
                {
                    await Task.Delay(AppConstants.IDS.BackgroundSaveIntervalMs);
                    if (_alertsDirty)    { _alertsDirty    = false; SaveAlerts(); }
                    if (_rulesDirty)     { _rulesDirty     = false; SaveRules(); }
                    if (_allowlistDirty) { _allowlistDirty = false; SaveAllowlist(); }
                    if (_blockedDirty)   { _blockedDirty   = false; SaveBlocked(); }
                    if ((DateTime.UtcNow - _lastPrune).TotalSeconds >= AppConstants.IDS.TrackerPruneIntervalSec)
                    {
                        PruneTrackers();
                        _lastPrune = DateTime.UtcNow;
                    }
                }
            });
        }

        // â”€â”€ Capture control â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        public IEnumerable<string> GetInterfaces()
        {
            // Console mode: show the REMOTE sensor's interfaces, not this machine's.
            if (RemoteControl != null && RemoteInterfaces != null) return RemoteInterfaces;
            try { return CaptureDeviceList.Instance.Select(d => d.Description ?? d.Name); }
            catch { return Enumerable.Empty<string>(); }
        }

        /// <summary>Local capture interfaces (used by the sensor to advertise to consoles).</summary>
        public List<string> LocalInterfaces()
        {
            try { return CaptureDeviceList.Instance.Select(d => d.Description ?? d.Name).ToList(); }
            catch { return new List<string>(); }
        }

        public void StartCapture(int deviceIndex = 0)
        {
            if (RemoteControl != null) { RemoteControl(IdsModuleBridge.CmdStart, new() { ["device"] = deviceIndex }); return; }
            if (_running) return;
            var devices = CaptureDeviceList.Instance;
            if (devices.Count == 0) throw new InvalidOperationException("No capture devices found. Run as Administrator.");
            _device = devices[Math.Min(deviceIndex, devices.Count - 1)];
            _device.OnPacketArrival += OnPacketArrival;
            _device.Open(DeviceModes.Promiscuous, 1000);
            _cts = new CancellationTokenSource();
            _running = true;
            _device.StartCapture();
            NotifyRunning();
        }

        public void StopCapture()
        {
            if (RemoteControl != null) { RemoteControl(IdsModuleBridge.CmdStop, null); return; }
            if (!_running) return;
            _running = false;
            _cts?.Cancel();
            try { _device?.StopCapture(); _device?.Close(); _device?.Dispose(); }
            catch (Exception ex) { Debug.WriteLine($"[IDSEngine.StopCapture] {ex.Message}"); }
            _device = null;
            NotifyRunning();
        }

        // â”€â”€ Packet handler â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        private void OnPacketArrival(object sender, PacketCapture e)
        {
            try
            {
                Interlocked.Increment(ref _totalPackets);
                var raw    = e.GetPacket();
                var parsed = Packet.ParsePacket(raw.LinkLayerType, raw.Data);

                // â”€â”€ ARP spoofing detection â”€â”€
                var arp = parsed.Extract<ArpPacket>();
                if (arp != null) { DetectArpSpoofing(arp); }

                // â”€â”€ Try IPv4 then IPv6 â”€â”€
                var net4 = parsed.Extract<IPPacket>();
                var net6 = parsed.Extract<IPv6Packet>();
                if (net4 == null && net6 == null) return;

                string srcIP = (net4?.SourceAddress ?? net6!.SourceAddress)?.ToString() ?? "?";
                string dstIP = (net4?.DestinationAddress ?? net6!.DestinationAddress)?.ToString() ?? "?";
                string proto = "IP";
                int srcPort = 0, dstPort = 0;
                string payload = "";
                byte[] payloadBytes = Array.Empty<byte>();
                bool isSyn = false;
                int size = raw.Data.Length;

                var tcp = parsed.Extract<TcpPacket>();
                var udp = parsed.Extract<UdpPacket>();

                if (tcp != null)
                {
                    srcPort = tcp.SourcePort; dstPort = tcp.DestinationPort;
                    isSyn   = tcp.Synchronize && !tcp.Acknowledgment;
                    payloadBytes = tcp.PayloadData ?? Array.Empty<byte>();
                    payload = Encoding.Latin1.GetString(payloadBytes);
                    proto   = "TCP";
                }
                else if (udp != null)
                {
                    srcPort = udp.SourcePort; dstPort = udp.DestinationPort;
                    payloadBytes = udp.PayloadData ?? Array.Empty<byte>();
                    payload = Encoding.Latin1.GetString(payloadBytes);
                    proto   = "UDP";
                }
                else if (net4?.Protocol == ProtocolType.Icmp || net4?.Protocol == ProtocolType.IcmpV6
                      || net6?.NextHeader == ProtocolType.IcmpV6)
                {
                    proto = "ICMP";
                }

                var pkt = new NetPacket
                {
                    SrcIP = srcIP, DstIP = dstIP, SrcPort = srcPort, DstPort = dstPort,
                    Protocol = proto, Payload = payload, PayloadBytes = payloadBytes,
                    Size = size, IsSyn = isSyn,
                    HasNullFlags = tcp != null && !tcp.Synchronize && !tcp.Acknowledgment && !tcp.Finished && !tcp.Reset && !tcp.Push && !tcp.Urgent,
                    HasXmasFlags = tcp != null && tcp.Finished && tcp.Push && tcp.Urgent,
                    Timestamp = raw.Timeval.Date
                };

                // â”€â”€ JA3 + JA4 fingerprinting on TLS ClientHello â”€â”€
                string? ja3Hash = null, ja3Info = null;
                string? ja4Hash = null, ja4Info = null;
                if (proto == "TCP" && payloadBytes.Length > 5)
                {
                    Ja3Fingerprinter.TryExtract(payloadBytes, out ja3Hash, out ja3Info);
                    Ja4Fingerprinter.TryExtract(payloadBytes, out ja4Hash, out ja4Info);
                    if (ja3Hash != null) Interlocked.Increment(ref _ja3Alerts);
                }

                // â”€â”€ Behavioral detection â”€â”€
                DetectBehavioral(pkt);

                // â”€â”€ DNS tunneling behavioral detection â”€â”€
                if (proto == "UDP" && dstPort == 53 && payloadBytes.Length > 12)
                    DetectDnsTunneling(pkt);

                // â”€â”€ DoH / DoT detection â”€â”€
                if (proto == "TCP" && (dstPort == 443 || dstPort == 853))
                {
                    var hit = DohDetector.Detect(dstIP, dstPort);
                    if (hit != null) DetectEncryptedDns(pkt, hit);
                }

                // â”€â”€ Kerberos attack detection â”€â”€
                if ((dstPort == 88 || srcPort == 88) && payloadBytes.Length > 8)
                    DetectKerberosAttacks(pkt);

                // â”€â”€ Signature matching â”€â”€
                lock (_rulesLock)
                    foreach (var rule in _rules.Where(r => r.IsEnabled && r.RuleKind == RuleKind.Signature))
                        if (MatchesRule(pkt, rule))
                        {
                            var alert = BuildAlert(rule, pkt);
                            if (ja3Hash != null) { alert.JA3Hash = ja3Hash; alert.JA3Info = ja3Info ?? ""; }
                            if (ja4Hash != null) { alert.JA4Hash = ja4Hash; alert.JA4String = ja4Info; }
                            RaiseAlert(rule, pkt, alert);
                        }

                if (_totalPackets % 50 == 0) StatsUpdated?.Invoke(this, GetStats());
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[IDSEngine.OnPacketArrival] {ex.Message}");
            }
        }

        // â”€â”€ ARP spoofing detection â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        private void DetectArpSpoofing(ArpPacket arp)
        {
            if (arp.Operation != ArpOperation.Response) return;
            string ip  = arp.SenderProtocolAddress?.ToString() ?? "";
            string mac = arp.SenderHardwareAddress?.ToString() ?? "";
            if (string.IsNullOrEmpty(ip) || string.IsNullOrEmpty(mac)) return;

            if (_arpTable.TryGetValue(ip, out var knownMac) && knownMac != mac)
            {
                Interlocked.Increment(ref _arpAlerts);
                string key = $"ARP:{ip}:{mac}";
                if (!_recentAlerts.TryGetValue(key, out var last) || (DateTime.UtcNow - last).TotalSeconds > 60)
                {
                    _recentAlerts[key] = DateTime.UtcNow;
                    EmitAlert(new IDSAlert
                    {
                        AlertId = Guid.NewGuid(), Timestamp = DateTime.Now,
                        SourceIP = ip, DestinationIP = "broadcast",
                        Protocol = "ARP", Severity = IDSAlertSeverity.Critical,
                        AlertType = "ARP Spoofing Detected",
                        Description = $"IP {ip} changed MAC from {knownMac} to {mac} â€” possible MITM attack",
                        RuleId = "BEHAVIORAL-ARP", AttackCategory = "MITM"
                    });
                }
            }
            _arpTable[ip] = mac;
        }

        // â”€â”€ DNS tunneling (proper DNS question name parsing) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        private void DetectDnsTunneling(NetPacket pkt)
        {
            try
            {
                var b = pkt.PayloadBytes;
                if (b.Length < 12) return;

                // Parse DNS questions section
                int qdCount = (b[4] << 8) | b[5];
                if (qdCount == 0) return;

                int offset = 12;
                var labels = new List<string>();
                while (offset < b.Length)
                {
                    int len = b[offset++];
                    if (len == 0) break;
                    if (len > 63 || offset + len > b.Length) return;
                    labels.Add(Encoding.ASCII.GetString(b, offset, len));
                    offset += len;
                }

                if (labels.Count == 0) return;

                string subdomain = string.Join(".", labels.Take(labels.Count - 1));
                double entropy = ShannonEntropy(subdomain);

                bool isSuspicious = subdomain.Length > 40 || entropy > 3.5;
                if (!isSuspicious) return;

                // Rate-limit: max 1 DNS tunneling alert per source per 60s
                var c = _dnsRateCounters.GetOrAdd(pkt.SrcIP, _ => new SlidingCounter(TimeSpan.FromSeconds(60)));
                if (c.Increment() > 3) return;

                RaiseBehavioralAlert("DNS Tunneling / Data Exfiltration", IDSAlertSeverity.High,
                    $"Source {pkt.SrcIP} queried '{subdomain}' (len={subdomain.Length} entropy={entropy:F2}) â€” possible DNS tunnel",
                    pkt, "Exfiltration");
            }
            catch { }
        }

        // ── Kerberos attack heuristics ──────────────────────────────────────
        // Kerberos messages are ASN.1 DER over TCP/88 with a 4-byte length prefix.
        //   * AS-REQ  (asn1 tag 0x6A): if PA-DATA section is missing pre-auth,
        //     the account is AS-REP roastable.
        //   * TGS-REQ (asn1 tag 0x6C) burst from same source: kerberoasting
        //     enumeration of SPNs.
        //   * AS-REP / TGS-REP with etype 23 (rc4-hmac-md5 = 0x17): classic
        //     Kerberoast / AS-REP-roast offline-crackable response.
        private readonly ConcurrentDictionary<string, SlidingCounter> _tgsRequestCounters = new();
        private void DetectKerberosAttacks(NetPacket pkt)
        {
            try
            {
                var b = pkt.PayloadBytes;
                // Optional 4-byte TCP length prefix for Kerberos-over-TCP.
                int off = (b.Length > 8 && b[0] == 0x00 && b[1] == 0x00) ? 4 : 0;
                if (off + 1 >= b.Length) return;

                byte tag = b[off];

                // RC4-HMAC etype 0x17 anywhere in the message body is a strong
                // indicator of an AS-REP / TGS-REP that is offline-crackable.
                bool hasRc4 = ContainsRc4Etype(b, off);

                if (tag == 0x6A) // AS-REQ
                {
                    // AS-REP roastable: AS-REQ with no PA-ENC-TIMESTAMP pre-auth (tag 0x02 inside PA-DATA).
                    // A simple heuristic: AS-REQ < 200 bytes and no 0x02 pa-type byte.
                    if (b.Length - off < 200 && !ContainsByteSeq(b, off, new byte[] { 0xa1, 0x05, 0x02, 0x01, 0x02 }))
                    {
                        RaiseBehavioralAlert("Kerberos AS-REP Roastable Request",
                            IDSAlertSeverity.High,
                            $"{pkt.SrcIP} sent AS-REQ without pre-auth — account is AS-REP roastable",
                            pkt, "AS-REP Roast");
                    }
                }
                else if (tag == 0x6C) // TGS-REQ
                {
                    var c = _tgsRequestCounters.GetOrAdd(pkt.SrcIP, _ => new SlidingCounter(TimeSpan.FromMinutes(2)));
                    int count = c.Increment();
                    if (count == 15)
                    {
                        RaiseBehavioralAlert("Kerberoasting Enumeration",
                            IDSAlertSeverity.High,
                            $"{pkt.SrcIP} requested {count} TGS tickets in 2 min — possible kerberoast SPN enumeration",
                            pkt, "Kerberoast");
                    }
                }
                else if ((tag == 0x6B || tag == 0x6D) && hasRc4) // AS-REP or TGS-REP with RC4
                {
                    string kind = tag == 0x6B ? "AS-REP" : "TGS-REP";
                    RaiseBehavioralAlert($"Kerberos {kind} with RC4 etype",
                        IDSAlertSeverity.Medium,
                        $"{pkt.DstIP} received {kind} using deprecated RC4-HMAC — crackable offline",
                        pkt, "Kerberoast");
                }
            }
            catch (Exception ex) { Debug.WriteLine($"[DetectKerberosAttacks] {ex.Message}"); }
        }

        private static bool ContainsRc4Etype(byte[] b, int start)
        {
            // Look for an INTEGER (tag 0x02) of length 1 with value 0x17 (= 23 = RC4-HMAC-MD5).
            for (int i = start; i < b.Length - 2; i++)
                if (b[i] == 0x02 && b[i + 1] == 0x01 && b[i + 2] == 0x17) return true;
            return false;
        }

        private static bool ContainsByteSeq(byte[] data, int start, byte[] seq)
        {
            for (int i = start; i <= data.Length - seq.Length; i++)
            {
                bool ok = true;
                for (int j = 0; j < seq.Length; j++) if (data[i + j] != seq[j]) { ok = false; break; }
                if (ok) return true;
            }
            return false;
        }

        // Rate-limited encrypted-DNS alert — fires once per source IP per hour.
        private void DetectEncryptedDns(NetPacket pkt, DohDetector.EncryptedDnsHit hit)
        {
            string key = $"DOH:{pkt.SrcIP}:{hit.Provider}";
            if (_recentAlerts.TryGetValue(key, out var last) && (DateTime.UtcNow - last).TotalMinutes < 60) return;
            _recentAlerts[key] = DateTime.UtcNow;
            RaiseBehavioralAlert(
                $"Encrypted DNS ({hit.Protocol}) to {hit.Provider}",
                IDSAlertSeverity.Medium,
                $"Source {pkt.SrcIP} is using {hit.Protocol} via {hit.Provider} ({pkt.DstIP}:{hit.Port}) — DNS queries bypass local resolver logging",
                pkt, "DNS Tunneling");
        }

        private static double ShannonEntropy(string s)
        {
            if (string.IsNullOrEmpty(s)) return 0;
            var freq = new Dictionary<char, int>();
            foreach (var c in s) freq[c] = freq.TryGetValue(c, out int v) ? v + 1 : 1;
            double e = 0;
            foreach (var f in freq.Values)
            {
                double p = (double)f / s.Length;
                e -= p * Math.Log2(p);
            }
            return e;
        }

        // â”€â”€ Behavioral detection (original 5 + expanded) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        private void DetectBehavioral(NetPacket pkt)
        {
            // SYN flood
            if (pkt.IsSyn)
            {
                var c = _synCounters.GetOrAdd(pkt.SrcIP, _ => new SlidingCounter(TimeSpan.FromSeconds(SynFloodWindowSec)));
                if (c.Increment() > SynFloodThreshold)
                    RaiseBehavioralAlert("SYN Flood Detected", IDSAlertSeverity.Critical,
                        $"Source {pkt.SrcIP} sent >{SynFloodThreshold} SYN packets in {SynFloodWindowSec}s", pkt, "DoS/DDoS");
            }
            // ICMP flood
            if (pkt.Protocol == "ICMP")
            {
                var c = _icmpCounters.GetOrAdd(pkt.SrcIP, _ => new SlidingCounter(TimeSpan.FromSeconds(IcmpFloodWindowSec)));
                if (c.Increment() > IcmpFloodThreshold)
                    RaiseBehavioralAlert("ICMP Flood Detected", IDSAlertSeverity.High,
                        $"Source {pkt.SrcIP} sent >{IcmpFloodThreshold} ICMP packets in {IcmpFloodWindowSec}s", pkt, "DoS/DDoS");
            }
            // UDP flood
            if (pkt.Protocol == "UDP")
            {
                var c = _udpCounters.GetOrAdd(pkt.SrcIP, _ => new SlidingCounter(TimeSpan.FromSeconds(UdpFloodWindowSec)));
                if (c.Increment() > UdpFloodThreshold)
                    RaiseBehavioralAlert("UDP Flood Detected", IDSAlertSeverity.High,
                        $"Source {pkt.SrcIP} sent >{UdpFloodThreshold} UDP packets in {UdpFloodWindowSec}s", pkt, "DoS/DDoS");
            }
            // Port scan
            if (pkt.Protocol == "TCP" && pkt.DstPort > 0)
            {
                var now = DateTime.UtcNow;
                var set = _portScanSets.GetOrAdd(pkt.SrcIP, _ => new HashSet<int>());
                lock (set)
                {
                    _portScanWindows.TryGetValue(pkt.SrcIP, out var windowStart);
                    if (windowStart == default || (now - windowStart).TotalSeconds > PortScanWindowSec)
                    { set.Clear(); _portScanWindows[pkt.SrcIP] = now; }
                    set.Add(pkt.DstPort);
                    if (set.Count > PortScanThreshold)
                    {
                        RaiseBehavioralAlert("Port Scan Detected", IDSAlertSeverity.Medium,
                            $"Source {pkt.SrcIP} scanned >{PortScanThreshold} distinct ports in {PortScanWindowSec}s", pkt, "Reconnaissance");
                        set.Clear(); _portScanWindows[pkt.SrcIP] = now;
                    }
                }
            }
            // Brute force (SYN-based)
            if (pkt.Protocol == "TCP" && pkt.DstPort > 0 && pkt.IsSyn)
            {
                string key = $"{pkt.SrcIP}:{pkt.DstPort}";
                var c = _bruteForce.GetOrAdd(key, _ => new SlidingCounter(TimeSpan.FromSeconds(BruteForceWindowSec)));
                int count = c.Increment();
                if (count == BruteForceThreshold)
                {
                    string svc = pkt.DstPort switch
                    {
                        22 => "SSH", 21 => "FTP", 23 => "Telnet", 3389 => "RDP",
                        5900 => "VNC", 25 => "SMTP", 110 => "POP3", 143 => "IMAP",
                        1433 => "MSSQL", 3306 => "MySQL", 5432 => "PostgreSQL",
                        _ => $"Port {pkt.DstPort}"
                    };
                    RaiseBehavioralAlert($"{svc} Brute Force Detected", IDSAlertSeverity.High,
                        $"Source {pkt.SrcIP} made {count} connection attempts to {svc} ({pkt.DstIP}:{pkt.DstPort}) in {BruteForceWindowSec}s",
                        pkt, "Brute Force");
                }
            }
        }

        // â”€â”€ Signature matching â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        private bool MatchesRule(NetPacket pkt, IDSRule rule)
        {
            if (!string.IsNullOrEmpty(rule.Protocol) && !rule.Protocol.Equals("any", StringComparison.OrdinalIgnoreCase) && !rule.Protocol.Equals(pkt.Protocol, StringComparison.OrdinalIgnoreCase)) return false;
            if (!string.IsNullOrEmpty(rule.SourceIP) && !rule.SourceIP.Equals("any", StringComparison.OrdinalIgnoreCase) && !IpMatches(pkt.SrcIP, rule.SourceIP)) return false;
            if (!string.IsNullOrEmpty(rule.DestinationIP) && !rule.DestinationIP.Equals("any", StringComparison.OrdinalIgnoreCase) && !IpMatches(pkt.DstIP, rule.DestinationIP)) return false;
            if (!string.IsNullOrEmpty(rule.DestinationPort) && !rule.DestinationPort.Equals("any", StringComparison.OrdinalIgnoreCase) && !PortMatches(pkt.DstPort, rule.DestinationPort)) return false;
            if (!string.IsNullOrEmpty(rule.SourcePort) && !rule.SourcePort.Equals("any", StringComparison.OrdinalIgnoreCase) && !PortMatches(pkt.SrcPort, rule.SourcePort)) return false;
            if (!string.IsNullOrEmpty(rule.Pattern))
            {
                if (string.IsNullOrEmpty(pkt.Payload)) return false;
                var rx = _regexCache.GetOrAdd(rule.Pattern, p =>
                    new Regex(p, RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.Compiled));
                if (!rx.IsMatch(pkt.Payload)) return false;
            }
            if (rule.RequireNullFlags && !pkt.HasNullFlags) return false;
            if (rule.RequireXmasFlags && !pkt.HasXmasFlags) return false;
            if (rule.MinPacketSize > 0 && pkt.Size < rule.MinPacketSize) return false;
            if (rule.MaxPacketSize > 0 && pkt.Size > rule.MaxPacketSize) return false;
            return true;
        }

        private static bool IpMatches(string ip, string pattern)
        {
            if (!pattern.Contains("/")) return string.Equals(ip, pattern, StringComparison.OrdinalIgnoreCase);
            try
            {
                var parts = pattern.Split("/");
                int prefix = int.Parse(parts[1]);
                uint mask = prefix == 0 ? 0 : (0xFFFFFFFFu << (32 - prefix));
                uint n = BitConverter.ToUInt32(IPAddress.Parse(parts[0]).GetAddressBytes().Reverse().ToArray(), 0) & mask;
                uint a = BitConverter.ToUInt32(IPAddress.Parse(ip).GetAddressBytes().Reverse().ToArray(), 0) & mask;
                return n == a;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[IDSEngine.IpMatches] pattern={pattern} ip={ip}: {ex.Message}");
                return false;
            }
        }

        private static bool PortMatches(int port, string spec)
        {
            foreach (var part in spec.Split(","))
            {
                var t = part.Trim();
                if (t.Contains(":")) { var r = t.Split(":"); if (int.TryParse(r[0], out int lo) && int.TryParse(r[1], out int hi) && port >= lo && port <= hi) return true; }
                else if (int.TryParse(t, out int p) && p == port) return true;
            }
            return false;
        }

        // â”€â”€ Alert raising â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        private IDSAlert BuildAlert(IDSRule rule, NetPacket pkt)
        {
            var alert = new IDSAlert
            {
                AlertId = Guid.NewGuid(), Timestamp = DateTime.Now,
                SourceIP = pkt.SrcIP, DestinationIP = pkt.DstIP,
                SourcePort = pkt.SrcPort, DestinationPort = pkt.DstPort,
                Protocol = pkt.Protocol, Severity = rule.Severity,
                AlertType = rule.Name, Description = rule.Description,
                RuleId = rule.RuleId, AttackCategory = rule.AttackCategory,
                PayloadPreview = pkt.Payload.Length > 200 ? pkt.Payload[..200] : pkt.Payload,
                PacketSize = pkt.Size
            };
            ApplyMitreMapping(alert, rule.MitreTechniqueId, rule.MitreTactic, rule.AttackCategory);
            return alert;
        }

        // Centralised so signature, behavioural, and HIDS alerts all populate
        // MITRE fields the same way: explicit rule mapping wins, otherwise we
        // fall back to category → technique resolution.
        private static void ApplyMitreMapping(IDSAlert alert, string? explicitId, string? explicitTactic, string? category)
        {
            string? techId   = explicitId;
            string? tactic   = explicitTactic;
            if (string.IsNullOrEmpty(techId))
            {
                var (mappedId, mappedTactic) = MitreReferenceService.FromCategory(category);
                techId ??= mappedId;
                tactic ??= mappedTactic;
            }
            if (!string.IsNullOrEmpty(techId))
            {
                alert.MitreTechniqueId = techId;
                var info = MitreReferenceService.Get(techId);
                if (info != null)
                {
                    alert.MitreTechniqueName = info.Name;
                    alert.MitreTactic = string.IsNullOrEmpty(tactic) ? info.Tactic : tactic;
                }
                else if (!string.IsNullOrEmpty(tactic))
                {
                    alert.MitreTactic = tactic;
                }
            }
        }

        private void RaiseAlert(IDSRule rule, NetPacket pkt, IDSAlert alert)
        {
            // Per-rule deduplication (10s cooldown for same rule+src+dstPort)
            string dedupKey = $"{rule.RuleId}:{pkt.SrcIP}:{pkt.DstPort}";
            if (_recentAlerts.TryGetValue(dedupKey, out var last) && (DateTime.UtcNow - last).TotalSeconds < AppConstants.IDS.AlertDedupCooldownSec) return;
            _recentAlerts[dedupKey] = DateTime.UtcNow;

            // Per-rule alert threshold check
            if (rule.AlertThreshold > 0)
            {
                var counter = _ruleCounters.GetOrAdd(rule.Id, _ => new SlidingCounter(TimeSpan.FromSeconds(rule.AlertWindowSec)));
                if (counter.Increment() < rule.AlertThreshold) return;
            }

            EmitAlert(alert);
            Interlocked.Increment(ref _sigMatches);
            rule.TriggerCount++; rule.LastTriggered = DateTime.Now;
        }

        private void RaiseBehavioralAlert(string name, IDSAlertSeverity sev, string desc, NetPacket pkt, string cat)
        {
            string key = $"BEH:{name}:{pkt.SrcIP}";
            if (_recentAlerts.TryGetValue(key, out var last) && (DateTime.UtcNow - last).TotalSeconds < AppConstants.IDS.BehavioralAlertCooldownSec) return;
            _recentAlerts[key] = DateTime.UtcNow;
            var alert = new IDSAlert
            {
                AlertId = Guid.NewGuid(), Timestamp = DateTime.Now,
                SourceIP = pkt.SrcIP, DestinationIP = pkt.DstIP,
                SourcePort = pkt.SrcPort, DestinationPort = pkt.DstPort,
                Protocol = pkt.Protocol, Severity = sev,
                AlertType = name, Description = desc,
                RuleId = "BEHAVIORAL", AttackCategory = cat, PacketSize = pkt.Size
            };
            ApplyMitreMapping(alert, null, null, cat);
            EmitAlert(alert);
        }

        private void EmitAlert(IDSAlert alert)
        {
            // â”€â”€ Allowlist check â”€â”€
            if (IsAllowlisted(alert.SourceIP, alert.RuleId)) return;

            // ── Threat-intel enrichment — bump severity if source IP is on a feed ──
            try
            {
                var tiTag = ThreatIntelService.Instance.Lookup(alert.SourceIP, "ip");
                if (!string.IsNullOrEmpty(tiTag))
                {
                    alert.ThreatIntelTags = tiTag;
                    if (alert.Severity < IDSAlertSeverity.High) alert.Severity = IDSAlertSeverity.High;
                }
            }
            catch { /* TI failures must never break alert flow */ }

            lock (_alertsLock) { _alerts.Insert(0, alert); if (_alerts.Count > AppConstants.IDS.MaxAlertsInMemory) _alerts.RemoveAt(_alerts.Count - 1); }
            Interlocked.Increment(ref _totalThreats);
            _alertsDirty = true;
            AlertGenerated?.Invoke(this, alert);

            // â”€â”€ IPS mode: auto-block Critical â”€â”€
            if (IpsMode && alert.Severity == IDSAlertSeverity.Critical)
                AutoBlock(alert);

            // â”€â”€ Kill-chain correlation â”€â”€
            TrackCorrelation(alert);
        }

        // â”€â”€ Allowlist â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        private bool IsAllowlisted(string srcIp, string ruleId)
        {
            lock (_allowlistLock)
                return _allowlist.Any(e =>
                    !e.IsExpired &&
                    IpMatches(srcIp, e.IpOrCidr) &&
                    (string.IsNullOrEmpty(e.RuleId) || e.RuleId == ruleId));
        }

        public void AddAllowlistEntry(AllowlistEntry entry)
        {
            lock (_allowlistLock) _allowlist.Add(entry);
            _allowlistDirty = true;
        }

        public void RemoveAllowlistEntry(Guid id)
        {
            lock (_allowlistLock) { var e = _allowlist.FirstOrDefault(x => x.Id == id); if (e != null) _allowlist.Remove(e); }
            _allowlistDirty = true;
        }

        // â”€â”€ IPS: Windows Firewall auto-block â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        private void AutoBlock(IDSAlert alert)
        {
            if (string.IsNullOrEmpty(alert.SourceIP) || alert.SourceIP == "?") return;
            lock (_blockedLock)
            {
                if (_blockedIps.Any(b => b.IP == alert.SourceIP)) return;
                if (IpsBlocklistService.BlockIp(alert.SourceIP, out _))
                {
                    _blockedIps.Add(new BlockedIpEntry { IP = alert.SourceIP, Reason = alert.AlertType, AlertType = alert.AttackCategory });
                    _blockedDirty = true;
                    alert.IsBlocked = true;
                }
            }
        }

        public bool ManualBlock(string ip, string reason, out string error)
        {
            if (IpsBlocklistService.BlockIp(ip, out error))
            {
                lock (_blockedLock) _blockedIps.Add(new BlockedIpEntry { IP = ip, Reason = reason, AlertType = "Manual" });
                _blockedDirty = true;
                return true;
            }
            return false;
        }

        public bool ManualUnblock(string ip, out string error)
        {
            if (IpsBlocklistService.UnblockIp(ip, out error))
            {
                lock (_blockedLock) { var e = _blockedIps.FirstOrDefault(b => b.IP == ip); if (e != null) _blockedIps.Remove(e); }
                _blockedDirty = true;
                return true;
            }
            return false;
        }

        // â”€â”€ Kill-chain correlation â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        private static readonly string[] _reconCats    = { "Reconnaissance" };
        private static readonly string[] _exploitCats  = { "Web Attack", "Exploit" };
        private static readonly string[] _c2Cats       = { "Malware/C2", "Brute Force" };

        private void TrackCorrelation(IDSAlert alert)
        {
            if (string.IsNullOrEmpty(alert.SourceIP) || alert.SourceIP == "?") return;

            var list = _srcCorr.GetOrAdd(alert.SourceIP, _ => new List<(string, DateTime)>());
            lock (list)
            {
                var cutoff = DateTime.Now.AddSeconds(-KillChainWindowSeconds);
                list.RemoveAll(x => x.when < cutoff);
                list.Add((alert.AttackCategory ?? "Unknown", alert.Timestamp));

                var cats = list.Select(x => x.cat).Distinct().ToHashSet();
                bool hasRecon   = cats.Any(c => _reconCats.Any(r => c.Contains(r, StringComparison.OrdinalIgnoreCase)));
                bool hasExploit = cats.Any(c => _exploitCats.Any(r => c.Contains(r, StringComparison.OrdinalIgnoreCase)));
                bool hasC2      = cats.Any(c => _c2Cats.Any(r => c.Contains(r, StringComparison.OrdinalIgnoreCase)));

                if (hasRecon && hasExploit && hasC2)
                {
                    string corrKey = $"KILLCHAIN:{alert.SourceIP}";
                    if (!_recentAlerts.TryGetValue(corrKey, out var lastCorr) || (DateTime.UtcNow - lastCorr).TotalSeconds > 300)
                    {
                        _recentAlerts[corrKey] = DateTime.UtcNow;
                        Interlocked.Increment(ref _correlationAlerts);
                        var group = new CorrelationGroup
                        {
                            SourceIP     = alert.SourceIP,
                            AlertCount   = list.Count,
                            Categories   = string.Join(" â†’ ", cats),
                            MaxSeverity  = "Critical",
                            MaxSeverityColor = "#F44747",
                            FirstSeen    = list.Min(x => x.when),
                            LastSeen     = list.Max(x => x.when),
                            IsKillChain  = true
                        };
                        KillChainDetected?.Invoke(this, group);
                        EmitAlert(new IDSAlert
                        {
                            AlertId = Guid.NewGuid(), Timestamp = DateTime.Now,
                            SourceIP = alert.SourceIP, DestinationIP = "multiple",
                            Protocol = "multi", Severity = IDSAlertSeverity.Critical,
                            AlertType = "Kill Chain Detected",
                            Description = $"Source {alert.SourceIP} progressed through {string.Join(" â†’ ", cats)} within {KillChainWindowSeconds}s â€” active attack chain",
                            RuleId = "CORRELATION", AttackCategory = "Kill Chain"
                        });
                    }
                }
            }
        }

        public List<CorrelationGroup> GetCorrelationGroups()
        {
            var result = new List<CorrelationGroup>();
            var cutoff = DateTime.Now.AddSeconds(-KillChainWindowSeconds);
            foreach (var kv in _srcCorr)
            {
                List<(string cat, DateTime when)> snap;
                lock (kv.Value) snap = kv.Value.Where(x => x.when >= cutoff).ToList();
                if (snap.Count == 0) continue;
                var cats = snap.Select(x => x.cat).Distinct().ToHashSet();
                bool hasRecon   = cats.Any(c => _reconCats.Any(r => c.Contains(r, StringComparison.OrdinalIgnoreCase)));
                bool hasExploit = cats.Any(c => _exploitCats.Any(r => c.Contains(r, StringComparison.OrdinalIgnoreCase)));
                bool hasC2      = cats.Any(c => _c2Cats.Any(r => c.Contains(r, StringComparison.OrdinalIgnoreCase)));

                var sev = snap.Count > 10 ? IDSAlertSeverity.Critical : snap.Count > 5 ? IDSAlertSeverity.High : IDSAlertSeverity.Medium;
                result.Add(new CorrelationGroup
                {
                    SourceIP    = kv.Key,
                    AlertCount  = snap.Count,
                    Categories  = string.Join(", ", cats.Take(4)),
                    MaxSeverity = sev.ToString(),
                    MaxSeverityColor = SevColor(sev),
                    FirstSeen   = snap.Min(x => x.when),
                    LastSeen    = snap.Max(x => x.when),
                    IsKillChain = hasRecon && hasExploit && hasC2
                });
            }
            return result.OrderByDescending(g => g.AlertCount).ToList();
        }

        private static string SevColor(IDSAlertSeverity s) => s switch
        {
            IDSAlertSeverity.Critical => "#F44747",
            IDSAlertSeverity.High     => "#FF8C00",
            IDSAlertSeverity.Medium   => "#FFA500",
            IDSAlertSeverity.Low      => "#4EC9B0",
            _ => "#808080"
        };

        // â”€â”€ Alert CRUD â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        public void AcknowledgeAlert(Guid id) { lock (_alertsLock) { var a = _alerts.FirstOrDefault(x => x.AlertId == id); if (a != null) a.IsAcknowledged = true; } _alertsDirty = true; }
        public void DeleteAlert(Guid id)       { lock (_alertsLock) { var a = _alerts.FirstOrDefault(x => x.AlertId == id); if (a != null) _alerts.Remove(a); } _alertsDirty = true; }
        public void ClearAlerts()              { lock (_alertsLock) _alerts.Clear(); _alertsDirty = true; }

        /// <summary>Inject an alert received from a remote module instance (console-side display).</summary>
        public void IngestExternalAlert(IDSAlert alert) => EmitAlert(alert);

        // â”€â”€ Stats â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        public IDSStats GetStats()
        {
            List<IDSAlert> alertSnap;
            List<IDSRule>  ruleSnap;
            lock (_alertsLock) alertSnap = _alerts.ToList();
            lock (_rulesLock)  ruleSnap  = _rules.ToList();
            return new IDSStats
            {
                TotalPackets      = _totalPackets,
                TotalThreats      = _totalThreats,
                SignatureMatches  = _sigMatches,
                TotalAlerts       = alertSnap.Count,
                CriticalAlerts    = alertSnap.Count(a => a.Severity == IDSAlertSeverity.Critical),
                HighAlerts        = alertSnap.Count(a => a.Severity == IDSAlertSeverity.High),
                MediumAlerts      = alertSnap.Count(a => a.Severity == IDSAlertSeverity.Medium),
                LowAlerts         = alertSnap.Count(a => a.Severity == IDSAlertSeverity.Low),
                ActiveRules       = ruleSnap.Count(r => r.IsEnabled),
                TotalRules        = ruleSnap.Count,
                IsRunning         = _running,
                ActiveInterface   = _device?.Description ?? "None",
                ArpAlerts         = _arpAlerts,
                Ja3Alerts         = _ja3Alerts,
                CorrelationAlerts = _correlationAlerts,
                BlockedIps        = _blockedIps.Count,
                AllowlistEntries  = _allowlist.Count
            };
        }

        // â”€â”€ Rule CRUD â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        public void AddRule(IDSRule r)    { if (RemoteControl != null) { RemoteControl(IdsModuleBridge.CmdRuleAdd, new() { ["rule"] = JsonSerializer.Serialize(r) }); return; } lock (_rulesLock) { if (r.Id == Guid.Empty) r.Id = Guid.NewGuid(); r.CreatedDate = r.ModifiedDate = DateTime.Now; _rules.Add(r); } _rulesDirty = true; RulesChanged?.Invoke(this, EventArgs.Empty); }
        public void UpdateRule(IDSRule r) { if (RemoteControl != null) { RemoteControl(IdsModuleBridge.CmdRuleUpdate, new() { ["rule"] = JsonSerializer.Serialize(r) }); return; } lock (_rulesLock) { var e = _rules.FirstOrDefault(x => x.Id == r.Id); if (e != null) { r.ModifiedDate = DateTime.Now; _rules[_rules.IndexOf(e)] = r; } } _rulesDirty = true; RulesChanged?.Invoke(this, EventArgs.Empty); }
        public void DeleteRule(Guid id)   { if (RemoteControl != null) { RemoteControl(IdsModuleBridge.CmdRuleDelete, new() { ["id"] = id.ToString() }); return; } lock (_rulesLock) { var r = _rules.FirstOrDefault(x => x.Id == id); if (r != null) _rules.Remove(r); } _rulesDirty = true; RulesChanged?.Invoke(this, EventArgs.Empty); }
        public void ToggleRule(Guid id, bool en) { if (RemoteControl != null) { RemoteControl(IdsModuleBridge.CmdRuleToggle, new() { ["id"] = id.ToString(), ["en"] = en }); return; } lock (_rulesLock) { var r = _rules.FirstOrDefault(x => x.Id == id); if (r != null) { r.IsEnabled = en; r.ModifiedDate = DateTime.Now; } } _rulesDirty = true; RulesChanged?.Invoke(this, EventArgs.Empty); }

        public void ResetToDefaults()
        {
            lock (_rulesLock) _rules.Clear();
            LoadDefaultRules();
        }

        // â”€â”€ Default rules (expanded from 25 to 40) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        private void LoadDefaultRules()
        {
            var defs = new IDSRule[]
            {
                // â”€â”€ Web Attacks â”€â”€
                Sig("SIG-001","Telnet Access","Connection to Telnet port (unencrypted remote access)",IDSAlertSeverity.Medium,"TCP","any","any","23",null,"Suspicious Access"),
                Sig("SIG-002","SMB Access","Connection to SMB file sharing ports",IDSAlertSeverity.Low,"TCP","any","any","139,445",null,"Reconnaissance"),
                Sig("SIG-003","FTP Anonymous Login","FTP anonymous login attempt",IDSAlertSeverity.Low,"TCP","any","any","21","USER anonymous","Suspicious Access"),
                Sig("SIG-004","SQL Injection UNION","SQL UNION SELECT injection in HTTP payload",IDSAlertSeverity.Critical,"TCP","any","any","80,443,8080,8443","(?i)union.{0,20}select","Web Attack"),
                Sig("SIG-005","SQL Injection OR 1=1","Classic SQL OR 1=1 injection pattern",IDSAlertSeverity.Critical,"TCP","any","any","80,443,8080,8443","(?i)(or|and)\\s+[^\\s]*\\s*=\\s*[^\\s]*\\s*(--|#)","Web Attack"),
                Sig("SIG-006","XSS Attack","Cross-site scripting payload in HTTP",IDSAlertSeverity.High,"TCP","any","any","80,443,8080,8443","(?i)<script[^>]*>|javascript:|on(load|error|click)\\s*=","Web Attack"),
                Sig("SIG-007","Path Traversal","Directory traversal attempt",IDSAlertSeverity.High,"TCP","any","any","80,443,8080,8443","(\\.\\./){2,}|%2e%2e%2f","Web Attack"),
                Sig("SIG-008","Command Injection","OS command injection in HTTP payload",IDSAlertSeverity.Critical,"TCP","any","any","80,443,8080,8443","(?i)(;|&&|\\|\\|)\\s*(ls|cat|wget|curl|bash|sh|cmd|powershell)","Web Attack"),
                Sig("SIG-009","Shellshock Exploit","Shellshock exploit attempt in HTTP headers",IDSAlertSeverity.Critical,"TCP","any","any","80,443,8080","\\(\\s*\\)\\s*\\{[^}]*\\}\\s*;","Exploit"),
                // â”€â”€ DoS â”€â”€
                Sig("SIG-010","Large ICMP Packet","Oversized ICMP - possible Ping of Death",IDSAlertSeverity.Medium,"ICMP","any","any","any",null,"DoS/DDoS",1025),
                // â”€â”€ Exfiltration â”€â”€
                Sig("SIG-011","HTTP Large POST","Very large HTTP POST - possible data exfiltration",IDSAlertSeverity.Low,"TCP","any","any","80,443,8080,8443","POST ","Data Exfiltration",102400),
                // â”€â”€ Malware/C2 â”€â”€
                Sig("SIG-012","Reverse Shell Port","Common Metasploit/reverse shell listener ports",IDSAlertSeverity.Critical,"TCP","any","any","4444,4445,5555,6666,6667",null,"Malware/C2"),
                Sig("SIG-013","Vulnerability Scanner UA","Known scanner user-agent in HTTP",IDSAlertSeverity.Medium,"TCP","any","any","80,443,8080","(?i)(sqlmap|nikto|nmap|masscan|metasploit|havij|acunetix|nessus|openvas)","Reconnaissance"),
                Sig("SIG-014","Base64 URL Evasion","Large Base64 payload in HTTP URL",IDSAlertSeverity.Medium,"TCP","any","any","80,443,8080","GET [^ ]*([A-Za-z0-9+/]{40,}={0,2})","Evasion"),
                Sig("SIG-015","PHP Webshell","PHP command execution via webshell pattern",IDSAlertSeverity.Critical,"TCP","any","any","80,443,8080","(?i)(system|exec|passthru|shell_exec|popen|proc_open)\\s*\\(","Malware/C2"),
                Sig("SIG-016","SMTP Relay Attempt","Outbound SMTP - possible spam relay",IDSAlertSeverity.Medium,"TCP","any","any","25",null,"Spam/Abuse"),
                Sig("SIG-017","RDP Connection","Remote Desktop connection detected",IDSAlertSeverity.Low,"TCP","any","any","3389",null,"Remote Access"),
                Sig("SIG-018","VNC Connection","VNC remote access connection detected",IDSAlertSeverity.Low,"TCP","any","any","5900,5901,5902",null,"Remote Access"),
                Sig("SIG-019","Meterpreter Payload","Meterpreter payload string in traffic",IDSAlertSeverity.Critical,"TCP","any","any","any","(?i)(meterpreter|stageless|stdapi)","Malware/C2"),
                Sig("SIG-020","LDAP Injection","LDAP injection patterns in payload",IDSAlertSeverity.High,"TCP","any","any","389,636","(?i)(\\(\\|\\()|(\\(\\&\\()|\\*\\)\\(","Web Attack"),
                Sig("SIG-021","Log4Shell","Log4Shell JNDI injection attempt",IDSAlertSeverity.Critical,"TCP","any","any","any","(?i)\\$\\{jndi:(ldap|rmi|dns|corba)://","Exploit"),
                Sig("SIG-022","SSRF Attempt","Server-Side Request Forgery pattern in HTTP",IDSAlertSeverity.High,"TCP","any","any","80,443,8080","(?i)(url=|redirect=|next=|target=).*(localhost|127\\.0\\.0|169\\.254|::1)","Web Attack"),
                Sig("SIG-023","TCP Null Scan","TCP packet with no flags - stealth scan technique",IDSAlertSeverity.High,"TCP","any","any","any",null,"Reconnaissance",0,true,false),
                Sig("SIG-024","TCP XMAS Scan","TCP FIN+PSH+URG flags - XMAS stealth scan",IDSAlertSeverity.High,"TCP","any","any","any",null,"Reconnaissance",0,false,true),
                Sig("SIG-025","XXE Injection","XML External Entity injection pattern",IDSAlertSeverity.High,"TCP","any","any","80,443,8080,8443","(?i)<!ENTITY\\s+\\w+\\s+SYSTEM\\s+['\"]","Web Attack"),

                // â”€â”€ New rules SIG-026 to SIG-040 â”€â”€
                Sig("SIG-026","EternalBlue SMB Probe","MS17-010 EternalBlue exploitation probe pattern",IDSAlertSeverity.Critical,"TCP","any","any","445","\\x00\\x00\\x00.{1}\\xffSMB","Exploit"),
                Sig("SIG-027","Cobalt Strike Beacon","Cobalt Strike default malleable C2 beacon pattern",IDSAlertSeverity.Critical,"TCP","any","any","80,443,8080","(?i)(User-Agent: Mozilla/5\\.0[^\\r\\n]{0,300}\\r\\nAccept-Encoding: gzip, deflate\\r\\n)","Malware/C2"),
                Sig("SIG-028","PowerShell Encoded Command","PowerShell base64 encoded command in HTTP (fileless attack)",IDSAlertSeverity.Critical,"TCP","any","any","80,443,8080,8443","(?i)(powershell|pwsh).*-e(nc|ncodedcommand)?\\s+[A-Za-z0-9+/]{40,}","Malware/C2"),
                Sig("SIG-029","WordPress Admin Probe","WordPress admin login or wp-admin probe",IDSAlertSeverity.Low,"TCP","any","any","80,443,8080","/wp-(admin|login\\.php|config\\.php)","Reconnaissance"),
                Sig("SIG-030","phpMyAdmin Probe","phpMyAdmin access attempt",IDSAlertSeverity.Low,"TCP","any","any","80,443,8080","(?i)/phpmyadmin|/pma/|/mysql/|/mysqladmin","Reconnaissance"),
                Sig("SIG-031","Git Repository Exposure","Exposed .git directory access attempt",IDSAlertSeverity.Medium,"TCP","any","any","80,443,8080","GET /\\.git/","Reconnaissance"),
                Sig("SIG-032","HTTP CONNECT Tunneling","HTTP CONNECT method used for tunneling",IDSAlertSeverity.Medium,"TCP","any","any","80,443,8080,3128","^CONNECT \\S+:\\d+ HTTP","Suspicious Access"),
                Sig("SIG-033","IRC C2 Channel","IRC protocol communication on non-standard port (possible botnet C2)",IDSAlertSeverity.High,"TCP","any","any","6667,6668,6669,7000","(?i)(NICK |USER |JOIN #|PRIVMSG #)","Malware/C2"),
                Sig("SIG-034","Host Header Injection","HTTP Host header injection attempt",IDSAlertSeverity.Medium,"TCP","any","any","80,443,8080","Host:\\s*(localhost|127\\.|192\\.168\\.|10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.)","Web Attack"),
                Sig("SIG-035","Spring4Shell RCE","Spring Framework RCE exploit attempt (CVE-2022-22965)",IDSAlertSeverity.Critical,"TCP","any","any","80,443,8080","class\\.module\\.classLoader\\.resources\\.context","Exploit"),
                Sig("SIG-036","ProxyLogon Exchange","Microsoft Exchange ProxyLogon/ProxyShell exploit pattern",IDSAlertSeverity.Critical,"TCP","any","any","443","(?i)/ews/exchange\\.asmx.*(autodiscover|mapi)|/autodiscover\\.json.*@","Exploit"),
                Sig("SIG-037","NTLM Relay Capture","NTLM authentication relay attack pattern",IDSAlertSeverity.High,"TCP","any","any","445,80,443","NTLMSSP\\x00\\x01","Exploit"),
                Sig("SIG-038","WinRM Remote Execution","Windows Remote Management access (possible lateral movement)",IDSAlertSeverity.Medium,"TCP","any","any","5985,5986",null,"Remote Access"),
                Sig("SIG-039","SOCKS Proxy Signature","SOCKS proxy protocol header (possible tunneling)",IDSAlertSeverity.Medium,"TCP","any","any","1080,1081","^\\x05[\\x00-\\x08]|^\\x04\\x01","Suspicious Access"),
                Sig("SIG-040","DNS Zone Transfer","DNS AXFR zone transfer request (reconnaissance)",IDSAlertSeverity.High,"TCP","any","any","53","(?s)\\x00\\xfc","Reconnaissance"),
            };
            foreach (var r in defs) { r.RuleKind = RuleKind.Signature; AddRule(r); }
        }

        private static IDSRule Sig(string id, string name, string desc, IDSAlertSeverity sev, string proto,
            string srcIp, string srcPort, string dstPort, string? pattern, string cat,
            int minSize = 0, bool nullF = false, bool xmasF = false, string dstIp = "any") => new IDSRule
        {
            Id = Guid.NewGuid(), RuleId = id, Name = name, Description = desc,
            IsEnabled = true, Severity = sev, Protocol = proto,
            SourceIP = srcIp, DestinationIP = dstIp, SourcePort = srcPort, DestinationPort = dstPort,
            Pattern = pattern ?? "", AttackCategory = cat,
            MinPacketSize = minSize, RequireNullFlags = nullF, RequireXmasFlags = xmasF,
            CreatedDate = DateTime.Now, ModifiedDate = DateTime.Now
        };

        // â”€â”€ Behavioral settings â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        public void ApplyBehavioralSettings(BehavioralSettings s)
        {
            SynFloodThreshold   = s.SynFloodThreshold;   SynFloodWindowSec   = s.SynFloodWindowSec;
            IcmpFloodThreshold  = s.IcmpFloodThreshold;  IcmpFloodWindowSec  = s.IcmpFloodWindowSec;
            UdpFloodThreshold   = s.UdpFloodThreshold;   UdpFloodWindowSec   = s.UdpFloodWindowSec;
            PortScanThreshold   = s.PortScanThreshold;   PortScanWindowSec   = s.PortScanWindowSec;
            BruteForceThreshold = s.BruteForceThreshold; BruteForceWindowSec = s.BruteForceWindowSec;
            _synCounters.Clear(); _icmpCounters.Clear(); _udpCounters.Clear(); _bruteForce.Clear();
            SaveBehavioralSettings();
        }

        public BehavioralSettings GetBehavioralSettings() => new BehavioralSettings
        {
            SynFloodThreshold   = SynFloodThreshold,   SynFloodWindowSec   = SynFloodWindowSec,
            IcmpFloodThreshold  = IcmpFloodThreshold,  IcmpFloodWindowSec  = IcmpFloodWindowSec,
            UdpFloodThreshold   = UdpFloodThreshold,   UdpFloodWindowSec   = UdpFloodWindowSec,
            PortScanThreshold   = PortScanThreshold,   PortScanWindowSec   = PortScanWindowSec,
            BruteForceThreshold = BruteForceThreshold, BruteForceWindowSec = BruteForceWindowSec
        };

        // â”€â”€ Rule import/export â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        public string ExportRulesJson() { lock (_rulesLock) return JsonSerializer.Serialize(_rules, new JsonSerializerOptions { WriteIndented = true }); }

        // Accepts both integer (legacy) and string (new) enum values for Severity and RuleKind
        private static readonly JsonSerializerOptions _importOpts = new()
        {
            PropertyNameCaseInsensitive = true,
            Converters = { new FlexEnumConverter<IDSAlertSeverity>(), new FlexEnumConverter<RuleKind>() }
        };

        public (int added, int skipped) ImportRulesJson(string json)
        {
            var imported = JsonSerializer.Deserialize<List<IDSRule>>(json, _importOpts);
            if (imported == null) return (0, 0);
            int added = 0, skipped = 0;
            lock (_rulesLock)
                foreach (var r in imported)
                {
                    if (_rules.Any(x => x.RuleId == r.RuleId)) { skipped++; continue; }
                    r.Id = Guid.NewGuid(); r.CreatedDate = r.ModifiedDate = DateTime.Now;
                    _rules.Add(r); added++;
                }
            _rulesDirty = true;
            return (added, skipped);
        }

        // â”€â”€ Persistence â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        private static readonly JsonSerializerOptions _jsonOpts = new() { WriteIndented = true };

        private void SaveAlerts()     { try { File.WriteAllText(_alertsPath,    JsonSerializer.Serialize(_alerts.ToList(), _jsonOpts)); } catch (Exception ex) { Debug.WriteLine($"[IDSEngine.SaveAlerts] {ex.Message}"); } }
        private void SaveRules()      { try { File.WriteAllText(_rulesPath,     JsonSerializer.Serialize(_rules, _jsonOpts)); } catch (Exception ex) { Debug.WriteLine($"[IDSEngine.SaveRules] {ex.Message}"); } }
        private void SaveAllowlist()  { try { File.WriteAllText(_allowlistPath, JsonSerializer.Serialize(_allowlist, _jsonOpts)); } catch (Exception ex) { Debug.WriteLine($"[IDSEngine.SaveAllowlist] {ex.Message}"); } }
        private void SaveBlocked()    { try { File.WriteAllText(_blockedPath,   JsonSerializer.Serialize(_blockedIps, _jsonOpts)); } catch (Exception ex) { Debug.WriteLine($"[IDSEngine.SaveBlocked] {ex.Message}"); } }

        private void LoadAlerts()     { try { if (File.Exists(_alertsPath))    { var l = JsonSerializer.Deserialize<List<IDSAlert>>(File.ReadAllText(_alertsPath));          if (l != null) foreach (var a in l) _alerts.Add(a); } } catch (Exception ex) { Debug.WriteLine($"[IDSEngine.LoadAlerts] {ex.Message}"); } }
        private void LoadRules()      { try { if (File.Exists(_rulesPath))     { var l = JsonSerializer.Deserialize<List<IDSRule>>(File.ReadAllText(_rulesPath));            if (l != null) _rules.AddRange(l); } } catch (Exception ex) { Debug.WriteLine($"[IDSEngine.LoadRules] {ex.Message}"); } }
        private void LoadAllowlist()  { try { if (File.Exists(_allowlistPath)) { var l = JsonSerializer.Deserialize<List<AllowlistEntry>>(File.ReadAllText(_allowlistPath)); if (l != null) _allowlist.AddRange(l); } } catch (Exception ex) { Debug.WriteLine($"[IDSEngine.LoadAllowlist] {ex.Message}"); } }
        private void LoadBlocked()    { try { if (File.Exists(_blockedPath))   { var l = JsonSerializer.Deserialize<List<BlockedIpEntry>>(File.ReadAllText(_blockedPath));   if (l != null) _blockedIps.AddRange(l); } } catch (Exception ex) { Debug.WriteLine($"[IDSEngine.LoadBlocked] {ex.Message}"); } }

        private void SaveBehavioralSettings() { try { File.WriteAllText(_settingsPath, JsonSerializer.Serialize(GetBehavioralSettings(), _jsonOpts)); } catch (Exception ex) { Debug.WriteLine($"[IDSEngine.SaveBehavioralSettings] {ex.Message}"); } }
        private void LoadBehavioralSettings() { try { if (!File.Exists(_settingsPath)) return; var s = JsonSerializer.Deserialize<BehavioralSettings>(File.ReadAllText(_settingsPath)); if (s != null) ApplyBehavioralSettings(s); } catch (Exception ex) { Debug.WriteLine($"[IDSEngine.LoadBehavioralSettings] {ex.Message}"); } }

        // â”€â”€ Tracker pruning â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        private void PruneTrackers()
        {
            var idleCut = DateTime.UtcNow.AddMinutes(-AppConstants.IDS.TrackerIdleMinutes);
            foreach (var k in _synCounters.Where(kv => kv.Value.LastIncrement < idleCut).Select(kv => kv.Key).ToList()) _synCounters.TryRemove(k, out _);
            foreach (var k in _icmpCounters.Where(kv => kv.Value.LastIncrement < idleCut).Select(kv => kv.Key).ToList()) _icmpCounters.TryRemove(k, out _);
            foreach (var k in _udpCounters.Where(kv => kv.Value.LastIncrement < idleCut).Select(kv => kv.Key).ToList()) _udpCounters.TryRemove(k, out _);
            foreach (var k in _bruteForce.Where(kv => kv.Value.LastIncrement < idleCut).Select(kv => kv.Key).ToList()) _bruteForce.TryRemove(k, out _);
            foreach (var k in _dnsRateCounters.Where(kv => kv.Value.LastIncrement < idleCut).Select(kv => kv.Key).ToList()) _dnsRateCounters.TryRemove(k, out _);
            foreach (var k in _portScanWindows.Where(kv => (DateTime.UtcNow - kv.Value).TotalMinutes > 5).Select(kv => kv.Key).ToList())
            { _portScanWindows.TryRemove(k, out _); _portScanSets.TryRemove(k, out _); }
            foreach (var k in _recentAlerts.Where(kv => kv.Value < idleCut).Select(kv => kv.Key).ToList()) _recentAlerts.TryRemove(k, out _);
            // Remove expired allowlist entries
            lock (_allowlistLock) { int removed = _allowlist.RemoveAll(e => e.IsExpired); if (removed > 0) _allowlistDirty = true; }
        }

        public void Dispose()
        {
            StopCapture();
            if (_alertsDirty)    SaveAlerts();
            if (_rulesDirty)     SaveRules();
            if (_allowlistDirty) SaveAllowlist();
            if (_blockedDirty)   SaveBlocked();
        }
    }

    // â”€â”€ SlidingCounter â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    public class SlidingCounter
    {
        private readonly Queue<DateTime> _q = new();
        private readonly TimeSpan _w;
        private readonly object _lk = new();
        public DateTime LastIncrement { get; private set; } = DateTime.UtcNow;
        public SlidingCounter(TimeSpan w) { _w = w; }
        public int Increment()
        {
            lock (_lk)
            {
                LastIncrement = DateTime.UtcNow;
                var cut = DateTime.UtcNow - _w;
                while (_q.Count > 0 && _q.Peek() < cut) _q.Dequeue();
                _q.Enqueue(DateTime.UtcNow);
                return _q.Count;
            }
        }
    }

    // â”€â”€ NetPacket â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    public class NetPacket
    {
        public string SrcIP { get; set; } = ""; public string DstIP { get; set; } = "";
        public int SrcPort { get; set; }         public int DstPort { get; set; }
        public string Protocol { get; set; } = "";
        public string Payload { get; set; } = "";
        public byte[] PayloadBytes { get; set; } = Array.Empty<byte>();
        public int Size { get; set; }            public bool IsSyn { get; set; }
        public bool HasNullFlags { get; set; }   public bool HasXmasFlags { get; set; }
        public DateTime Timestamp { get; set; }
    }

    // â”€â”€ IDSStats (expanded) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    public class IDSStats
    {
        public long TotalPackets { get; set; }   public long TotalThreats { get; set; }    public long SignatureMatches { get; set; }
        public int TotalAlerts { get; set; }     public int CriticalAlerts { get; set; }
        public int HighAlerts { get; set; }      public int MediumAlerts { get; set; }      public int LowAlerts { get; set; }
        public int ActiveRules { get; set; }     public int TotalRules { get; set; }
        public bool IsRunning { get; set; }      public string ActiveInterface { get; set; } = "";
        public long ArpAlerts { get; set; }      public long Ja3Alerts { get; set; }
        public long CorrelationAlerts { get; set; }
        public int BlockedIps { get; set; }      public int AllowlistEntries { get; set; }
    }

    // â”€â”€ Ja3Fingerprinter â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    internal static class Ja3Fingerprinter
    {
        // Known malicious JA3 hashes (small curated set â€” add more as discovered)
        private static readonly HashSet<string> _knownBad = new(StringComparer.OrdinalIgnoreCase)
        {
            "d4a43ef1fa0f0786027c2b0e4d2d2a77", // Metasploit Meterpreter
            "e7d705a3286e19ea42f587b344ee6865", // Cobalt Strike default
            "6bea65232d16d69e4b62db35a575e46d", // CobaltStrike v4
            "72a589da586844d7f0818ce684948eea", // Cobalt Strike beacon
            "a0e9f5d64349fb13191bc781f81f42e1", // Hancitor
            "b386946a5a44d1ddcc843bc75336dfce", // Zloader
        };

        private static readonly HashSet<ushort> _grease = new()
        { 0x0a0a,0x1a1a,0x2a2a,0x3a3a,0x4a4a,0x5a5a,0x6a6a,0x7a7a,0x8a8a,0x9a9a,0xaaaa,0xbaba,0xcaca,0xdada,0xeaea,0xfafa };

        public static void TryExtract(byte[] data, out string? hash, out string? info)
        {
            hash = null; info = null;
            try
            {
                // TLS record: ContentType(0x16) + Version(0x03xx) + Length(2)
                if (data.Length < 6 || data[0] != 0x16 || data[1] != 0x03) return;
                // Handshake type 0x01 = ClientHello at offset 5
                if (data[5] != 0x01) return;

                int pos = 9; // skip Record header(5) + HandshakeType(1) + Length(3)
                if (pos + 2 > data.Length) return;

                ushort tlsVersion = ToU16(data, pos); pos += 2; // ClientHello.Version
                pos += 32; // Random
                if (pos >= data.Length) return;

                int sessionLen = data[pos++];
                pos += sessionLen;
                if (pos + 2 > data.Length) return;

                int csLen = ToU16(data, pos); pos += 2;
                var ciphers = new List<ushort>();
                int csEnd = pos + csLen;
                while (pos < csEnd && pos + 1 < data.Length)
                {
                    ushort cs = ToU16(data, pos); pos += 2;
                    if (!_grease.Contains(cs)) ciphers.Add(cs);
                }
                pos = csEnd;
                if (pos >= data.Length) return;

                int compLen = data[pos++];
                pos += compLen;

                var extensions = new List<ushort>();
                var curves     = new List<ushort>();
                var ecFormats  = new List<byte>();

                if (pos + 2 <= data.Length)
                {
                    int extTotal = ToU16(data, pos); pos += 2;
                    int extEnd   = pos + extTotal;
                    while (pos + 3 < extEnd && pos + 3 < data.Length)
                    {
                        ushort extType = ToU16(data, pos); pos += 2;
                        int    extLen  = ToU16(data, pos); pos += 2;
                        int    extData = pos;
                        if (!_grease.Contains(extType)) extensions.Add(extType);

                        if (extType == 0x000a && extLen >= 2) // supported_groups
                        {
                            int glLen = ToU16(data, extData); int gPos = extData + 2;
                            while (gPos + 1 < extData + glLen + 2 && gPos + 1 < data.Length)
                            { ushort g = ToU16(data, gPos); gPos += 2; if (!_grease.Contains(g)) curves.Add(g); }
                        }
                        else if (extType == 0x000b && extLen >= 1) // ec_point_formats
                        {
                            int fCount = data[extData]; int fPos = extData + 1;
                            for (int i = 0; i < fCount && fPos < data.Length; i++) ecFormats.Add(data[fPos++]);
                        }

                        pos = extData + extLen;
                    }
                }

                string ja3str = $"{tlsVersion},{string.Join("-", ciphers)},{string.Join("-", extensions)},{string.Join("-", curves)},{string.Join("-", ecFormats)}";
                hash = Md5Hex(ja3str);
                bool known = _knownBad.Contains(hash);
                info = $"JA3={hash}{(known ? " âš  KNOWN MALICIOUS" : "")} ({ja3str[..Math.Min(80, ja3str.Length)]})";
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[Ja3Fingerprinter.TryExtract] {ex.Message}");
            }
        }

        private static ushort ToU16(byte[] b, int i) => (ushort)((b[i] << 8) | b[i + 1]);

        private static string Md5Hex(string s)
        {
            var bytes = MD5.HashData(Encoding.ASCII.GetBytes(s));
            return Convert.ToHexString(bytes).ToLower();
        }
    }

    // ── Ja4Fingerprinter ────────────────────────────────────────────────────
    // JA4 (FoxIO 2023) is the modern successor to JA3.  Format:
    //   {Protocol}{TLSVersion}{SNIflag}{CipherCount}{ExtensionCount}{ALPN}_
    //   {sha256(sorted ciphers)[:12]}_{sha256(sorted ext+sig)[:12]}
    // e.g. "t13d1517h2_8daaf6152771_b186095e22b6"
    //
    // The hash is more evasion-resistant than JA3 because it sorts extensions
    // (Chrome's randomised extension order famously broke JA3) and includes the
    // ALPN — both major sources of JA3 false positives in modern browsers.
    internal static class Ja4Fingerprinter
    {
        private static readonly HashSet<ushort> _grease = new()
        { 0x0a0a,0x1a1a,0x2a2a,0x3a3a,0x4a4a,0x5a5a,0x6a6a,0x7a7a,0x8a8a,0x9a9a,0xaaaa,0xbaba,0xcaca,0xdada,0xeaea,0xfafa };

        public static void TryExtract(byte[] data, out string? hash, out string? full)
        {
            hash = null; full = null;
            try
            {
                if (data.Length < 6 || data[0] != 0x16 || data[1] != 0x03) return;
                if (data[5] != 0x01) return;

                int pos = 9;
                if (pos + 2 > data.Length) return;
                ushort tlsRecVer = ToU16(data, pos); pos += 2;
                pos += 32; // Random
                if (pos >= data.Length) return;
                int sessionLen = data[pos++];
                pos += sessionLen;
                if (pos + 2 > data.Length) return;

                int csLen = ToU16(data, pos); pos += 2;
                var ciphers = new List<ushort>();
                int csEnd = pos + csLen;
                while (pos + 1 < csEnd && pos + 1 < data.Length)
                {
                    ushort cs = ToU16(data, pos); pos += 2;
                    if (!_grease.Contains(cs)) ciphers.Add(cs);
                }
                pos = csEnd;
                if (pos >= data.Length) return;

                int compLen = data[pos++];
                pos += compLen;

                var extensions = new List<ushort>();
                var sigAlgos   = new List<ushort>();
                ushort selectedTlsVer = tlsRecVer;
                string? sni  = null;
                string? alpn = null;

                if (pos + 2 <= data.Length)
                {
                    int extTotal = ToU16(data, pos); pos += 2;
                    int extEnd = pos + extTotal;
                    while (pos + 3 < extEnd && pos + 3 < data.Length)
                    {
                        ushort extType = ToU16(data, pos); pos += 2;
                        int extLen = ToU16(data, pos); pos += 2;
                        int extData = pos;
                        if (!_grease.Contains(extType)) extensions.Add(extType);

                        if (extType == 0x0000 && extLen > 2) // SNI
                        {
                            try
                            {
                                int sniListLen = ToU16(data, extData);
                                int sniPos = extData + 2;
                                if (sniPos + 3 < extData + 2 + sniListLen && data[sniPos] == 0)
                                {
                                    int hostLen = ToU16(data, sniPos + 1);
                                    sniPos += 3;
                                    if (sniPos + hostLen <= data.Length)
                                        sni = Encoding.ASCII.GetString(data, sniPos, hostLen);
                                }
                            }
                            catch { }
                        }
                        else if (extType == 0x0010 && extLen > 2) // ALPN
                        {
                            try
                            {
                                int alpnListLen = ToU16(data, extData);
                                int aPos = extData + 2;
                                if (aPos < extData + 2 + alpnListLen && aPos < data.Length)
                                {
                                    int strLen = data[aPos++];
                                    if (aPos + strLen <= data.Length)
                                        alpn = Encoding.ASCII.GetString(data, aPos, strLen);
                                }
                            }
                            catch { }
                        }
                        else if (extType == 0x000d && extLen >= 2) // sig algorithms
                        {
                            int sLen = ToU16(data, extData);
                            int sPos = extData + 2;
                            while (sPos + 1 < extData + 2 + sLen && sPos + 1 < data.Length)
                            { ushort s = ToU16(data, sPos); sPos += 2; if (!_grease.Contains(s)) sigAlgos.Add(s); }
                        }
                        else if (extType == 0x002b && extLen >= 2) // supported_versions
                        {
                            int n = data[extData];
                            for (int i = 1; i < n && extData + i + 1 < data.Length; i += 2)
                            {
                                ushort v = ToU16(data, extData + i);
                                if (_grease.Contains(v)) continue;
                                if (v > selectedTlsVer) selectedTlsVer = v;
                            }
                        }

                        pos = extData + extLen;
                    }
                }

                string proto = "t"; // TCP only — QUIC would be "q"
                string verCode = selectedTlsVer switch
                {
                    0x0304 => "13",
                    0x0303 => "12",
                    0x0302 => "11",
                    0x0301 => "10",
                    _ => "00"
                };
                string sniFlag = string.IsNullOrEmpty(sni) ? "i" : "d";
                string alpnCode;
                if (string.IsNullOrEmpty(alpn) || alpn!.Length < 2) alpnCode = "00";
                else alpnCode = $"{alpn[0]}{alpn[^1]}";

                int cipherCount = Math.Min(99, ciphers.Count);
                int extCount    = Math.Min(99, extensions.Count);

                var cipherSorted = ciphers.ConvertAll(c => c).ToArray();
                Array.Sort(cipherSorted);
                var extSorted = extensions.ConvertAll(c => c).ToArray();
                Array.Sort(extSorted);
                var sigSorted = sigAlgos.ConvertAll(c => c).ToArray();
                Array.Sort(sigSorted);

                string cipherList = string.Join(",", Array.ConvertAll(cipherSorted, c => c.ToString("x4")));
                string extList    = string.Join(",", Array.ConvertAll(extSorted,    c => c.ToString("x4")));
                string sigList    = string.Join(",", Array.ConvertAll(sigSorted,    c => c.ToString("x4")));
                string extSigList = sigSorted.Length > 0 ? extList + "_" + sigList : extList;

                string cipherHash = Sha256Hex(cipherList).Substring(0, 12);
                string extHash    = Sha256Hex(extSigList).Substring(0, 12);

                string head = $"{proto}{verCode}{sniFlag}{cipherCount:D2}{extCount:D2}{alpnCode}";
                hash = $"{head}_{cipherHash}_{extHash}";
                full = $"JA4={hash} sni={(sni ?? "-")} alpn={(alpn ?? "-")}";
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[Ja4Fingerprinter.TryExtract] {ex.Message}");
            }
        }

        private static ushort ToU16(byte[] b, int i) => (ushort)((b[i] << 8) | b[i + 1]);

        private static string Sha256Hex(string s)
        {
            var bytes = SHA256.HashData(Encoding.ASCII.GetBytes(s));
            return Convert.ToHexString(bytes).ToLower();
        }
    }

    // â”€â”€ Backward-compat IDSManager wrapper â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    public class IDSManager
    {
        public static readonly IDSEngine Engine = new IDSEngine();
        public bool IsMonitoring => Engine.IsRunning;
        public async Task StartMonitoring() { await Task.Run(() => Engine.StartCapture()); }
        public void StopMonitoring() => Engine.StopCapture();
        public List<IDSAlert> GetAlerts(IDSAlertSeverity? sev = null, bool? ack = null)
        {
            var l = Engine.Alerts.ToList();
            if (sev.HasValue) l = l.Where(a => a.Severity == sev).ToList();
            if (ack.HasValue) l = l.Where(a => a.IsAcknowledged == ack).ToList();
            return l;
        }
        public List<IDSRule> GetRules(bool? en = null)
        {
            var l = Engine.Rules.ToList();
            if (en.HasValue) l = l.Where(r => r.IsEnabled == en).ToList();
            return l;
        }
        public void AddRule(IDSRule r)          => Engine.AddRule(r);
        public void UpdateRule(IDSRule r)        => Engine.UpdateRule(r);
        public void DeleteRule(Guid id)          => Engine.DeleteRule(id);
        public void ToggleRule(Guid id, bool en) => Engine.ToggleRule(id, en);
        public void AcknowledgeAlert(Guid id)    => Engine.AcknowledgeAlert(id);
        public void DeleteAlert(Guid id)         => Engine.DeleteAlert(id);
        public void ClearAllAlerts()             => Engine.ClearAlerts();
        public void LoadAlerts() { } public void LoadRules() { } public void LoadDefaultRules() { }
        public IDSStatistics GetStatistics()
        {
            var s = Engine.GetStats();
            return new IDSStatistics
            {
                TotalAlerts = s.TotalAlerts, CriticalAlerts = s.CriticalAlerts,
                HighAlerts = s.HighAlerts, MediumAlerts = s.MediumAlerts, LowAlerts = s.LowAlerts,
                UnacknowledgedAlerts = Engine.Alerts.Count(a => !a.IsAcknowledged),
                ActiveRules = s.ActiveRules, TotalRules = s.TotalRules
            };
        }
    }

    public class IDSStatistics
    {
        public int TotalAlerts { get; set; } public int CriticalAlerts { get; set; }
        public int HighAlerts { get; set; }  public int MediumAlerts { get; set; }
        public int LowAlerts { get; set; }   public int UnacknowledgedAlerts { get; set; }
        public int ActiveRules { get; set; } public int TotalRules { get; set; }
    }

    public class BehavioralSettings
    {
        public int SynFloodThreshold   { get; set; } = 200; public int SynFloodWindowSec   { get; set; } = 5;
        public int IcmpFloodThreshold  { get; set; } = 100; public int IcmpFloodWindowSec  { get; set; } = 10;
        public int UdpFloodThreshold   { get; set; } = 500; public int UdpFloodWindowSec   { get; set; } = 5;
        public int PortScanThreshold   { get; set; } = 25;  public int PortScanWindowSec   { get; set; } = 10;
        public int BruteForceThreshold { get; set; } = 10;  public int BruteForceWindowSec { get; set; } = 60;
    }

    /// <summary>
    /// Deserializes an enum from either its integer value (legacy) or its string name (new format).
    /// </summary>
    internal sealed class FlexEnumConverter<T> : System.Text.Json.Serialization.JsonConverter<T> where T : struct, Enum
    {
        public override T Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            if (reader.TokenType == JsonTokenType.Number)
            {
                int intVal = reader.GetInt32();
                if (Enum.IsDefined(typeof(T), intVal))
                    return (T)(object)intVal;
                throw new JsonException($"Integer {intVal} is not a valid {typeof(T).Name}.");
            }
            if (reader.TokenType == JsonTokenType.String)
            {
                string strVal = reader.GetString() ?? "";
                if (Enum.TryParse<T>(strVal, ignoreCase: true, out T result))
                    return result;
                throw new JsonException($"String '{strVal}' is not a valid {typeof(T).Name}.");
            }
            throw new JsonException($"Unexpected token {reader.TokenType} for {typeof(T).Name}.");
        }

        public override void Write(Utf8JsonWriter writer, T value, JsonSerializerOptions options)
            => writer.WriteStringValue(value.ToString());
    }
}
