# PrivaCore IDS — How It All Works

This document explains the complete Intrusion Detection System (IDS) built into PrivaCore Desktop — every component, how they connect, and exactly what happens from the moment a packet arrives or a file changes to the moment an alert appears on screen.

---

## Table of Contents

1. [Big Picture — Two Systems in One](#1-big-picture)
2. [Network IDS (NIDS) — Architecture](#2-network-ids-architecture)
3. [NIDS — Packet Capture Pipeline](#3-packet-capture-pipeline)
4. [NIDS — Behavioral Detection](#4-behavioral-detection)
5. [NIDS — Signature Matching](#5-signature-matching)
6. [NIDS — Advanced Detection (ARP, DNS, JA3)](#6-advanced-detection)
7. [NIDS — Alert Lifecycle](#7-alert-lifecycle)
8. [NIDS — Kill-Chain Correlation](#8-kill-chain-correlation)
9. [NIDS — IPS Mode (Auto-Block)](#9-ips-mode)
10. [Host IDS (HIDS) — Architecture](#10-host-ids-architecture)
11. [HIDS — File System Monitoring](#11-file-system-monitoring)
12. [HIDS — Windows Security Event Log](#12-windows-security-event-log)
13. [HIDS — Process Monitoring (WMI)](#13-process-monitoring)
14. [HIDS — Registry Monitoring](#14-registry-monitoring)
15. [HIDS — Services Monitoring](#15-services-monitoring)
16. [HIDS — Scheduled Tasks Monitoring](#16-scheduled-tasks-monitoring)
17. [HIDS — Session Monitoring](#17-session-monitoring)
18. [HIDS — DNS Cache Monitoring](#18-dns-cache-monitoring)
19. [Allowlist — Suppressing False Positives](#19-allowlist)
20. [Configuration System](#20-configuration-system)
21. [Data Persistence](#21-data-persistence)
22. [Live Traffic Graph](#22-live-traffic-graph)
23. [Alert Severity Scale](#23-alert-severity-scale)
24. [Threading Model](#24-threading-model)
25. [How to Tune It for Your Environment](#25-tuning-guide)

---

## 1. Big Picture

PrivaCore has two completely independent IDS engines that can run simultaneously:

```
┌──────────────────────────────────────────────────────────────────────┐
│                         PrivaCore IDS                               │
│                                                                      │
│   ┌───────────────────────┐      ┌───────────────────────────────┐   │
│   │   Network IDS (NIDS)  │      │      Host IDS (HIDS)          │   │
│   │                       │      │                               │   │
│   │  Watches the wire     │      │  Watches the machine          │   │
│   │  (all network traffic │      │  (OS events, files,           │   │
│   │   passing the NIC)    │      │   processes, registry...)     │   │
│   │                       │      │                               │   │
│   │  SharpPcap promiscuous│      │  WMI + EventLog + WinAPI      │   │
│   │  capture              │      │  polling every N seconds      │   │
│   └──────────┬────────────┘      └──────────────┬────────────────┘   │
│              │                                  │                    │
│              ▼                                  ▼                    │
│         IDSEngine                      HostIDSDashboardPage          │
│     (IDSManager.cs)                  (Hostidsdashboardpage.xaml.cs)  │
│              │                                  │                    │
│              └──────────────┬───────────────────┘                    │
│                             ▼                                        │
│                      Alert → Toast → Dashboard → Persist             │
└──────────────────────────────────────────────────────────────────────┘
```

**NIDS** inspects raw network packets at the NIC driver level — every TCP, UDP, ICMP, and ARP frame that passes through your network adapter, regardless of which application sent or received it.

**HIDS** watches the operating system itself — what processes are running, what registry keys changed, what services appeared, what files were modified, who logged in.

They share the same alert notification system (toast popups, dashboard lists) but run completely separately. You can run one, both, or neither.

---

## 2. Network IDS Architecture

The NIDS is built around a single class: `IDSEngine` in `Services/IDSManager.cs`.

```
NIC (promiscuous mode)
        │
        │  raw frame bytes
        ▼
   SharpPcap (WinPcap/Npcap driver)
        │
        │  OnPacketArrival event (fired for every packet)
        ▼
   IDSEngine.OnPacketArrival()
        │
        ├─► Parse packet (PacketDotNet)
        │       IPv4 / IPv6 / ARP / TCP / UDP / ICMP
        │
        ├─► DetectArpSpoofing()   ← ARP only
        │
        ├─► Ja3Fingerprinter.TryExtract()  ← TCP only, TLS only
        │
        ├─► DetectBehavioral()
        │       SYN flood check
        │       ICMP flood check
        │       UDP flood check
        │       Port scan check
        │       Brute force check
        │
        ├─► DNS tunneling check   ← UDP/53 only
        │
        └─► Signature matching
                foreach enabled Signature rule:
                    MatchesRule() → RaiseAlert()
```

Everything above happens on the SharpPcap capture thread — not the UI thread. All UI updates are dispatched via `Dispatcher.InvokeAsync`.

---

## 3. Packet Capture Pipeline

### How capture starts

When you click **▶ Start Monitoring** and select a network interface:

```csharp
_device = CaptureDeviceList.Instance[selectedIndex];
_device.Open(DeviceModes.Promiscuous, 1000);  // 1000ms read timeout
_device.OnPacketArrival += OnPacketArrival;
_device.StartCapture();
```

**Promiscuous mode** means the NIC is told to capture ALL frames on the network segment, not just ones addressed to your MAC. On a switched network this is limited to your own traffic plus broadcasts/multicasts. On a hub or port-mirrored switch port, you see everything.

### Packet parsing

Every arriving packet goes through PacketDotNet's parser:

```
raw bytes
    │
    ▼
Packet.ParsePacket(linkLayerType, data)
    │
    ├─ Extract<ArpPacket>()      → ARP spoofing check
    ├─ Extract<IPPacket>()       → IPv4
    ├─ Extract<IPv6Packet>()     → IPv6 (fallback)
    │       │
    │       ├─ Extract<TcpPacket>()
    │       │       srcPort, dstPort, flags (SYN/ACK/FIN/RST/PSH/URG)
    │       │       PayloadData (application bytes)
    │       │
    │       ├─ Extract<UdpPacket>()
    │       │       srcPort, dstPort, PayloadData
    │       │
    │       └─ Protocol == ICMP / ICMPv6
    │
    └─ NetPacket struct (internal representation)
            SrcIP, DstIP, SrcPort, DstPort
            Protocol ("TCP"/"UDP"/"ICMP"/"IP")
            Payload (Latin-1 string for regex matching)
            PayloadBytes (raw bytes for binary parsing)
            Size, IsSyn, HasNullFlags, HasXmasFlags
            Timestamp
```

**Why Latin-1 for payload?** Regex matching works on strings. Latin-1 is a 1:1 byte-to-character encoding — no multi-byte sequences, no lossy conversions. Every byte value 0x00–0xFF maps to a character, so the payload string has the exact same length as the byte array and regex character positions correspond directly to byte positions.

**PayloadBytes is kept separately** for cases that need actual binary parsing — JA3 fingerprinting, DNS question name extraction. Those work on raw bytes, not strings.

---

## 4. Behavioral Detection

Behavioral detection looks at *patterns of traffic over time*, not individual packet content. It uses `SlidingCounter` — a queue-based sliding window that evicts entries older than the window duration on every increment.

### SYN Flood

**What it detects:** A source IP sending an abnormally high number of TCP SYN packets in a short time — the classic SYN flood denial-of-service attack.

**How it works:**
```
For each TCP SYN packet (Synchronize=true, Acknowledgment=false):
    counter = _synCounters[srcIP]  ← one SlidingCounter per source IP
    count = counter.Increment()    ← evicts old entries, adds now, returns current count
    if count > SynFloodThreshold (default: 200):
        fire "SYN Flood Detected" CRITICAL alert
```

**Default threshold:** 200 SYN packets within 5 seconds from the same source IP.

**Why SYN specifically?** In a normal TCP connection, SYN is sent once to initiate. An attacker sending thousands of SYNs is trying to exhaust the server's half-open connection table, preventing legitimate connections.

### ICMP Flood

Same pattern, applied to ICMP (ping) packets. Catches ping floods (Smurf attack variants) and ICMP-based DoS.

**Default threshold:** 100 ICMP packets within 10 seconds.

### UDP Flood

Same pattern, applied to UDP traffic. Catches UDP amplification attacks (DNS, NTP, SSDP reflection).

**Default threshold:** 500 UDP packets within 5 seconds.

### Port Scan

**What it detects:** A source IP connecting to many different destination ports in a short time — classic reconnaissance.

**How it works:**
```
For each TCP packet:
    portSet = _portScanSets[srcIP]     ← HashSet<int> of ports seen
    windowStart = _portScanWindows[srcIP]
    
    if (now - windowStart) > PortScanWindowSec:
        portSet.Clear()                ← reset window
        windowStart = now
    
    portSet.Add(dstPort)
    
    if portSet.Count > PortScanThreshold (default: 25):
        fire "Port Scan Detected" MEDIUM alert
        portSet.Clear()                ← reset to avoid repeated alerts
```

**Why reset after firing?** Without resetting, every subsequent port would trigger another alert. One alert per scan attempt is the right behavior.

**Default threshold:** 25 distinct destination ports within 10 seconds.

### Brute Force

**What it detects:** Repeated connection attempts to the same service — SSH password guessing, RDP brute force, FTP credential stuffing.

**How it works:**
```
For each TCP SYN to a specific port:
    key = "srcIP:dstPort"            ← unique per attacker-service pair
    counter = _bruteForce[key]       ← SlidingCounter
    count = counter.Increment()
    
    if count == BruteForceThreshold (default: 10):
        serviceName = port switch { 22→"SSH", 3389→"RDP", 21→"FTP", ... }
        fire "{serviceName} Brute Force" HIGH alert
```

**Why SYN-based?** Each password attempt requires a new TCP connection (SYN). Counting SYNs to a specific port is a reliable proxy for counting authentication attempts at the protocol level, without needing to parse application-layer credentials.

**Default threshold:** 10 connection attempts to the same port within 60 seconds.

---

## 5. Signature Matching

Every packet is checked against all enabled Signature-type rules after behavioral detection. A rule matches when ALL specified conditions are true.

### Rule structure

```
IDSRule {
    Protocol       "TCP" | "UDP" | "ICMP" | "any"
    SourceIP       exact IP or CIDR (e.g. "192.168.1.0/24") or "any"
    DestinationIP  exact IP or CIDR or "any"
    SourcePort     port, comma-list, or range "1024:65535" or "any"
    DestinationPort  same format
    Pattern        regex applied to payload (empty = match any payload)
    RequireNullFlags  bool — match only TCP packets with NO flags set
    RequireXmasFlags  bool — match only TCP FIN+PSH+URG packets
    MinPacketSize  int — minimum total packet size in bytes (0 = disabled)
    MaxPacketSize  int — maximum total packet size in bytes (0 = disabled)
    AlertThreshold int — fire only after N matches in AlertWindowSec (0 = first match)
    AlertWindowSec int — time window for AlertThreshold
}
```

### Matching logic

```
MatchesRule(packet, rule):
    if rule.Protocol != "any" and rule.Protocol != packet.Protocol → NO MATCH
    if rule.SourceIP != "any" and !IpMatches(packet.SrcIP, rule.SourceIP) → NO MATCH
    if rule.DestIP != "any" and !IpMatches(packet.DstIP, rule.DestIP) → NO MATCH
    if rule.DstPort != "any" and !PortMatches(packet.DstPort, rule.DstPort) → NO MATCH
    if rule.SrcPort != "any" and !PortMatches(packet.SrcPort, rule.SrcPort) → NO MATCH
    if rule.Pattern != "" and !regex.IsMatch(packet.Payload) → NO MATCH
    if rule.RequireNullFlags and !packet.HasNullFlags → NO MATCH
    if rule.RequireXmasFlags and !packet.HasXmasFlags → NO MATCH
    if rule.MinPacketSize > 0 and packet.Size < rule.MinPacketSize → NO MATCH
    if rule.MaxPacketSize > 0 and packet.Size > rule.MaxPacketSize → NO MATCH
    → MATCH
```

### CIDR IP matching

```
IpMatches("192.168.1.45", "192.168.0.0/16"):
    prefix = 16
    mask = 0xFFFF0000  (16 ones followed by 16 zeros)
    network_masked = 192.168.0.0 & mask = 192.168.0.0
    packet_masked  = 192.168.1.45 & mask = 192.168.0.0
    → MATCH (both reduce to the same network address)
```

### Port range matching

Ports are specified as comma-separated values and/or colon-delimited ranges:
- `"80"` — exact match
- `"80,443,8080"` — any of these
- `"1024:65535"` — any port in this range
- `"80,443,8080:8090"` — combination

### Regex caching

Compiling a regex from a string is expensive (microseconds). With hundreds of packets per second and 40 rules, recompiling would cost millions of operations per second. PrivaCore maintains a `ConcurrentDictionary<string, Regex>` that stores compiled regex objects keyed on the pattern string. Each pattern is compiled exactly once and reused for every subsequent packet.

### Per-rule alert threshold

Rules with `AlertThreshold > 0` use a per-rule `SlidingCounter`. The alert fires only when the rule matches `AlertThreshold` times within `AlertWindowSec` seconds. This prevents a single scanner or automated tool from flooding the alert list with hundreds of identical hits — you get one alert for the batch, not one per packet.

### Alert deduplication

Even without per-rule thresholds, a 10-second cooldown per unique `(ruleId, srcIP, dstPort)` combination prevents repeated alerts from the same source hitting the same rule in quick succession.

---

## 6. Advanced Detection

### ARP Spoofing

**What it is:** An attacker sends fake ARP (Address Resolution Protocol) replies to poison the ARP cache of other hosts — mapping their IP to the attacker's MAC address. All traffic intended for the victim gets sent to the attacker instead (man-in-the-middle).

**How PrivaCore detects it:**
```
_arpTable: Dictionary<string, string>  ← IP → last seen MAC

For each ARP Reply packet:
    ip  = arp.SenderProtocolAddress
    mac = arp.SenderHardwareAddress
    
    if _arpTable contains ip:
        if _arpTable[ip] != mac:
            → FIRE "ARP Spoofing Detected" CRITICAL
              (IP {x} changed MAC from {old} to {new})
    
    _arpTable[ip] = mac  ← update table
```

**30-second deduplication** on `(ip, newMac)` pair prevents alert storms during an active MITM.

### DNS Tunneling

**What it is:** Attackers encode data inside DNS queries to exfiltrate information or establish a covert C2 channel. The subdomain portion of the DNS query carries the data — for example `aGVsbG8gd29ybGQ.evil.com` (base64-encoded data as the subdomain).

**How PrivaCore detects it:**

Step 1 — Parse the DNS wire format:
```
UDP payload bytes:
[0-1]  Transaction ID
[2-3]  Flags
[4-5]  Question count
[6-7]  Answer count
[8-9]  Authority count
[10-11] Additional count
[12+]  Questions section
    Each question = sequence of length-prefixed labels:
    [len][label][len][label]...[0x00] (null terminator)
```

PrivaCore reads the question section, extracts each label, and reconstructs the full domain name by joining with dots.

Step 2 — Analyse the domain:
```
subdomain = everything before the last two labels (the base domain)
            e.g. for "aGVsbG8gd29ybGQ.evil.com" → subdomain = "aGVsbG8gd29ybGQ"

Shannon entropy of subdomain:
    H = -Σ (p_i × log2(p_i))
    where p_i = frequency of character i / total characters

English text entropy ≈ 3.0–3.5 bits
Random/base64 data entropy ≈ 5.0–6.0 bits

If subdomain.Length > 40 OR entropy > 3.5:
    → FIRE "DNS Tunneling / Data Exfiltration" HIGH
```

**Rate limiting:** Maximum 3 alerts per source IP per 60 seconds to prevent alert storms from a single actively tunneling host.

### JA3 TLS Fingerprinting

**What it is:** When a TLS client (browser, malware, tool) initiates a connection, it sends a "ClientHello" message listing its supported cipher suites, extensions, and elliptic curves. The specific combination is characteristic of the software that generated it. JA3 is an MD5 hash of these values — a fingerprint of the TLS client library.

**Why it matters:** Malware like Meterpreter and Cobalt Strike have distinctive JA3 hashes because they use specific SSL/TLS library versions with specific default configurations. Even if they use port 443 (HTTPS, which looks legitimate), their JA3 hash identifies them.

**How PrivaCore computes it:**

Step 1 — Identify TLS ClientHello:
```
TCP payload bytes[0] == 0x16  → TLS record type (Handshake)
TCP payload bytes[1] == 0x03  → TLS version major (3 = SSL 3.0 / TLS 1.x)
TCP payload bytes[5] == 0x01  → Handshake type (1 = ClientHello)
```

Step 2 — Parse the ClientHello structure:
```
Offset 9:  TLS version (2 bytes)      → part of JA3
Offset 11: Random (32 bytes)          → skip
Offset 43: SessionID length (1 byte)  → skip session ID
Then:  CipherSuites length (2 bytes)
       CipherSuites (variable)        → part of JA3
       CompressionMethods             → skip
       Extensions length (2 bytes)
       Extensions (variable):
           Each extension:
               Type (2 bytes)         → part of JA3
               Length (2 bytes)
               Data (variable)
               
           Extension 0x000a (supported_groups):
               Elliptic curves list   → part of JA3
           Extension 0x000b (ec_point_formats):
               Point formats list     → part of JA3
```

Step 3 — Filter GREASE values:
RFC 8701 defines "GREASE" — specific values (0x0A0A, 0x1A1A, 0x2A2A... 0xFAFA) that clients advertise to test server tolerance of unknown values. These are NOT part of the client's actual capabilities and must be excluded from JA3.

Step 4 — Build JA3 string and hash:
```
JA3 string = "{TLSVersion},{CipherSuites},{Extensions},{EllipticCurves},{ECPointFormats}"
             values separated by "-", groups separated by ","
             e.g. "771,4866-4867-4865,0-23-65281-10-11-35-16-5-13,29-23-24,0"

JA3 hash = MD5(JA3 string) = "aaa85ad674631a8cee71234d2e2e5b21"
```

Step 5 — Check against known-malicious hashes:
```
Known bad hashes include:
  d4a43ef1fa0f0786027c2b0e4d2d2a77  ← Metasploit Meterpreter
  e7d705a3286e19ea42f587b344ee6865  ← Cobalt Strike default
  6bea65232d16d69e4b62db35a575e46d  ← Cobalt Strike v4
  72a589da586844d7f0818ce684948eea  ← Cobalt Strike beacon
  (+ more)
```

The JA3 hash and info string are attached to the `IDSAlert` object so you can look them up against community databases (e.g. sslbl.abuse.ch).

---

## 7. Alert Lifecycle

Every detection path — behavioral, signature, ARP, DNS, JA3 — eventually calls `EmitAlert(IDSAlert)`.

```
EmitAlert(alert):
    │
    ├─ IsAllowlisted(alert.SourceIP, alert.RuleId)?
    │       if YES → drop silently, return
    │
    ├─ Insert alert into _alerts (ObservableCollection, max 5000)
    │
    ├─ Increment _totalThreats counter
    │
    ├─ Set _alertsDirty = true  (triggers save within 5 seconds)
    │
    ├─ Fire AlertGenerated event → NetworkIDSDashboardPage.OnAlertGenerated()
    │       → Insert into _filteredAlerts (if passes current filter)
    │       → Update threat counter on UI
    │       → Show toast for High/Critical
    │
    ├─ IpsMode == true AND severity == Critical?
    │       → AutoBlock(alert.SourceIP)
    │           → IpsBlocklistService.BlockIp(ip)
    │               → netsh advfirewall firewall add rule ...
    │           → Add to _blockedIps list
    │           → alert.IsBlocked = true
    │
    └─ TrackCorrelation(alert)  ← feed into kill-chain engine
```

### Alert fields

| Field | Description |
|---|---|
| `AlertId` | Unique GUID per alert |
| `Timestamp` | When the packet was captured |
| `SourceIP` / `SourcePort` | Where it came from |
| `DestinationIP` / `DestinationPort` | Where it was going |
| `Protocol` | TCP / UDP / ICMP / ARP / multi |
| `Severity` | Info / Low / Medium / High / Critical |
| `AlertType` | Human-readable name (e.g. "SQL Injection UNION") |
| `AttackCategory` | Broad category (e.g. "Web Attack", "Malware/C2") |
| `RuleId` | Which rule fired ("SIG-004", "BEHAVIORAL", "CORRELATION") |
| `Description` | What the rule means |
| `PayloadPreview` | First 200 bytes of application payload |
| `PacketSize` | Total frame size in bytes |
| `JA3Hash` / `JA3Info` | TLS fingerprint (if applicable) |
| `Country` / `ISP` / `ASN` | GeoIP enrichment (populated on demand) |
| `IsBlocked` | Whether IPS mode auto-blocked this source |
| `IsAcknowledged` | Whether an analyst has reviewed it |

---

## 8. Kill-Chain Correlation

A kill chain is the sequence of steps an attacker takes: reconnaissance → initial access → execution → persistence → command and control. PrivaCore watches for this progression from a single source IP.

### How it works

```
_srcCorr: ConcurrentDictionary<string, List<(category, timestamp)>>
           ← per source IP, list of all attack categories seen with timestamps

TrackCorrelation(alert):
    list = _srcCorr[alert.SourceIP]
    
    Prune entries older than 5 minutes from list
    
    Add (alert.AttackCategory, alert.Timestamp)
    
    categories = distinct categories in list
    
    hasRecon   = categories contains "Reconnaissance"
    hasExploit = categories contains "Web Attack" or "Exploit"
    hasC2      = categories contains "Malware/C2" or "Brute Force"
    
    if hasRecon AND hasExploit AND hasC2:
        (with 5-minute cooldown per source IP)
        → Fire "Kill Chain Detected" CRITICAL alert
        → Fire KillChainDetected event (updates Correlation tab banner)
```

### Why these three categories?

- **Reconnaissance** (port scan, null/XMAS scan, scanner UA) — attacker mapping the target
- **Exploit/Web Attack** (SQLi, XSS, RCE, Shellshock, Log4Shell...) — attacker gaining access
- **Malware/C2** (reverse shell ports, Meterpreter, webshell, brute force) — attacker establishing persistence or control

All three from the same source IP within 5 minutes is a very strong indicator of an active, multi-stage attack against a specific target. A legitimate user or scanner will rarely trigger all three.

### Correlation tab

The **🔗 Correlation** tab shows a live view of all source IPs with recent alert activity, even before a kill chain is detected. You can spot an IP that's hit Reconnaissance + Web Attack but not yet C2 — and act before the final stage.

---

## 9. IPS Mode

PrivaCore can automatically block attacker IP addresses at the Windows Firewall level.

### How blocking works

```
IpsBlocklistService.BlockIp("1.2.3.4"):
    Process: netsh
    Args:    advfirewall firewall add rule
             name="PrivaCore_Block_1.2.3.4"
             dir=in
             action=block
             remoteip=1.2.3.4
             enable=yes
             protocol=any
    
    → Windows Firewall immediately drops all inbound packets from 1.2.3.4
```

### What triggers auto-block

Only **Critical severity** alerts trigger auto-block when IPS mode is enabled. High and lower are detection-only. This is intentional — Critical means something definitive (confirmed Meterpreter, Log4Shell exploitation, kill chain completion, ARP spoofing). Medium and below could be noisy in some environments.

### Unblocking

```
IpsBlocklistService.UnblockIp("1.2.3.4"):
    netsh advfirewall firewall delete rule name="PrivaCore_Block_1.2.3.4"
```

All rules are named with the `PrivaCore_Block_` prefix so they can be found and cleaned up. The **IPS tab** shows every blocked IP with a per-row Unblock button, or you can Unblock All to clear everything at once.

### Requirements

IPS mode requires Administrator privileges — Windows Firewall policy can only be modified by elevated processes.

---

## 10. Host IDS Architecture

The HIDS runs in `HostIDSDashboardPage`. Unlike NIDS which is event-driven (packet arrival), HIDS is primarily **poll-based** — it takes a snapshot of system state every N seconds and compares it to the previous snapshot.

```
DispatcherTimer (every N seconds, default 5)
        │
        │ fires → Task.Run(SafePollAll)   ← background thread
        │
        ▼
     SafePollAll()
        │
        ├─ PollWindowsEvents()    ← EventLog
        ├─ PollProcesses()        ← WMI Win32_Process
        ├─ PollNetworkConnections() ← netstat -ano
        ├─ PollRegistryChanges()  ← Registry API diff
        ├─ PollServices()         ← WMI Win32_Service
        ├─ PollScheduledTasks()   ← schtasks.exe
        ├─ PollSessions()         ← query session
        ├─ PollDnsCache()         ← ipconfig /displaydns
        └─ UpdateSystemHealth()
```

**FileSystemWatcher** is event-driven (OS notifies on file change), not polled.

**Baselines** are taken once at monitoring start:
- Service list → `_svcBaseline` (HashSet)
- Scheduled task list → `_taskBaseline` (HashSet)
- Session list → `_sessionBaseline` (HashSet)
- Registry values → `_regSnapshot` (Dictionary)
- File hashes → `_hashBaseline` (Dictionary, built incrementally)

Everything after the baseline is **delta detection** — only new/changed/deleted items generate alerts.

---

## 11. File System Monitoring

### How FileSystemWatcher works

Windows provides `FileSystemWatcher` — a .NET wrapper around the Win32 `ReadDirectoryChangesW` API. The OS notifies your process whenever a file in the watched directory is created, changed, deleted, or renamed. This is purely event-driven — no polling, no CPU overhead when nothing changes.

PrivaCore watches:
- `C:\Windows` (non-recursive)
- `C:\Windows\System32` (non-recursive)
- `C:\Windows\SysWOW64` (non-recursive)
- Any custom paths from config (recursive)

### Severity classification

```
OnFileChanged(changeType, path):
    
    path.contains("system32") or "syswow64" → "Critical"
    path.endsWith(".exe", ".dll", ".sys")    → "High"
    path.endsWith(".bat", ".ps1", ".vbs",
                  ".js", ".wsf")             → "High"
    anything else                            → "Info"
```

### File hashing

When `EnableFileHashing = true` (from config) and a Critical or High event fires:

```
hash = SHA256(File.ReadAllBytes(path))

if path already in _hashBaseline:
    if hash != _hashBaseline[path]:
        escalate severity to CRITICAL  ← hash changed = file was modified
else:
    _hashBaseline[path] = hash  ← first time seeing this file

Show hash (first 16 hex chars) inline in the File Integrity tab row
```

Hash computation is guarded by try/catch — system files actively in use (e.g. `ntdll.dll`, pagefile-backed DLLs) can raise `IOException` on read. The hash is skipped silently if the file is inaccessible.

---

## 12. Windows Security Event Log

### The polling approach

Windows Security Event Log is read every 5 seconds. PrivaCore queries for all events generated in the last 5 minutes, skipping any it has already seen (tracked by `entry.Index`):

```csharp
var log = new EventLog("Security");
var recent = log.Entries
    .Cast<EventLogEntry>()
    .Where(e => e.TimeGenerated > DateTime.Now.AddMinutes(-5))
    .OrderByDescending(e => e.TimeGenerated)
    .Take(30);
```

### Event IDs monitored

| ID | Name | Severity | Why it matters |
|---|---|---|---|
| 1102 | Audit log cleared | **Critical** | Attackers erase logs to cover tracks — this is almost always malicious |
| 4625 | Failed logon | **Critical** | Brute force attempts, credential stuffing |
| 4697 | Service installed | **Critical** | Malware persistence via service installation |
| 7045 | New service registered | **Critical** | Same as 4697 but from Service Control Manager |
| 4648 | Explicit credentials used | **High** | Pass-the-hash, lateral movement with alternate credentials |
| 4672 | Special privileges assigned | **High** | Privilege escalation — SeDebugPrivilege, SeTcbPrivilege etc. |
| 4698 | Scheduled task created | **High** | Malware persistence via scheduled task |
| 4720 | User account created | **High** | Backdoor account creation |
| 4732 | User added to local Administrators | **High** | Privilege escalation via group membership |
| 4756 | User added to security group | **High** | Lateral movement setup |
| 4776 | NTLM authentication | **High** | NTLM relay attacks, Pass-the-Hash indicators |
| 4688 | New process created | **Medium** | Process execution tracking |
| 4663 | Object access | **Medium** | Sensitive file/registry access |
| 4624 | Successful logon | **Info** | Baseline — who logged in successfully |

### Structured field extraction

Windows Event messages are multi-line text like:
```
An account was successfully logged on.

Subject:
    Security ID:    S-1-5-18
    Account Name:   SYSTEM

New Logon:
    Account Name:   john.doe
    Logon Type:     10

Process Information:
    Process Name:   C:\Windows\System32\svchost.exe
```

PrivaCore's `ParseEventFields()` splits this on colons and builds a dictionary, then pulls the most relevant fields:
- `Account Name` → who
- `Process Name` → what triggered it (only filename, not full path)
- Combines into: `User: john.doe  Proc: svchost.exe`

---

## 13. Process Monitoring

### Why WMI instead of Process.GetProcesses()

`Process.GetProcesses()` gives you: PID, name, and RAM usage. That's it. It cannot give you the command line (the arguments a process was started with) or the parent process.

WMI `Win32_Process` gives you everything:
```sql
SELECT ProcessId, Name, ExecutablePath, CommandLine, ParentProcessId, WorkingSetSize 
FROM Win32_Process
```

The command line is the single most important field for detecting malicious PowerShell, LOLBin abuse, and fileless attacks.

### Detection passes

**Pass 1 — Name blacklist:**
```
Known attack tools: mimikatz, procdump, pwdump, meterpreter, ncat, netcat,
psexec, cobalt, empire, beacon, lazagne, sharphound, bloodhound, rubeus,
seatbelt, powersploit, covenant, crackmapexec, responder, kerbrute, hashcat...
(+ user-defined extras from config)
```

**Pass 2 — Parent-child anomaly:**
```
Dangerous parent → child combinations:
    winword  → cmd, powershell, pwsh, wscript, cscript, mshta, wmic...
    excel    → cmd, powershell, pwsh, wscript, cscript, mshta, wmic...
    powerpnt → cmd, powershell, pwsh, wscript, cscript, mshta...
    outlook  → cmd, powershell, pwsh, wscript, cscript...
    chrome   → cmd, powershell, pwsh, wscript, cscript
    firefox  → cmd, powershell, pwsh, wscript, cscript
    msedge   → cmd, powershell, pwsh, wscript, cscript
    iexplore → cmd, powershell, pwsh, wscript, cscript, mshta
```

When Word spawns PowerShell, that is almost certainly a macro executing a payload. This is the exact execution chain used in the majority of phishing attacks.

**Pass 3 — Suspicious execution path:**
```
Execution from:
    \temp\          → High (staging area)
    \tmp\           → High
    \appdata\local\temp\ → High (common malware staging)
    \public\        → High (world-writeable)
    \users\public\  → High
```

Legitimate software almost never runs from temp directories. Malware drops itself there because those directories are always writeable, even without admin.

**Pass 4 — PowerShell flags:**
```
Process name is "powershell" or "pwsh" AND command line contains:
    -enc / -encodedcommand   → base64 encoded payload (evasion)
    -w hidden               → hidden window (evasion)
    -nop / -noprofile       → bypass profile restrictions
    bypass                  → Set-ExecutionPolicy Bypass or -ExecutionPolicy Bypass
```

Legitimate PowerShell scripts rarely need all these flags simultaneously.

---

## 14. Registry Monitoring

### Why these registry locations

The Windows registry has thousands of keys. Attackers almost always use a small number of well-known locations for persistence:

| Key | Why attackers use it |
|---|---|
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` | Runs for ALL users at login |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce` | Runs once for ALL users, self-deletes |
| `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` | Runs for current user at login |
| `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce` | Runs once for current user |
| `HKLM\SYSTEM\CurrentControlSet\Services` | Service definitions — kernel-level persistence |

Custom keys can be added via the config file (`additionalRegistryKeys`).

### How diffing works

```
On monitoring start:
    _regSnapshot = BuildRegSnapshot()
    ← snapshot all value names and their data as strings
    ← stored as Dictionary<"HKLM\Run\SomeName", "C:\path\malware.exe">

Every 5 seconds:
    current = BuildRegSnapshot()
    
    For each key in current:
        if key in _regSnapshot:
            if current[key] != _regSnapshot[key]:
                → "Registry MODIFIED" CRITICAL
                  detail: "HKLM\Run\SomeName [old value] → [new value]"
        else:
            → "Registry ADDED" CRITICAL
              detail: "HKLM\Run\SomeName = C:\path\malware.exe"
    
    For each key in _regSnapshot NOT in current:
        → "Registry DELETED" HIGH
          detail: "HKLM\Run\SomeName"
    
    _regSnapshot = current
```

**Why Critical for any registry change?** The Run keys exist solely to execute programs at startup. Any change to them outside of a known software installation is suspicious. Unlike network traffic or process creation (which have many legitimate causes), changes to Run keys are rare in normal operation and high-value for attackers.

---

## 15. Services Monitoring

Windows services run in the background, often as SYSTEM, and start automatically. They are one of the most common and powerful persistence mechanisms available to malware.

### How baseline works

```
On monitoring start:
    _svcBaseline = HashSet of all service names currently installed
                   (via WMI Win32_Service query)
    _baselinesSet = true

Every 5 seconds:
    current = WMI Win32_Service query (all services)
    
    For each service in current:
        if service.Name NOT in _svcBaseline:
            → "NEW SERVICE INSTALLED" CRITICAL
            → Toast notification
            → Add to _svcBaseline (don't re-alert)
        
        if service.PathName contains \temp\ or \public\:
            → Mark severity = High (suspicious service path)
```

**Why only new services?** Existing services were installed before monitoring started and are considered the known baseline. Only services that appear AFTER monitoring begins are anomalies worth alerting on.

---

## 16. Scheduled Tasks Monitoring

Scheduled tasks can run arbitrary code at system startup, user login, or on a timer — another common persistence mechanism.

### How it works

```
On monitoring start:
    Run: schtasks /query /fo csv /v
    Parse CSV output
    _taskBaseline = HashSet of all task names

Every 5 seconds:
    Run: schtasks /query /fo csv /v  (again)
    Parse
    
    For each task:
        if task.Name NOT in _taskBaseline:
            → "NEW SCHEDULED TASK" HIGH alert
            → Add to _taskBaseline
        
        if task.RunAs contains "SYSTEM":
            → severity = Medium (SYSTEM tasks are powerful)
```

The `schtasks` command returns structured CSV with: task name, status, next run time, last run time, author, and the "Run As" user. The Run As field is particularly important — a task running as SYSTEM has full machine control.

---

## 17. Session Monitoring

Login sessions are another indicator of compromise — an unexpected RDP session at 3am is worth knowing about.

### How it works

```
On monitoring start:
    Run: query session
    Parse text output into session list
    _sessionBaseline = HashSet of session names

Every 5 seconds:
    Run: query session  (again)
    
    For each session:
        if session.Name NOT in _sessionBaseline:
            if session is RDP (name starts with "rdp-tcp" or "rdp-ica"):
                → "RDP SESSION OPENED" HIGH alert
            else:
                → "NEW SESSION" MEDIUM alert
            → Add to _sessionBaseline
```

RDP sessions get Higher severity than local console sessions because remote access from an unexpected source is a stronger indicator of compromise.

---

## 18. DNS Cache Monitoring

Every DNS query your machine makes gets cached in the Windows DNS Resolver Cache. If malware is beaconing to a C2 server, the domain it resolves will appear in the cache.

### How it works

```
Every 5 seconds:
    Run: ipconfig /displaydns
    Parse output into (domain, recordType, data) triples
    Deduplicate
    
    For each domain:
        Analyse:
            subdomain = labels before the last two (the base domain)
            
            1. Shannon entropy of subdomain:
               H = -Σ(p_i × log2(p_i))
               Normal English: ~3.0 bits
               DGA random: ~5.0-6.0 bits
               Threshold: 3.5 bits → flag as suspicious
            
            2. Subdomain length:
               > 45 chars → possible DNS tunnel (data encoded in subdomain)
            
            3. Suspicious TLD:
               .tk .ml .ga .cf .gq .pw .top .xyz .work .click .download
               → these are abused heavily by malware operators
            
            4. Label depth:
               > 5 dot-separated labels → unusual structure
```

### What Shannon entropy means practically

- `google.com` → subdomain="" → entropy=0 → clean
- `mail.google.com` → subdomain="mail" → entropy ~2.1 → clean
- `aHR0cHM6Ly9ldmlsLmNvbQ.evil.com` → subdomain has base64 → entropy ~5.8 → flagged
- `ab3d9f2c1e.update.evil.tk` → random hex + suspicious TLD → double flag

---

## 19. Allowlist

The allowlist prevents alerts from being generated for known-good traffic. Without it, certain rules will constantly fire on legitimate activity (e.g., your local network scanner triggering the port scan rule, or your email client triggering the SMTP rule).

### Structure

```
AllowlistEntry {
    IpOrCidr  "192.168.0.0/16" or "10.0.0.5" etc.
    RuleId    "SIG-017" or null (null = suppress ALL rules for this IP)
    Note      "Internal RDP" (human-readable label)
    ExpiresAt DateTime? (null = never expires)
}
```

### How checking works

```
EmitAlert(alert):
    For each entry in _allowlist:
        if entry.IsExpired → skip
        if IpMatches(alert.SourceIP, entry.IpOrCidr):
            if entry.RuleId == null:
                → suppress ALL alerts from this IP
                → drop alert, return
            if entry.RuleId == alert.RuleId:
                → suppress only THIS rule for this IP
                → drop alert, return
    → not allowlisted, proceed with alert
```

### Example use cases

- `192.168.0.0/16, null` — suppress everything from your LAN (dangerous, use sparingly)
- `192.168.0.0/16, SIG-002` — suppress SMB alerts from LAN (local file sharing is expected)
- `10.0.0.5, SIG-013` — suppress scanner UA alert for your Nessus scanner
- `127.0.0.1, null` — suppress all alerts from localhost (development/testing)
- `10.0.0.0/8, SIG-017, expires: 2026-06-01` — temporary RDP allowlist for a project

---

## 20. Configuration System

A single JSON file (`PrivaCoreConfig`) can configure every aspect of both NIDS and HIDS.

### Config blocks

**NIDS block (`nids`):**
```json
{
  "replaceRules": false,
  "ipsMode": false,
  "behavioralThresholds": {
    "synFloodThreshold": 200, "synFloodWindowSec": 5,
    "icmpFloodThreshold": 100, "icmpFloodWindowSec": 10,
    "udpFloodThreshold": 500, "udpFloodWindowSec": 5,
    "portScanThreshold": 25, "portScanWindowSec": 10,
    "bruteForceThreshold": 10, "bruteForceWindowSec": 60
  },
  "allowlist": [ ... ],
  "rules": [ ... ]
}
```

**HIDS block (`hids`):**
```json
{
  "pollIntervalSeconds": 5,
  "customWatchPaths": [],
  "additionalProcessBlacklist": [],
  "additionalSuspiciousPorts": [],
  "additionalRegistryKeys": [],
  "enableFileHashing": true,
  "enableScheduledTaskMonitor": true,
  "enableServiceMonitor": true,
  "enableDnsMonitor": true,
  "enableSessionMonitor": true,
  "enableParentChildDetection": true
}
```

### How import works

1. JSON is deserialized into `PrivaCoreConfig`
2. `ConfigManager.Apply()` is called
3. NIDS changes take effect immediately on the live `IDSEngine` instance
4. HIDS changes update the `ConfigManager.Hids` singleton — a static object that the HIDS page reads on every monitoring start
5. Config is saved to `%AppData%\PrivaCore\Config\last_config.json` and reloaded on next launch

---

## 21. Data Persistence

All IDS state is saved to disk and reloaded on startup.

```
%AppData%\Roaming\PrivaCore\
├── IDS\
│   ├── alerts.json         ← NIDS alert history (max 5000)
│   ├── rules.json          ← Current ruleset (modified rules + custom rules)
│   ├── behavioral_settings.json ← Threshold configuration
│   ├── allowlist.json      ← Allowlist entries
│   └── blocked.json        ← IPS-blocked IP list
├── HIDS\
│   └── events.json         ← HIDS event history (last 1000 events)
└── Config\
    └── last_config.json    ← Last imported config (auto-reapplied on launch)
```

### Save strategy

A background task checks dirty flags every 5 seconds:
```
every 5s:
    if _alertsDirty:    save alerts.json
    if _rulesDirty:     save rules.json
    if _allowlistDirty: save allowlist.json
    if _blockedDirty:   save blocked.json
    
    if (now - _lastPrune) > 60s:
        prune idle behavioral counters
        prune _recentAlerts deduplication cache
        remove expired allowlist entries
```

This batching strategy means file I/O happens at most once every 5 seconds regardless of how many alerts fire. A packet storm generating 1000 alerts per second won't hammer the disk.

---

## 22. Live Traffic Graph

The graph strip at the top of the NIDS dashboard visualises the last 2 minutes of network activity.

### Data collection

Every time `RefreshUI()` runs (every 2 seconds):
```
pktDelta  = stats.TotalPackets - _graphLastPktCount
pktPerSec = pktDelta / 2.0  (timer interval)
alertDelta = stats.TotalAlerts - _graphLastAlertCount

→ Enqueue GraphPoint(pktPerSec, alertDelta, DateTime.Now)
→ Dequeue if buffer > 60 points  (60 × 2s = 120s = 2 minutes)
```

### Rendering

The canvas renders three layers:
1. **Polygon** (cyan fill) — area under the packet rate curve
2. **Polyline** (cyan line) — packet rate
3. **Polyline** (red line) — alert rate (only drawn if any alerts occurred)
4. **Line elements** — three dashed horizontal gridlines at 25/50/75% of max

Points are mapped to pixel coordinates:
```
x = canvasWidth × (pointIndex / (totalPoints - 1))
    ← right-aligned: newest point always at far right

y = canvasHeight - canvasHeight × (1 - 0.12) × (value / maxValue)
    ← 12% top padding so the line never touches the very top edge
```

Y-axis auto-scales to the current maximum value in the buffer. Labels use `k` suffix above 1000 pkt/s.

---

## 23. Alert Severity Scale

| Severity | Color | Meaning | Example |
|---|---|---|---|
| **Critical** | Red `#F44747` | Definitive threat — requires immediate action | Meterpreter payload, ARP spoofing, Kill Chain, Log4Shell |
| **High** | Orange `#FF8C00` | Strong indicator — likely malicious | SYN flood, XSS attack, brute force, suspicious process |
| **Medium** | Yellow `#FFA500` | Moderate indicator — investigate | Port scan, path traversal, large ICMP packet |
| **Low** | Teal `#4EC9B0` | Informational — may be legitimate | SMB access, RDP connection, FTP anonymous login |
| **Info** | Blue `#007ACC` | Pure information — no threat | Successful logon, HIDS started |

---

## 24. Threading Model

Understanding the threading model matters for stability and correctness.

### NIDS

```
SharpPcap capture thread
    → OnPacketArrival() [runs on capture thread, NOT UI thread]
        → All detection logic runs here (behavioral, signatures, JA3, ARP, DNS)
        → EmitAlert() → fires event → handler runs on capture thread
            → _alerts.Insert() [locked]
            → AlertGenerated?.Invoke()
                → NetworkIDSDashboardPage.OnAlertGenerated()
                    → Dispatcher.InvokeAsync(() => UI update)
                                            ← back to UI thread for actual display

StatsUpdated event fires every 50 packets
    → Also Dispatcher.InvokeAsync for UI updates

DispatcherTimer (every 2 seconds) — fires on UI thread
    → RefreshUI() → UpdateGraphData() → RedrawGraph()
    → RefreshCorrelation() (if correlation tab is open)
```

### HIDS

```
DispatcherTimer tick — fires on UI thread
    → Task.Run(SafePollAll) [immediately off-load to thread pool]
        → PollWindowsEvents()    [background thread, EventLog read]
            → Dispatcher.InvokeAsync(UI update)
        → PollProcesses()        [background thread, WMI query]
            → Dispatcher.InvokeAsync(UI update)
        → [all other polls similarly]
    
    _polling guard flag prevents overlapping polls if one poll
    takes longer than the timer interval

FileSystemWatcher callbacks
    → Fire on a ThreadPool thread (OS callback)
        → Dispatcher.InvokeAsync(UI update) → back to UI thread
```

**The rule:** Only the WPF dispatcher thread may touch UI elements. Every other thread must marshal back to the dispatcher before modifying `ObservableCollection`, `TextBlock.Text`, etc. This is why every poll method ends with `Dispatcher.InvokeAsync(...)`.

---

## 25. Tuning Guide

### Reducing false positives

**The home_lab_config.json included with PrivaCore** already addresses the most common sources of noise. Beyond that:

**If port scan alerts are too frequent:**
- Raise `portScanThreshold` from 25 to 50 and `portScanWindowSec` from 10 to 20
- Or allowlist your scanner's IP against the behavioral rules

**If SMB alerts are constant:**
- Allowlist your LAN range against `SIG-002`: `192.168.0.0/16, SIG-002`

**If RDP alerts are constant:**
- Allowlist your LAN against `SIG-017`: `192.168.0.0/16, SIG-017`

**If localhost is noisy:**
- Allowlist `127.0.0.1` against all rules: `127.0.0.1, null`

**If brute force fires on your own login manager:**
- Raise `bruteForceThreshold` and `bruteForceWindowSec`

### Increasing sensitivity

**If you want to catch slower port scans:**
- Lower `portScanThreshold` to 10, raise `portScanWindowSec` to 60
- This catches horizontal scans that spread attempts over a full minute

**If you want to catch low-rate brute force:**
- Lower `bruteForceThreshold` to 5, raise `bruteForceWindowSec` to 300 (5 minutes)

**For HIDS in high-security environments:**
- Set `enableFileHashing: true` — baseline + detect changed executables
- Add sensitive paths to `customWatchPaths`: web roots, config directories, credential stores
- Add custom registry keys to `additionalRegistryKeys`: COM object registrations, AppInit DLLs, etc.

### Performance tips

- **HIDS poll interval:** The default 5 seconds is good. Lowering to 1 second puts more load on WMI. For most environments, 5–10 seconds is the right balance.
- **File hashing:** SHA256 of large files takes time. `enableFileHashing: true` is recommended but if you have many large files in watched directories and the process tab is slow, consider `enableFileHashing: false`.
- **Scheduled task monitoring:** `schtasks /query /v` is slow on systems with many tasks (hundreds). If it's causing delays, set `enableScheduledTaskMonitor: false`.
- **DNS monitoring:** `ipconfig /displaydns` is fast. Keep it enabled.
