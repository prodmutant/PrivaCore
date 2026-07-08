# PrivaCore Agent — deploy on any machine to feed the SIEM

The agent is a tiny, cross-platform (Windows / Linux / macOS) log shipper. Put it on a machine
you want to monitor, point it at your **SIEM collector** (the box running the PrivaCore SIEM
module), and it forwards events over the same secure module channel the console uses.

```
   [ Agent on WEB01 ]  ┐
   [ Agent on DC01  ]  ├──►  SIEM collector (PrivaCore.SIEM, port 9720)  ──►  Console dashboard
   [ Agent on Ubuntu]  ┘            (pipeline → store → search/dashboards)
```

## 1. Build / publish

From the repo root:

```bash
# framework-dependent (needs .NET 8 runtime on the target):
dotnet build PrivaCore.Agent/PrivaCore.Agent.csproj -c Release

# OR self-contained single file for a target OS (no runtime needed on the target):
dotnet publish PrivaCore.Agent/PrivaCore.Agent.csproj -c Release -r linux-x64  --self-contained -p:PublishSingleFile=true
dotnet publish PrivaCore.Agent/PrivaCore.Agent.csproj -c Release -r win-x64    --self-contained -p:PublishSingleFile=true
dotnet publish PrivaCore.Agent/PrivaCore.Agent.csproj -c Release -r osx-x64    --self-contained -p:PublishSingleFile=true
```

Copy the published `privacore-agent` (or `.exe`) to the target machine.

## 2. Configure & run

**Interactive first run** (creates `agent-config.json` next to the exe):

```
privacore-agent
```

**Unattended / scripted** (no config file needed — args bootstrap and save it):

```
privacore-agent --host 192.168.1.50 --port 9720 \
                --user admin --pass <password> --pairing ABCD-EFGH-JKLM \
                --name WEB01 --tail /var/log/auth.log,/var/log/syslog
```

Flags:

| flag | meaning |
|------|---------|
| `--host` / `--port` | collector address (must match the SIEM module's listen port, default 9720) |
| `--user` / `--pass` | the SIEM module's operator credentials |
| `--pairing`         | the SIEM module's deployment pairing code |
| `--name`            | machine name reported to the SIEM (defaults to the OS hostname) |
| `--tail f1,f2`      | comma-separated log files to ship (only **new** lines, cross-OS) |
| `--gen`             | also emit synthetic demo events (handy to verify the flow) |
| `--config <path>`   | use a specific config file |
| `--setup`           | force the interactive setup again |

The agent auto-reconnects with backoff if the collector is unavailable, and a heartbeat keeps
it visible under **SIEM → Sources & Agents**.

## 3. Make sure the collector is reachable

On the **collector** machine, open the inbound firewall for the SIEM port (run as admin):
`Modules/SIEM/Allow-Firewall.cmd` (Windows) — or allow TCP 9720 on Linux/macOS.
