# PrivaCore IDS — standalone module

The IDS module is the PrivaCore app launched in module mode, so it is the **exact
same GUI** (dashboard, setup wizard, rule editor) — only it runs the IDS engine on
this machine and hosts a connection for the console.

## Run
    PROSCANNERCONT.exe --module IDS
(or double-click `Run-IDS-Module.cmd`)

On first run, set the **listen port + username/password + pairing code**. Then the
real IDS dashboard opens and the sensor is reachable from the console:
**Add Module → Intrusion Detection → connect to this host's IP + those credentials.**
