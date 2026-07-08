@echo off
REM Run as Administrator. Opens the honeypot control channel (so the console can connect)
REM and the default decoy ports (so attackers on the LAN can reach the decoys).
netsh advfirewall firewall add rule name="PrivaCore Honeypot control 9710" dir=in action=allow protocol=TCP localport=9710
netsh advfirewall firewall add rule name="PrivaCore Honeypot decoys" dir=in action=allow protocol=TCP localport=2222,2323,8080
echo Done. Adjust the decoy ports above to match the decoys you run.
pause
