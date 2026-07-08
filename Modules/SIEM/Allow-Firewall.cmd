@echo off
REM Run as Administrator (right-click > Run as administrator).
REM Opens the Windows Firewall so agents and the console can reach the SIEM collector.
REM Change 9720 if you configured a different listen port.
set PORT=9720
netsh advfirewall firewall delete rule name="PrivaCore SIEM %PORT%" >nul 2>&1
netsh advfirewall firewall add rule name="PrivaCore SIEM %PORT%" dir=in action=allow protocol=TCP localport=%PORT%
echo.
echo Allowed inbound TCP %PORT% for the PrivaCore SIEM collector.
pause
