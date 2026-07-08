@echo off
REM PrivaCore IDS module launcher.
REM Runs the PrivaCore app in standalone IDS-module mode (real IDS GUI + host).
REM Deploy the published PrivaCore app on the sensor host and run this.
set APP=%~dp0..\..\PROSCANNERCONT\bin\Debug\net8.0-windows\PROSCANNERCONT.exe
start "PrivaCore IDS" "%APP%" --module IDS
