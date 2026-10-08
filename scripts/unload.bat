@echo off
::unload.bat
:: Stops and removes the Lethe driver service.
:: Also removes the lethe.sys file from bin\.
:: Run as Administrator.

setlocal

set SCRIPTS=%~dp0
set BIN=%SCRIPTS%..\bin
set SYS=%BIN%\lethe.sys

::Stop
echo [*] Stopping Lethe...

sc stop Lethe >nul 2>&1

if %ERRORLEVEL% EQU 0 (
    echo [+] Service stopped.
) else (
    echo [~] Service was not running or already stopped.
)

:: Give the driver time to unload cleanly
timeout /t 2 /nobreak >nul

::Delete service
echo [*] Removing service entry...

sc delete Lethe >nul 2>&1

if %ERRORLEVEL% EQU 0 (
    echo [+] Service entry removed.
) else (
    echo [~] Service entry not found or already removed.
)

::Remove signed binary
if exist "%SYS%" (
    del /f /q "%SYS%" >nul 2>&1
    echo [+] lethe.sys removed from bin\.
) else (
    echo [~] lethe.sys not found in bin\ - nothing to remove.
)

::Remove persistence registry key if still present
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\Lethe" /f >nul 2>&1

echo.
echo [+] Unload complete.