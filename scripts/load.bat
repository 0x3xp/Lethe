@echo off
:: oad.bat
::Signs lethe.sys and registers the driver service.
::sc start Lethe must be run manually after this.
::Run as Administrator.

setlocal

set SCRIPTS=%~dp0
set BIN=%SCRIPTS%..\bin
set SYS=%BIN%\lethe.sys
set SIGNTOOL=%SCRIPTS%signtool.exe

::Sanity checks
if not exist "%SYS%" (
    echo [!] lethe.sys not found at %SYS%
    echo     Run build.bat first.
    exit /b 1
)

if not exist "%SIGNTOOL%" (
    echo [!] signtool.exe not found at %SCRIPTS%signtool.exe
    exit /b 1
)

::Sign
echo [*] Signing lethe.sys...

"%SIGNTOOL%" sign ^
    /fd sha256 ^
    /n "LetheTestCert" ^
    /v ^
    "%SYS%"

if %ERRORLEVEL% NEQ 0 (
    echo [!] Signing failed.
    echo     Make sure LetheTestCert is installed in the certificate store.
    echo     See WIKI.md - Certificate Setup section.
    exit /b 1
)

echo [+] Signed OK

::Register service
echo [*] Registering driver service...

sc create Lethe ^
    type= kernel ^
    binPath= "%SYS%"

if %ERRORLEVEL% NEQ 0 (
    echo [!] sc create failed - service may already exist.
    echo     Run unload.bat first, then retry.
    exit /b 1
)

echo [+] Service registered.
echo.
echo [*] To start Lethe run:
echo     sc start Lethe
echo.
echo [*] Remember to run client.exe BEFORE sc start Lethe.
echo     The client creates the named pipe — driver connects on first DPC tick.