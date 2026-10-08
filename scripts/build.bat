@echo off
setlocal

::Paths
set ROOT=%~dp0..
set DRIVER=%ROOT%\driver
set CLIENT=%ROOT%\client
set BIN=%ROOT%\bin
set OUT=%ROOT%

set WDK_INC=C:\Program Files (x86)\Windows Kits\10\Include\10.0.28000.0\km
set WDK_LIB=C:\Program Files (x86)\Windows Kits\10\Lib\10.0.28000.0\km\x64

::Output dirs 
if not exist "%BIN%" mkdir "%BIN%"

:: DRIVER
echo [*] Building driver...

cl.exe ^
    /kernel ^
    /c ^
    /GS- ^
    /W4 ^
    /WX- ^
    /Zi ^
    /nologo ^
    /Oy- ^
    /I"%WDK_INC%" ^
    /I"%WDK_INC%\crt" ^
    /I"%DRIVER%" ^
    /D_AMD64_ ^
    /DAMD64 ^
    /D_WIN64 ^
    /DNTDDI_VERSION=0x0A000000 ^
    /D_NT_TARGET_VERSION=0x0A000000 ^
    /Fo"%OUT%\lethe.obj" ^
    "%DRIVER%\lethe.c"

if %ERRORLEVEL% NEQ 0 (
    echo [!] Driver compile failed
    exit /b 1
)

link.exe ^
    /DRIVER ^
    /SUBSYSTEM:NATIVE ^
    /NODEFAULTLIB ^
    /NOLOGO ^
    /DEBUG ^
    /ENTRY:DriverEntry ^
    /LIBPATH:"%WDK_LIB%" ^
    ntoskrnl.lib ^
    hal.lib ^
    wdm.lib ^
    "%OUT%\lethe.obj" ^
    /OUT:"%OUT%\lethe.sys" ^
    /PDB:"%OUT%\lethe.pdb"

if %ERRORLEVEL% NEQ 0 (
    echo [!] Driver link failed
    exit /b 1
)

:: Move final artifacts to bin\
copy /Y "%OUT%\lethe.sys" "%BIN%\lethe.sys" >nul
echo [+] Driver: bin\lethe.sys

:: CLIENT
echo [*] Building client...

cl.exe ^
    /nologo ^
    /W3 ^
    /Zi ^
    /Fe:"%BIN%\client.exe" ^
    "%CLIENT%\client.c" ^
    /link kernel32.lib

if %ERRORLEVEL% NEQ 0 (
    echo [!] Client compile failed
    exit /b 1
)

echo [+] Client: bin\client.exe
echo.
echo [+] Build complete.
echo     Copy bin\lethe.sys and bin\client.exe to the target machine.
echo     Run scripts\load.bat as Administrator to sign and register the driver.
echo     Then: sc start Lethe