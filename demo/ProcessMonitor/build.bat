@echo off
echo ========================================
echo  ProcessMonitor - Build Script
echo ========================================

:: Percorso compilatore - adatta se necessario
call "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
if %ERRORLEVEL% neq 0 (
    echo [ERRORE] vcvars64.bat non trovato
    pause
    exit /b 1
)

:: Versione WDK
set WDK_VER=10.0.26100.0
set WDK_INC=C:\Program Files (x86)\Windows Kits\10\Include\%WDK_VER%
set WDK_LIB=C:\Program Files (x86)\Windows Kits\10\Lib\%WDK_VER%

:: Cartella output
if not exist driver\out mkdir driver\out
if not exist userapp\out mkdir userapp\out

echo.
echo [1/2] Compilazione driver kernel...

cl.exe /nologo ^
    /kernel ^
    /W4 /WX- ^
    /O2 /Oi /Ot ^
    /GS- ^
    /Gz ^
    /TC ^
    /FAcs /Fa"driver\out\\" ^
    /Fo"driver\out\\" ^
    /c driver\driver.c ^
    /I "%WDK_INC%\km" ^
    /I "%WDK_INC%\shared" ^
    /D _AMD64_ ^
    /D AMD64 ^
    /D _WIN64 ^
    /D NDEBUG ^
    /D _KERNEL_MODE ^
    /D POOL_NX_OPTIN=1

if %ERRORLEVEL% neq 0 (
    echo [ERRORE] Compilazione driver fallita.
    pause
    exit /b 1
)

link.exe /nologo ^
    /DRIVER:WDM ^
    /SUBSYSTEM:NATIVE ^
    /ENTRY:DriverEntry ^
    /MACHINE:X64 ^
    /NODEFAULTLIB ^
    /OPT:REF /OPT:ICF ^
    /INTEGRITYCHECK ^
    /OUT:"driver\out\ProcessMonitor.sys" ^
    "driver\out\driver.obj" ^
    "%WDK_LIB%\km\x64\ntoskrnl.lib" ^
    "%WDK_LIB%\km\x64\hal.lib" ^
    "%WDK_LIB%\km\x64\wdmsec.lib" ^
    "%WDK_LIB%\km\x64\wdm.lib" ^
    "%WDK_LIB%\km\x64\ntstrsafe.lib" ^
    "%WDK_LIB%\km\x64\BufferOverflowFastFailK.lib"

if %ERRORLEVEL% neq 0 (
    echo [ERRORE] Link driver fallito.
    pause
    exit /b 1
)

echo [OK] Driver: driver\out\ProcessMonitor.sys

echo.
echo [2/2] Compilazione programma user mode...

cl.exe /nologo ^
    /W3 /O2 ^
    /Fe:"userapp\out\ProcessMonitor.exe" ^
    userapp\main.c ^
    /link kernel32.lib

if %ERRORLEVEL% neq 0 (
    echo [ERRORE] Compilazione user mode fallita.
    pause
    exit /b 1
)

echo [OK] Userapp: userapp\out\ProcessMonitor.exe

echo.
echo ========================================
echo  Build completata con successo!
echo  Copia nella VM:
echo    driver\out\ProcessMonitor.sys
echo    userapp\out\ProcessMonitor.exe
echo ========================================
pause