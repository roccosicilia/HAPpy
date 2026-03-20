@echo off
echo ========================================
echo  ProcessMonitor - Build Script
echo ========================================

:: Percorso del Developer Command Prompt di Visual Studio
:: Adatta il path se hai installato VS in una cartella diversa
call "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat"

echo.
echo [1/2] Compilazione driver kernel...
msbuild driver\ProcessMonitor.vcxproj /p:Configuration=Release /p:Platform=x64 /nologo /v:minimal

if %ERRORLEVEL% neq 0 (
    echo [ERRORE] Build del driver fallita.
    pause
    exit /b 1
)

echo.
echo [2/2] Compilazione programma user mode...
cl /nologo /W3 /O2 /Fe:userapp\ProcessMonitor.exe userapp\main.c

if %ERRORLEVEL% neq 0 (
    echo [ERRORE] Build del programma user mode fallita.
    pause
    exit /b 1
)

echo.
echo ========================================
echo  Build completata con successo!
echo  Driver  : driver\x64\Release\ProcessMonitor.sys
echo  Userapp : userapp\ProcessMonitor.exe
echo ========================================
pause