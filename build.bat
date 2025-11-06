@echo off
echo Building remote-console...
gcc -o my.exe my.c -lws2_32 -ladvapi32
if %ERRORLEVEL% EQU 0 (
    echo Build successful! Created my.exe
) else (
    echo Build failed!
    exit /b 1
)

