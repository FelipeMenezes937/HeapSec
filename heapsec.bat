@echo off
REM HeapSec Antivirus - Windows Launcher
REM Compatible with Java 11+

set SCRIPT_DIR=%~dp0
set CLASSES_DIR=%SCRIPT_DIR%out\classes

set JAVAC_PATH=

where java >nul 2>nul
if %errorlevel% equ 0 (
    for /f "delims=" %%i in ('where java') do (
        set JAVA_BIN=%%i
        goto :found_java
    )
    :found_java
    if not "%JAVA_BIN%"=="" (
        set JAVAC_PATH=%JAVA_BIN:~0,-8%
    )
)

if not defined JAVAC_PATH (
    if defined JAVA_HOME (
        set JAVAC_PATH=%JAVA_HOME%\bin
    )
)

if not defined JAVAC_PATH (
    echo ERROR: Java not found. Please install Java 11+ and set JAVA_HOME.
    exit /b 1
)

"%JAVAC_PATH%\java.exe" -version 2>&1 | findstr /C:"version" >nul
for /f "delims=" %%v in ('"%JAVAC_PATH%\java.exe" -version 2^>^&1') do set JAVA_VERSION_LINE=%%v
echo %JAVA_VERSION_LINE% | findstr /C:"11" >nul
if %errorlevel% neq 0 (
    echo %JAVA_VERSION_LINE% | findstr /C:"17" >nul
    if %errorlevel% neq 0 (
        echo %JAVA_VERSION_LINE% | findstr /C:"21" >nul
        if %errorlevel% neq 0 (
            echo ERROR: Java 11+ required. Current version:
            echo %JAVA_VERSION_LINE%
            exit /b 1
        )
    )
)

echo Using Java: %JAVA_VERSION_LINE%

echo Compiling HeapSec...
if not exist "%CLASSES_DIR%" mkdir "%CLASSES_DIR%"

"%JAVAC_PATH%\javac.exe" -d "%CLASSES_DIR%" -sourcepath src\main\java src\main\java\antivirus\*.java src\main\java\antivirus\*\*.java 2>NUL
if %errorlevel% neq 0 (
    "%JAVAC_PATH%\javac.exe" -d "%CLASSES_DIR%" -sourcepath src\main\java src\main\java\antivirus\*.java src\main\java\antivirus\*\*.java
)

"%JAVAC_PATH%\java.exe" -cp "%CLASSES_DIR%" antivirus.AntivirusScanner %*