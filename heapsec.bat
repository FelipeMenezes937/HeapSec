@echo off
REM HeapSec Antivirus - Windows Launcher

set SCRIPT_DIR=%~dp0
set CLASSES_DIR=%SCRIPT_DIR%out\classes

echo Compiling HeapSec...
if not exist "%CLASSES_DIR%" mkdir "%CLASSES_DIR%"

javac -d "%CLASSES_DIR%" -sourcepath src\main\java src\main\java\antivirus\*.java src\main\java\antivirus\*\*.java 2>NUL
if errorlevel 1 (
    javac -d "%CLASSES_DIR%" -sourcepath src\main\java src\main\java\antivirus\*.java src\main\java\antivirus\*\*.java
)

java -cp "%CLASSES_DIR%" antivirus.AntivirusScanner %*