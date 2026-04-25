#!/bin/bash
# HeapSec Antivirus - Simple Launcher
# Usage: ./heapsec.sh [args] or just heapsec [args]

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CLASSES_DIR="$SCRIPT_DIR/out/classes"

echo "Compiling HeapSec..."
mkdir -p "$CLASSES_DIR"
javac -d "$CLASSES_DIR" --source-path src/main/java src/main/java/antivirus/*.java src/main/java/antivirus/*/*.java 2>/dev/null
if [ $? -ne 0 ]; then
    echo "Retrying with full output..."
    javac -d "$CLASSES_DIR" --source-path src/main/java src/main/java/antivirus/*.java src/main/java/antivirus/*/*.java
fi

JAVA_VERSION=$(java -version 2>&1 | head -1 | cut -d'"' -f2 | cut -d'.' -f1)
if [ "$JAVA_VERSION" -lt 21 ]; then
    echo "ERROR: Java 21+ required. Current version: $JAVA_VERSION"
    exit 1
fi

case "$1" in
    --test|-t)
        exec java -cp "$CLASSES_DIR" antivirus.HeapSecTest "${@:2}"
        ;;
    *)
        exec java -cp "$CLASSES_DIR" antivirus.AntivirusScanner "$@"
        ;;
esac