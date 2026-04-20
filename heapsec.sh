#!/bin/bash
# HeapSec Antivirus - Simple Launcher
# Usage: ./heapsec.sh [args] or just heapsec [args]

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CLASSES_DIR="$SCRIPT_DIR/out/classes"

if [ ! -d "$CLASSES_DIR" ]; then
    echo "Compiling HeapSec..."
    mkdir -p "$CLASSES_DIR"
    javac -d "$CLASSES_DIR" --source-path src/main/java src/main/java/antivirus/*.java src/main/java/antivirus/*/*.java 2>/dev/null
    if [ $? -ne 0 ]; then
        javac -d "$CLASSES_DIR" --source-path src/main/java src/main/java/antivirus/*.java src/main/java/antivirus/*/*.java
    fi
fi

case "$1" in
    --test|-t)
        exec java -cp "$CLASSES_DIR" antivirus.HeapSecTest "${@:2}"
        ;;
    *)
        exec java -cp "$CLASSES_DIR" antivirus.AntivirusScanner "$@"
        ;;
esac