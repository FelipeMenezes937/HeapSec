#!/bin/bash
set -e

echo "=== HeapSec Antivirus AOT Build ==="

APP_NAME="HeapSec"
APP_VERSION="1.0.0"
MAIN_CLASS="antivirus.AntivirusScanner"
SOURCE_DIR="src/main/java"
OUTPUT_DIR="out/aot"

mkdir -p "$OUTPUT_DIR"

echo "[1/3] Compilando codigo fonte..."
mkdir -p out/classes
javac -d out/classes -sourcepath "$SOURCE_DIR" -cp out "$SOURCE_DIR"/antivirus/**/*.java 2>/dev/null || \
javac -d out/classes --source-path "$SOURCE_DIR" "$SOURCE_DIR"/antivirus/*/*.java "$SOURCE_DIR"/antivirus/*.java 2>/dev/null || \
find "$SOURCE_DIR" -name "*.java" -print0 | xargs -0 javac -d out/classes -sourcepath "$SOURCE_DIR" 2>/dev/null

echo "[2/3] Criando JAR..."
cd out/classes
jar cf ../heapsec.jar antivirus/*
cd ../..

echo "[3/3] Compilando para binario nativo (AOT)..."
jpackage \
  --input out \
  --main-jar heapsec.jar \
  --main-class "$MAIN_CLASS" \
  --name "$APP_NAME" \
  --app-version "$APP_VERSION" \
  --type appimage \
  --dest "$OUTPUT_DIR" \
  --java-options "-Xmx512m" \
  --icon src/main/resources/icon.png 2>/dev/null || \
jpackage \
  --input out \
  --main-jar heapsec.jar \
  --main-class "$MAIN_CLASS" \
  --name "$APP_NAME" \
  --app-version "$APP_VERSION" \
  --type dir \
  --dest "$OUTPUT_DIR" \
  --java-options "-Xmx512m"

echo ""
echo "=== Build concluído! ==="
ls -la "$OUTPUT_DIR"
echo ""
echo "Executavel: $OUTPUT_DIR/HeapSec"