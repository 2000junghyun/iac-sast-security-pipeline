#!/bin/bash

# Trivy와 필요한 도구를 bin 디렉토리에 설치하는 스크립트

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="$SCRIPT_DIR/bin"
TRIVY_VERSION="0.58.1"

# bin 디렉토리 생성
mkdir -p "$BIN_DIR"

echo "🔍 Detecting OS and Architecture..."

# OS 및 아키텍처 감지
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$OS" in
    darwin)
        OS="macOS"
        ;;
    linux)
        OS="Linux"
        ;;
    *)
        echo "❌ Unsupported OS: $OS"
        exit 1
        ;;
esac

case "$ARCH" in
    x86_64)
        ARCH="64bit"
        ;;
    arm64|aarch64)
        if [ "$OS" = "macOS" ]; then
            ARCH="ARM64"
        else
            ARCH="ARM64"
        fi
        ;;
    *)
        echo "❌ Unsupported architecture: $ARCH"
        exit 1
        ;;
esac

TRIVY_FILENAME="trivy_${TRIVY_VERSION}_${OS}-${ARCH}.tar.gz"
TRIVY_URL="https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/${TRIVY_FILENAME}"

echo "📥 Downloading Trivy ${TRIVY_VERSION} for ${OS} ${ARCH}..."
echo "   URL: $TRIVY_URL"

cd "$BIN_DIR"

# Trivy 다운로드
if command -v curl &> /dev/null; then
    curl -LO "$TRIVY_URL"
elif command -v wget &> /dev/null; then
    wget "$TRIVY_URL"
else
    echo "❌ Neither curl nor wget is available. Please install one of them."
    exit 1
fi

# 압축 해제
echo "📦 Extracting Trivy..."
tar -xzf "$TRIVY_FILENAME"
chmod +x trivy
rm "$TRIVY_FILENAME"

echo "✅ Trivy installed successfully!"
echo "   Location: $BIN_DIR/trivy"
echo ""

# Trivy 버전 확인
./trivy --version

echo ""
echo "⚠️  Note: You still need to manually place trivy-parser in the bin directory:"
echo "   cp /path/to/trivy-parser $BIN_DIR/trivy-parser"
echo "   chmod +x $BIN_DIR/trivy-parser"
echo ""
echo "📁 Bin directory structure:"
ls -lh "$BIN_DIR"
