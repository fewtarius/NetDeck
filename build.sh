#!/bin/bash
# NetDeck Build Script

set -e

echo "Building NetDeck..."

# Version info (no update-version.sh dependency)
if [ -f "VERSION" ]; then
    VERSION=$(cat VERSION | tr -d '\n\r')
    echo "Building version: $VERSION"
fi

# Install dependencies
echo "Installing dependencies..."
if command -v pnpm &> /dev/null; then
    pnpm install
elif command -v npm &> /dev/null; then
    npm install
else
    echo "Error: Neither pnpm nor npm found!"
    exit 1
fi

# Build frontend
echo "Building frontend..."
if command -v pnpm &> /dev/null; then
    pnpm build
else
    npm run build
fi

# Apply IIFE fix for Decky compatibility
echo "Applying Decky compatibility fix..."
if [ -f "dist/index.js" ]; then
    # Check if fix is needed
    if grep -q "export { index as default };" dist/index.js; then
        # Linux compatible sed (GitHub Actions)
        sed -i 's/export { index as default };/(function() { return index; })();/' dist/index.js
        echo "IIFE fix applied"
    else
        echo "IIFE fix not needed (already in correct format)"
    fi
else
    echo "Build failed - dist/index.js not found"
    exit 1
fi

echo "NetDeck build complete!"
echo "Built files available in dist/"

# Show version info
if [ -f "VERSION" ]; then
    VERSION=$(cat VERSION | tr -d '\n\r')
    echo "Version: $VERSION"
fi
