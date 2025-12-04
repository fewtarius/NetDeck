#!/bin/bash

# NetDeck Version Synchronization Script
# Ensures package.json and plugin.json versions match VERSION file

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
VERSION_FILE="$SCRIPT_DIR/VERSION"
PACKAGE_JSON="$SCRIPT_DIR/package.json"
PLUGIN_JSON="$SCRIPT_DIR/plugin.json"

# Check if VERSION file exists
if [ ! -f "$VERSION_FILE" ]; then
    echo "Error: VERSION file not found at $VERSION_FILE"
    exit 1
fi

# Read version from VERSION file
NEW_VERSION=$(cat "$VERSION_FILE" | tr -d '\n\r ')

if [ -z "$NEW_VERSION" ]; then
    echo "Error: VERSION file is empty"
    exit 1
fi

echo "Synchronizing version to: $NEW_VERSION"

# Update package.json version
if [ -f "$PACKAGE_JSON" ]; then
    echo "Updating package.json version..."
    if command -v jq &> /dev/null; then
        # Use jq if available for proper JSON handling
        tmp=$(mktemp)
        jq --arg version "$NEW_VERSION" '.version = $version' "$PACKAGE_JSON" > "$tmp" && mv "$tmp" "$PACKAGE_JSON"
        echo "  * package.json updated via jq"
    else
        # Fallback to sed for systems without jq
        if [[ "$OSTYPE" == "darwin"* ]]; then
            sed -i '' "s/\"version\": \"[^\"]*\"/\"version\": \"$NEW_VERSION\"/" "$PACKAGE_JSON"
        else
            sed -i "s/\"version\": \"[^\"]*\"/\"version\": \"$NEW_VERSION\"/" "$PACKAGE_JSON"
        fi
        echo "  * package.json updated via sed"
    fi
else
    echo "Warning: package.json not found"
fi

# Update plugin.json version
if [ -f "$PLUGIN_JSON" ]; then
    echo "Updating plugin.json version..."
    if command -v jq &> /dev/null; then
        # Use jq if available for proper JSON handling
        tmp=$(mktemp)
        jq --arg version "$NEW_VERSION" '.version = $version' "$PLUGIN_JSON" > "$tmp" && mv "$tmp" "$PLUGIN_JSON"
        echo "  * plugin.json updated via jq"
    else
        # Fallback to sed for systems without jq
        if [[ "$OSTYPE" == "darwin"* ]]; then
            sed -i '' "s/\"version\": \"[^\"]*\"/\"version\": \"$NEW_VERSION\"/" "$PLUGIN_JSON"
        else
            sed -i "s/\"version\": \"[^\"]*\"/\"version\": \"$NEW_VERSION\"/" "$PLUGIN_JSON"
        fi
        echo "  * plugin.json updated via sed"
    fi
else
    echo "Warning: plugin.json not found"
fi

echo "Version synchronization complete: $NEW_VERSION"

# Verify updates
echo ""
echo "Version verification:"
if [ -f "$PACKAGE_JSON" ]; then
    PACKAGE_VERSION=$(grep -o '"version": "[^"]*"' "$PACKAGE_JSON" | cut -d'"' -f4)
    echo "  * package.json: $PACKAGE_VERSION"
fi

if [ -f "$PLUGIN_JSON" ]; then
    PLUGIN_VERSION=$(grep -o '"version": "[^"]*"' "$PLUGIN_JSON" | cut -d'"' -f4)
    echo "  * plugin.json: $PLUGIN_VERSION"
fi

echo "  * VERSION file: $NEW_VERSION"
echo ""

# Check if all versions match
ALL_MATCH=true
if [ -f "$PACKAGE_JSON" ] && [ "$PACKAGE_VERSION" != "$NEW_VERSION" ]; then
    ALL_MATCH=false
    echo "ERROR: package.json version ($PACKAGE_VERSION) doesn't match VERSION file ($NEW_VERSION)"
fi

if [ -f "$PLUGIN_JSON" ] && [ "$PLUGIN_VERSION" != "$NEW_VERSION" ]; then
    ALL_MATCH=false
    echo "ERROR: plugin.json version ($PLUGIN_VERSION) doesn't match VERSION file ($NEW_VERSION)"
fi

if [ "$ALL_MATCH" = true ]; then
    echo "✅ All versions synchronized successfully!"
else
    echo "❌ Version synchronization failed!"
    exit 1
fi