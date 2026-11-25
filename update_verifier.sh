#!/bin/bash
# Pins tinfoil-go.properties to the TinfoilGo.aar of a tinfoil-go release: it
# downloads the library, checks it against the checksum that the release
# publishes, and writes the release's tag and the library's SHA-256 together.
#
# Usage: ./update_verifier.sh <tag>
#   tag  the release to pin, such as v0.17.0
set -euo pipefail
cd "$(dirname "$0")"

if [[ $# -ne 1 ]]; then
    echo "usage: $0 <tag>, such as v0.17.0" >&2
    exit 2
fi
tag="$1"
# The tag becomes part of a URL and of the pin, so it must be a plain version.
if [[ ! "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]]; then
    echo "not a release tag: $tag" >&2
    exit 2
fi
url="https://github.com/tinfoilsh/tinfoil-go/releases/download/$tag/TinfoilGo.aar"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
curl -fsSL --proto '=https' -o "$work/TinfoilGo.aar" "$url"
curl -fsSL --proto '=https' -o "$work/TinfoilGo.aar.sha256" "$url.sha256"

# The published file is "<sha256>  TinfoilGo.aar".
read -r published name < "$work/TinfoilGo.aar.sha256" || true
if [[ ! "$published" =~ ^[0-9a-f]{64}$ || "$name" != TinfoilGo.aar ]]; then
    echo "the release's TinfoilGo.aar.sha256 is not a checksum of TinfoilGo.aar" >&2
    exit 1
fi
checksum="$(shasum -a 256 "$work/TinfoilGo.aar" | cut -d ' ' -f 1)"
if [[ "$checksum" != "$published" ]]; then
    echo "downloaded checksum $checksum does not match the published $published" >&2
    exit 1
fi
listing="$(unzip -Z1 "$work/TinfoilGo.aar")"
if ! grep -qx 'classes.jar' <<< "$listing" || ! grep -q '^jni/.*\.so$' <<< "$listing"; then
    echo "TinfoilGo.aar has no classes or no native libraries" >&2
    exit 1
fi

# Replace the tag and the checksum together, so that the pin cannot end up
# naming one release with another's checksum.
TAG="$tag" CHECKSUM="$checksum" perl -0pi -e '
    s{^version=.*$}{version=$ENV{TAG}}m or die "no version\n";
    s{^sha256=.*$}{sha256=$ENV{CHECKSUM}}m or die "no sha256\n";
' tinfoil-go.properties
if ! grep -qx "version=$tag" tinfoil-go.properties || ! grep -qx "sha256=$checksum" tinfoil-go.properties; then
    echo "could not update tinfoil-go.properties" >&2
    exit 1
fi

if git diff --quiet -- tinfoil-go.properties; then
    echo "tinfoil-go.properties already pins tinfoil-go $tag"
else
    echo "Pinned tinfoil-go $tag ($checksum) in tinfoil-go.properties."
    echo "Build and test against it, then commit it as \"chore(deps): pin tinfoil-go $tag\"."
fi
