#!/usr/bin/env bash
#
# Cross-compile the agent for the platforms agents actually run on.
#
# Binaries are fully static (CGO_ENABLED=0), so one file drops onto a host with
# no runtime to install and no libc version to match — which is the point, given
# an agent is meant to be copied onto machines you do not otherwise manage.
#
# Usage:
#   ./build.sh [version]
#
# The version is stamped into the binary and reported at enrollment, so the UI
# can tell which agents are behind. Defaults to a git description.

set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
version="${1:-$(git -C "$repo_dir" describe --tags --always --dirty 2>/dev/null || echo dev)}"
out_dir="$repo_dir/dist"

platforms=(
    linux/amd64
    linux/arm64
    darwin/amd64
    darwin/arm64
)

mkdir -p "$out_dir"
echo "building runjet-agent $version"

for platform in "${platforms[@]}"; do
    goos="${platform%/*}"
    goarch="${platform#*/}"
    output="$out_dir/runjet-agent-$goos-$goarch"

    # -s -w drop the symbol table and DWARF data: nothing debugs these in place,
    # and it is a third off the size that has to be copied to every host.
    CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
        go -C "$repo_dir" build \
        -ldflags="-s -w -X main.version=$version" \
        -o "$output" .

    printf '  %-34s %s\n' "$(basename "$output")" "$(du -h "$output" | cut -f1)"
done

echo
echo "binaries in $out_dir"
echo "install one with: install -m 0755 <binary> /usr/local/bin/runjet-agent"
