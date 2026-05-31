#!/bin/sh
# Generate an RPM %changelog block from git history.
#
# Usage: gen-changelog.sh <version> <release>
#
# Emits a single dated %changelog entry for <version>-<release> whose body is
# the list of non-merge commit subjects since the previous v* tag (or the last
# 20 commits if there is no previous tag). Intended to be appended to the spec
# in CI so the packaged changelog tracks the release automatically. Requires a
# git checkout with history/tags (CI uses fetch-depth: 0).
set -eu

VERSION="${1:-0.1.0}"
RELEASE="${2:-1}"
DATE="$(LC_ALL=C date -u '+%a %b %d %Y')"
AUTHOR="${CHANGELOG_AUTHOR:-rootseal release automation <rootseal@example.com>}"

# Range: previous v* tag (excluding HEAD's own tag) .. HEAD.
prev_tag="$(git describe --tags --abbrev=0 --match 'v*' 'HEAD^' 2>/dev/null || true)"
if [ -n "$prev_tag" ]; then
  range="${prev_tag}..HEAD"
else
  range=""
fi

printf '* %s %s - %s-%s\n' "$DATE" "$AUTHOR" "$VERSION" "$RELEASE"
if [ -n "$range" ]; then
  git log --no-merges --pretty='- %s' "$range"
else
  git log --no-merges --pretty='- %s' -n 20
fi
