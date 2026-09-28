#!/usr/bin/env bash
# Print the CHANGELOG section for one release, without its heading.
# Usage: release/notes.sh <version> [changelog]
# Fails when the section is missing or empty, so a tag whose CHANGELOG still
# says "Unreleased" cannot be published.
set -euo pipefail
version="${1:?usage: release/notes.sh <version> [changelog]}"
changelog="${2:-CHANGELOG.md}"
notes="$(awk -v heading="## ${version}" '
  $0 == heading { found = 1; next }
  found && /^## / { exit }
  found { print }
' "${changelog}" | sed -e '/./,$!d')"
if [ -z "${notes//[[:space:]]/}" ]; then
  echo "release/notes.sh: no '## ${version}' section in ${changelog}" >&2
  exit 1
fi
printf '%s\n' "${notes}"
