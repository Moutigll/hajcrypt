#!/bin/bash
# changelog.sh - Generate CHANGELOG.md from tags
# Usage: ./changelog.sh [--output=<file>]
set -e

OUTPUT="CHANGELOG.md"

# Parse arguments
for arg in "$@"; do
	case "$arg" in
		--output=*)
			OUTPUT="${arg#*=}"
			;;
		*)
			echo "Usage: $0 [--output=<file>]"
			exit 1
			;;
	esac
done

# Get all tags sorted by version (newest first)
TAGS=$(git tag --sort=-v:refname)
if [ -z "$TAGS" ]; then
	echo "No tags found." >&2
	exit 0
fi

echo "# Changelog" > "$OUTPUT"
echo "" >> "$OUTPUT"

# Reverse to oldest first for proper range calculation
TAGS_REV=$(echo "$TAGS" | tac)

prev=""
for tag in $TAGS_REV; do
	if [ -z "$prev" ]; then
		# First tag: from the beginning to this tag
		range="$tag"
	else
		# Subsequent tags: from previous tag to this tag
		range="$prev..$tag"
	fi

	# Get commits in range, filtering out ignored types
	commits=$(git log "$range" --pretty=format:"%s|%h" --no-merges 2>/dev/null | while IFS='|' read -r subject hash; do
		[ -z "$hash" ] && continue
		# Skip ignored commit types
		if echo "$subject" | grep -q -E '^(test|chore|docs|build|style|ci|refactor)(\(.+\))?:'; then
			continue
		fi
		# Clean subject: remove trailing weird artifacts
		subject=$(echo "$subject" | sed -E 's/[[:space:]]*\([^)]*\)[[:space:]]*$//' | sed -E 's/[[:space:]]+$//')
		echo "- $subject ($hash)"
	done | sort -u)

	if [ -n "$commits" ]; then
		date=$(git log -1 --format="%ad" --date=format:"%d %b %Y" "$tag" 2>/dev/null || echo "")
		echo "## [$tag] - $date" >> "$OUTPUT"
		echo "" >> "$OUTPUT"
		echo "$commits" >> "$OUTPUT"
		echo "" >> "$OUTPUT"
	fi

	prev="$tag"
done

# Unreleased commits since the newest tag
newest=$(echo "$TAGS" | head -n1)
if [ -n "$newest" ]; then
	commits=$(git log "$newest"..HEAD --pretty=format:"%s|%h" --no-merges 2>/dev/null | while IFS='|' read -r subject hash; do
		[ -z "$hash" ] && continue
		if echo "$subject" | grep -q -E '^(test|chore|docs|build|style|ci|refactor)(\(.+\))?:'; then
			continue
		fi
		subject=$(echo "$subject" | sed -E 's/[[:space:]]*\([^)]*\)[[:space:]]*$//' | sed -E 's/[[:space:]]+$//')
		echo "- $subject ($hash)"
	done | sort -u)

	if [ -n "$commits" ]; then
		echo "## [Unreleased]" >> "$OUTPUT"
		echo "" >> "$OUTPUT"
		echo "$commits" >> "$OUTPUT"
		echo "" >> "$OUTPUT"
	fi
fi

echo "Changelog generated in $OUTPUT"
