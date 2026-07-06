#!/bin/bash
# version.sh - Compute next version based on commits since last tag.
# Usage: ./version.sh [--dry-run] [--changelog]
set -e

VERSION_FILE="VERSION"
CURRENT_VERSION=$(cat "$VERSION_FILE")

LAST_TAG=$(git describe --tags --abbrev=0 2>/dev/null || git rev-list --max-parents=0 HEAD)

# Count merges since last tag
MERGE_COUNT=$(git log "$LAST_TAG"..HEAD --merges --oneline | wc -l)

MAJOR_BUMP=0
MINOR_BUMP=0
PATCH_BUMP=0

# 1) Detect BREAKING CHANGE (in subject with !: or in body)
if git log "$LAST_TAG"..HEAD --grep="BREAKING CHANGE" -E --no-merges | head -n1 | grep -q .; then
	MAJOR_BUMP=1
fi
if git log "$LAST_TAG"..HEAD --pretty=format:"%s" --no-merges | grep -q '!:' ; then
	MAJOR_BUMP=1
fi

# 2) If no major, check for minor indicators (merge OR feat!:)
if [ "$MAJOR_BUMP" -eq 0 ]; then
	# Check for feat!: commits (explicit minor version marker)
	if git log "$LAST_TAG"..HEAD --pretty=format:"%s" --no-merges \
		| grep -q -E '^(feat|perf)\(.+\)?!:|^(feat|perf)!:' ; then
		MINOR_BUMP=1
	fi
	
	# Check for merges (backward compatibility)
	if [ "$MINOR_BUMP" -eq 0 ] && [ "$MERGE_COUNT" -gt 0 ]; then
		MINOR_BUMP=1
	fi
fi

# 3) If no major and no minor, check for useful commits (patch)
if [ "$MAJOR_BUMP" -eq 0 ] && [ "$MINOR_BUMP" -eq 0 ]; then
	NON_IGNORED=$(git log "$LAST_TAG"..HEAD --pretty=format:"%s" --no-merges \
		| grep -v -E '^(test|chore|docs|build|style|ci|refactor)(\(.+\))?:' || true)
	if [ -n "$NON_IGNORED" ]; then
		PATCH_BUMP=1
	fi
fi

# Compute new version
IFS='.' read -r MAJOR MINOR PATCH <<< "$CURRENT_VERSION"

if [ "$MAJOR_BUMP" -eq 1 ]; then
	MAJOR=$((MAJOR + 1)); MINOR=0; PATCH=0
elif [ "$MINOR_BUMP" -eq 1 ]; then
	MINOR=$((MINOR + 1)); PATCH=0
elif [ "$PATCH_BUMP" -eq 1 ]; then
	# Count useful commits since last tag for patch version
	USEFUL_COMMITS=$(git log "$LAST_TAG"..HEAD --pretty=format:"%s" --no-merges \
		| grep -v -E '^(test|chore|docs|build|style|ci|refactor)(\(.+\))?:' | wc -l)
	PATCH=$USEFUL_COMMITS
else
	echo "$CURRENT_VERSION"
	exit 0
fi

NEW_VERSION="$MAJOR.$MINOR.$PATCH"
DRY_RUN=0
if [ "$1" == "--dry-run" ]; then
	DRY_RUN=1
fi

echo "Scanning for commits since $LAST_TAG..."

# Get all merge commits since LAST_TAG, in chronological order (oldest first)
MERGES=$(git log "$LAST_TAG"..HEAD --merges --reverse --pretty=format:"%H")

# Get all feat!: commits that are not merges
FEAT_BANG=$(git log "$LAST_TAG"..HEAD --no-merges --pretty=format:"%H" --grep="!:" -E | while read hash; do
	if [ -n "$hash" ]; then
		subject=$(git log -1 --format="%s" "$hash")
		if echo "$subject" | grep -q -E '^(feat|perf)\(.+\)?!:|^(feat|perf)!:'; then
			echo "$hash"
		fi
	fi
done)

# Combine merges and feat!: commits, sort by date
ALL_MINOR_COMMITS=$(echo -e "$MERGES\n$FEAT_BANG" | sort -u | while read hash; do
	if [ -n "$hash" ]; then
		echo "$(git log -1 --format="%at" "$hash") $hash"
	fi
done | sort -n | cut -d' ' -f2)

if [ -n "$ALL_MINOR_COMMITS" ]; then
	echo "Found $(echo "$ALL_MINOR_COMMITS" | wc -l) minor commit(s) to process."

	CURRENT_MAJOR=$MAJOR
	CURRENT_MINOR=$MINOR
	CURRENT_PATCH=$PATCH
	FIRST_COMMIT=1

	for HASH in $ALL_MINOR_COMMITS; do
		# Check if this commit already has a tag
		if git tag --points-at "$HASH" 2>/dev/null | grep -q .; then
			continue
		fi

		# Check if this commit contains breaking changes
		BREAKING=0
		IS_MERGE=0
		
		# Check if it's a merge commit
		if git log -1 --format="%P" "$HASH" | grep -q ' '; then
			IS_MERGE=1
			PARENT=$(git log -1 --format="%P" "$HASH" | cut -d' ' -f1)
			if [ -n "$PARENT" ]; then
				if git log "$PARENT".."$HASH" --pretty=format:"%s" --no-merges \
					| grep -q -E 'BREAKING CHANGE|!:' 2>/dev/null; then
					BREAKING=1
				fi
			fi
		else
			# Check single commit for breaking changes
			if git log -1 --pretty=format:"%s" "$HASH" | grep -q -E '!:|BREAKING CHANGE'; then
				BREAKING=1
			fi
		fi

		if [ "$BREAKING" -eq 1 ]; then
			CURRENT_MAJOR=$((CURRENT_MAJOR + 1))
			CURRENT_MINOR=0
			CURRENT_PATCH=0
		else
			if [ "$FIRST_COMMIT" -eq 1 ]; then
				CURRENT_MAJOR=$MAJOR
				CURRENT_MINOR=$MINOR
				CURRENT_PATCH=$PATCH
				FIRST_COMMIT=0
			else
				CURRENT_MINOR=$((CURRENT_MINOR + 1))
				CURRENT_PATCH=0
			fi
		fi

		COMMIT_VERSION="$CURRENT_MAJOR.$CURRENT_MINOR.$CURRENT_PATCH"
		TAG_NAME="v$COMMIT_VERSION"

		if [ $DRY_RUN -eq 0 ]; then
			if [ "$IS_MERGE" -eq 1 ]; then
				echo "  Creating tag $TAG_NAME on merge $HASH"
			else
				echo "  Creating tag $TAG_NAME on feat!: commit $HASH"
			fi
			git tag -a "$TAG_NAME" -m "Version $COMMIT_VERSION" "$HASH" 2>/dev/null || true
		else
			if [ "$IS_MERGE" -eq 1 ]; then
				echo "  [DRY RUN] Would create tag $TAG_NAME on merge $HASH"
			else
				echo "  [DRY RUN] Would create tag $TAG_NAME on feat!: commit $HASH"
			fi
		fi

		MAJOR=$CURRENT_MAJOR
		MINOR=$CURRENT_MINOR
		PATCH=$CURRENT_PATCH
	done

	# Now count useful commits since the last processed commit
	LAST_PROCESSED=$(echo "$ALL_MINOR_COMMITS" | tail -n1)
	if [ -n "$LAST_PROCESSED" ]; then
		# Count useful commits after the last processed commit
		USEFUL_COMMITS=$(git log "$LAST_PROCESSED"..HEAD --pretty=format:"%s" --no-merges \
			| grep -v -E '^(test|chore|docs|build|style|ci|refactor)(\(.+\))?:' | wc -l)
		PATCH=$USEFUL_COMMITS
		NEW_VERSION="$MAJOR.$MINOR.$PATCH"
	fi
else
	echo "No minor commits found since $LAST_TAG"
fi

# ---------------------------------------------------------------------------
# Apply the version bump
# ---------------------------------------------------------------------------
if [ $DRY_RUN -eq 0 ]; then
	echo "Bumping version: $CURRENT_VERSION -> $NEW_VERSION"
	echo "$NEW_VERSION" > "$VERSION_FILE"
else
	echo "[DRY RUN] Would bump version: $CURRENT_VERSION -> $NEW_VERSION"
fi

# Capture last commit metadata
LAST_HASH=$(git log -1 --format="%h")
LAST_SUBJECT=$(git log -1 --format="%s")
LAST_DATE=$(git log -1 --format="%ad" --date=format:"%d %b %Y")
echo "LAST_COMMIT_HASH=$LAST_HASH" > .version_meta
echo "LAST_COMMIT_SUBJECT=$LAST_SUBJECT" >> .version_meta
echo "LAST_COMMIT_DATE=$LAST_DATE" >> .version_meta

# Optionally generate changelog
if [[ "$1" == "--changelog" ]]; then
	./changelog.sh "$LAST_TAG"
fi

echo "$NEW_VERSION"
