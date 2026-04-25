#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 1 ]; then
	echo "Usage: $0 <tag>"
	exit 1
fi

TAG="$1"
TMPDIR="$(mktemp -d)"

cleanup() {
	rm -rf "$TMPDIR"
}
trap cleanup EXIT

command -v git >/dev/null
command -v git-filter-repo >/dev/null

if [ -d "$HOME/go/.git" ]; then
	REFERENCE=(--reference "$HOME/go" --dissociate)
else
	REFERENCE=()
fi

git -c advice.detachedHead=false clone --no-checkout "${REFERENCE[@]}" \
	-b "$TAG" https://go.googlesource.com/go.git "$TMPDIR"

git -C "$TMPDIR" filter-repo --force \
	--paths-from-file /dev/stdin \
	--prune-empty always \
	--prune-degenerate always \
	--tag-callback 'tag.skip()' <<'EOF'
src/crypto/internal/fips140/mldsa
src/crypto/internal/fips140test/mldsa_test.go
src/crypto/mldsa
EOF

git fetch "$TMPDIR"
git update-ref "refs/heads/upstream/$TAG" FETCH_HEAD

echo
echo "Fetched upstream history up to $TAG. Merge with:"
echo -e "\tgit merge --no-ff --no-commit --allow-unrelated-histories upstream/$TAG"
