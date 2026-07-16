#!/usr/bin/env bash
set -Eeuo pipefail
umask 022

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
cd "$ROOT"

VERSION=$(<VERSION)
[[ $VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9.-]+)?$ ]] \
    || die "invalid VERSION: $VERSION"
[[ -z $(git status --porcelain=v1) ]] \
    || die 'the Git worktree must be clean before packaging'

COMMIT=$(git rev-parse --verify HEAD)
if [[ $VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    TAG="v$VERSION"
    [[ $(git cat-file -t "$TAG" 2>/dev/null || true) == tag ]] \
        || die "final release tag $TAG must be annotated"
    [[ $(git rev-list -n 1 "$TAG" 2>/dev/null || true) == "$COMMIT" ]] \
        || die "final version $VERSION must be built from its exact annotated tag $TAG"
fi

OUTPUT_DIR=${1:-dist}
mkdir -p "$OUTPUT_DIR"
ARCHIVE="$OUTPUT_DIR/openvpn-lan-party-v$VERSION.zip"
DIGEST="$ARCHIVE.sha256"
rm -f -- "$ARCHIVE" "$DIGEST"

git archive --format=zip --prefix="openvpn-lan-party-v$VERSION/" \
    --output="$ARCHIVE" "$COMMIT"
unzip -tqq "$ARCHIVE"

LIST=$(mktemp)
trap 'rm -f -- "$LIST"' EXIT
unzip -Z1 "$ARCHIVE" > "$LIST"
for required in \
    install-vpn-server.sh \
    assets/windows/JOIN-VPN.cmd assets/windows/Join-VPN.ps1 \
    assets/windows/Enroll-VPN-High-Assurance.ps1 \
    assets/windows/Test-VPN-High-Assurance.ps1 \
    assets/windows/Leave-OpenVPN-LAN-Party.ps1 \
    assets/windows/Remove-VPN-Disposable-Identity.ps1 \
    assets/windows/LAN-Party-Companion.ps1 assets/windows/LAN-PARTY.cmd \
    assets/vpn-enrollment-csr.py assets/vpn-player-enrollment.py \
    assets/vpn-enrollment-admin.py assets/vpn-enrollment-portal.py \
    assets/audit-openvpn-lan-party \
    README.md HIGH-ASSURANCE.md COMPANION.md ACCEPTANCE.md SECURITY.md \
    RELEASE-NOTES.md VERSION; do
    grep -Fxq "openvpn-lan-party-v$VERSION/$required" "$LIST" \
        || die "release archive is missing $required"
done

if grep -Eiq '(^|/)(companion\.json|credential-registry\.json|.*\.(key|p12|pfx|7z|ovpn|vpninvite))$' "$LIST"; then
    die 'release archive unexpectedly contains generated identity or secret material'
fi

(cd "$OUTPUT_DIR" && sha256sum "${ARCHIVE##*/}" > "${DIGEST##*/}")
(cd "$OUTPUT_DIR" && sha256sum -c "${DIGEST##*/}")
printf 'Release candidate: %s\nCommit: %s\nDigest: %s\n' \
    "$ARCHIVE" "$COMMIT" "$(cut -d ' ' -f 1 "$DIGEST")"
