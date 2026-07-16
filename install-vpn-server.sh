#!/usr/bin/env bash

set -Eeuo pipefail
umask 077

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ASSETS_DIR="$SCRIPT_DIR/assets"
OPENVPN_MINIMUM_VERSION=2.7.2
OPENVPN_REPOSITORY_KEY_URL=https://swupdate.openvpn.net/repos/repo-public.gpg
OPENVPN_REPOSITORY_KEY=/etc/apt/keyrings/openvpn-repo-public.asc
OPENVPN_REPOSITORY_SOURCE=/etc/apt/sources.list.d/openvpn-community.sources

die() {
    printf 'Error: %s\n' "$*" >&2
    exit 1
}

confirm() {
    local answer
    read -r -p "$1 [y/N]: " answer
    case ${answer,,} in
        y|yes) return 0 ;;
        *) return 1 ;;
    esac
}

openvpn_version() {
    local first_line patch

    command -v openvpn >/dev/null 2>&1 || return 1
    first_line=$(openvpn --version 2>/dev/null | sed -n '1p') || return 1
    if [[ $first_line =~ OpenVPN[[:space:]]+([0-9]+)\.([0-9]+)(\.([0-9]+))? ]]; then
        patch=${BASH_REMATCH[4]:-0}
        printf '%s.%s.%s\n' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "$patch"
        return 0
    fi
    return 1
}

openvpn_version_supported() {
    local version=$1 major minor patch

    IFS=. read -r major minor patch <<< "$version"
    [[ $major =~ ^[0-9]+$ && $minor =~ ^[0-9]+$ && $patch =~ ^[0-9]+$ ]] || return 1
    (( major > 2 || (major == 2 && (minor > 7 || (minor == 7 && patch >= 2))) ))
}

validate_ipv4() {
    local address=$1 octet
    local -a octets
    IFS=. read -r -a octets <<< "$address"
    [[ ${#octets[@]} -eq 4 ]] || return 1
    for octet in "${octets[@]}"; do
        [[ $octet =~ ^[0-9]{1,3}$ ]] || return 1
        (( 10#$octet <= 255 )) || return 1
    done
}

validate_public_ipv4() {
    python3 - "$1" <<'PY'
import ipaddress
import sys

try:
    address = ipaddress.ip_address(sys.argv[1])
except ValueError:
    raise SystemExit(1)
raise SystemExit(0 if address.version == 4 and address.is_global else 1)
PY
}

validate_email() {
    python3 - "$1" <<'PY'
import re
import sys

pattern = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}$")
raise SystemExit(0 if pattern.fullmatch(sys.argv[1]) else 1)
PY
}

validate_cidr24() {
    local cidr=$1 base octet
    local -a octets
    [[ $cidr == */24 ]] || return 1
    base=${cidr%/24}
    IFS=. read -r -a octets <<< "$base"
    [[ ${#octets[@]} -eq 4 && ${octets[3]} == 0 ]] || return 1
    for octet in "${octets[@]}"; do
        [[ $octet =~ ^[0-9]{1,3}$ ]] || return 1
        (( 10#$octet <= 255 )) || return 1
    done
}

render() {
    local source=$1 destination=$2
    sed \
        -e "s|__VPN_PORT__|$VPN_PORT|g" \
        -e "s|__VPN_SERVER_IP__|$VPN_SERVER_IP|g" \
        -e "s|__VPN_POOL_START__|$VPN_POOL_START|g" \
        -e "s|__VPN_POOL_END__|$VPN_POOL_END|g" \
        -e "s|__VPN_PREFIX__|$VPN_PREFIX|g" \
        -e "s|__VPN_CIDR__|$VPN_CIDR|g" \
        -e "s|__REMOTE_HOST__|$REMOTE_HOST|g" \
        -e "s|__LAN_IP__|$LAN_IP|g" \
        -e "s|__PORTAL_UPNP__|$PORTAL_UPNP|g" \
        -e "s|__ENROLLMENT_PORT__|$ENROLLMENT_PORT|g" \
        "$source" > "$destination"
}

usage() {
    cat <<'EOF'
Usage: sudo ./install-vpn-server.sh

Each invitation independently selects high-assurance or compatible Windows
key protection. The server defaults every new invitation to high-assurance.
EOF
}

while (($#)); do
    case $1 in
        -h|--help)
            usage
            exit 0
            ;;
        *) die "unknown installer option: $1" ;;
    esac
done

[[ $EUID -eq 0 ]] || die "run this installer as root"

[[ -r /etc/os-release ]] || die "/etc/os-release is missing"
# shellcheck disable=SC1091
. /etc/os-release
[[ ${ID:-} == "debian" && ${VERSION_ID:-} == "13" ]] \
    || die "this deployment kit supports Debian 13 only"

for required in \
    server.conf.in openvpn-tap-bridge.service.in \
    openvpn-server-bridge.conf openvpn-upnp.service.in openvpn-upnp.timer \
    vpn-player-enrollment.py vpn-enrollment-admin.py vpn-enrollment-admin.in \
    x509-types/vpn-player \
    vpn-enrollment-csr.py vpn-enrollment-portal.py vpn-enrollment-portal.service \
    vpn-enrollment-portal.json.in verify-tls-crypt-v2-player \
    audit-openvpn-lan-party \
    vpn-profile-acme.py vpn-profile-acme.json.in \
    vpn-profile-acme-renew.service vpn-profile-acme-renew.timer \
    openvpn-lan-party-backports.sources openvpn-community.sources \
    lan-party-companion.py lan-party-companion.json.in \
    lan-party-companion-players.json lan-party-companion.service \
    windows/JOIN-VPN.cmd windows/Join-VPN.ps1 \
    windows/Enroll-VPN-High-Assurance.ps1 windows/Test-VPN-High-Assurance.ps1 \
    windows/Leave-OpenVPN-LAN-Party.ps1 \
    windows/Remove-VPN-Disposable-Identity.ps1 \
    windows/LAN-Party-Companion.ps1 windows/LAN-PARTY.cmd; do
    [[ -f $ASSETS_DIR/$required ]] || die "deployment asset is missing: $required"
done

if [[ -e /root/openvpn-pki || -e /etc/openvpn/server/server.conf \
    || -e /etc/openvpn-lan-companion || -e /etc/openvpn-lan-party ]]; then
    die "an OpenVPN PKI, server configuration or LAN companion configuration already exists; refusing to overwrite it"
fi

OPENVPN_VERSION_BEFORE="not installed"
if command -v openvpn >/dev/null 2>&1; then
    OPENVPN_VERSION_BEFORE=$(openvpn_version || printf 'unknown\n')
fi

printf '\nOpenVPN virtual LAN deployment for Debian 13\n'
printf 'This installer does not modify the physical network interface or default route.\n\n'

confirm "Proceed with OpenVPN LAN Party package installation?" \
    || die "installation cancelled before system changes"

printf 'Configuring the official OpenVPN stable repository...\n'
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates curl

DEBIAN_ARCHITECTURE=$(dpkg --print-architecture)
case $DEBIAN_ARCHITECTURE in
    amd64|arm64) ;;
    *) die "the official OpenVPN Debian repository does not support architecture: $DEBIAN_ARCHITECTURE" ;;
esac

install -d -m 755 /etc/apt/keyrings /etc/apt/sources.list.d
OPENVPN_KEY_TEMP=$(mktemp)
trap 'rm -f "$OPENVPN_KEY_TEMP"' EXIT
curl -fsSL "$OPENVPN_REPOSITORY_KEY_URL" -o "$OPENVPN_KEY_TEMP" \
    || die "could not download the official OpenVPN repository signing key"
grep -q '^-----BEGIN PGP PUBLIC KEY BLOCK-----$' "$OPENVPN_KEY_TEMP" \
    || die "the downloaded OpenVPN repository key is not an ASCII-armored PGP key"
install -m 644 "$OPENVPN_KEY_TEMP" "$OPENVPN_REPOSITORY_KEY"
install -m 644 "$ASSETS_DIR/openvpn-community.sources" "$OPENVPN_REPOSITORY_SOURCE"
rm -f "$OPENVPN_KEY_TEMP"
trap - EXIT

printf 'Installing the latest stable OpenVPN package and required Debian packages...\n'
apt-get update
OPENVPN_PACKAGE_CANDIDATE=$(apt-cache madison openvpn \
    | awk '$0 ~ /https:\/\/build\.openvpn\.net\/debian\/openvpn\/stable/ { print $3; exit }')
[[ -n $OPENVPN_PACKAGE_CANDIDATE ]] \
    || die "the official OpenVPN stable repository has no installation candidate"
DEBIAN_FRONTEND=noninteractive apt-get install -y \
    --allow-downgrades "openvpn=$OPENVPN_PACKAGE_CANDIDATE" \
    easy-rsa miniupnpc python3 ca-certificates openssl

OPENVPN_VERSION_AFTER=$(openvpn_version) \
    || die "OpenVPN was installed but its version could not be determined"
if ! openvpn_version_supported "$OPENVPN_VERSION_AFTER"; then
    die "OpenVPN $OPENVPN_VERSION_AFTER remains installed; the current stable branch ($OPENVPN_MINIMUM_VERSION or newer) is required"
fi

OPENVPN_PACKAGE_INSTALLED=$(dpkg-query -W -f='${Version}' openvpn 2>/dev/null) \
    || die "could not determine the installed OpenVPN package version"
dpkg --compare-versions "$OPENVPN_PACKAGE_INSTALLED" eq "$OPENVPN_PACKAGE_CANDIDATE" \
    || die "OpenVPN package $OPENVPN_PACKAGE_INSTALLED is installed but the latest stable candidate is $OPENVPN_PACKAGE_CANDIDATE (check APT holds and pins)"

printf 'Latest stable OpenVPN installed successfully: %s -> %s (package %s)\n' \
    "$OPENVPN_VERSION_BEFORE" "$OPENVPN_VERSION_AFTER" "$OPENVPN_PACKAGE_INSTALLED"

DEFAULT_INTERFACE=$(ip -4 route show default | awk 'NR == 1 { print $5 }')
[[ -n $DEFAULT_INTERFACE ]] || die "could not detect the default network interface"

DETECTED_LAN_IP=$(ip -4 -o address show dev "$DEFAULT_INTERFACE" scope global \
    | awk 'NR == 1 { split($4, address, "/"); print address[1] }')
[[ -n $DETECTED_LAN_IP ]] || die "could not detect the LAN IPv4 address"

DEFAULT_GATEWAY=$(ip -4 route show default | awk 'NR == 1 { print $3 }')

read -r -p "LAN IPv4 address [$DETECTED_LAN_IP]: " LAN_IP
LAN_IP=${LAN_IP:-$DETECTED_LAN_IP}
validate_ipv4 "$LAN_IP" || die "invalid LAN IPv4 address: $LAN_IP"

UPNP_OUTPUT=$(timeout 15s upnpc -l 2>/dev/null || true)
DETECTED_PUBLIC_IP=$(awk -F '= ' '/ExternalIPAddress/ { print $2; exit }' <<< "$UPNP_OUTPUT" \
    | tr -d '\r')

if [[ -n $DETECTED_PUBLIC_IP ]]; then
    printf 'UPnP detected public address: %s\n' "$DETECTED_PUBLIC_IP"
fi

while true; do
    read -r -p "Public IPv4 address or DNS name${DETECTED_PUBLIC_IP:+ [$DETECTED_PUBLIC_IP]}: " REMOTE_HOST
    REMOTE_HOST=${REMOTE_HOST:-$DETECTED_PUBLIC_IP}
    if [[ $REMOTE_HOST =~ ^[A-Za-z0-9.-]{1,253}$ ]]; then
        break
    fi
    printf 'Enter a valid IPv4 address or DNS hostname.\n'
done

while true; do
    read -r -p "OpenVPN UDP port [1194]: " VPN_PORT
    VPN_PORT=${VPN_PORT:-1194}
    if [[ $VPN_PORT =~ ^[0-9]+$ ]] && (( VPN_PORT >= 1 && VPN_PORT <= 65535 )); then
        break
    fi
    printf 'Enter a valid UDP port between 1 and 65535.\n'
done
ENROLLMENT_PORT=8790
if (( VPN_PORT == ENROLLMENT_PORT )); then
    ENROLLMENT_PORT=8791
fi

while true; do
    read -r -p "Isolated VPN subnet [10.44.0.0/24]: " VPN_CIDR
    VPN_CIDR=${VPN_CIDR:-10.44.0.0/24}
    validate_cidr24 "$VPN_CIDR" && break
    printf 'Enter a valid /24 IPv4 network ending in .0/24.\n'
done

VPN_PREFIX=${VPN_CIDR%.0/24}
VPN_SERVER_IP="$VPN_PREFIX.1"
VPN_POOL_START="$VPN_PREFIX.10"
VPN_POOL_END="$VPN_PREFIX.200"

if ip -4 route show | awk '{ print $1 }' | grep -Fxq "$VPN_CIDR"; then
    printf 'Warning: %s already appears in the routing table.\n' "$VPN_CIDR"
    confirm "Continue despite the subnet conflict?" || die "choose another VPN subnet"
fi

ENABLE_UPNP=false
if grep -q 'Found valid IGD' <<< "$UPNP_OUTPUT"; then
    confirm "Enable and refresh the OpenVPN and enrollment UPnP mappings automatically?" \
        && ENABLE_UPNP=true
else
    printf 'No UPnP Internet Gateway Device was detected.\n'
fi
PORTAL_UPNP=$ENABLE_UPNP

ENABLE_PUBLIC_TLS=false
ACME_EMAIL=""
if validate_public_ipv4 "$REMOTE_HOST"; then
    if confirm "Use a publicly trusted Let's Encrypt certificate for this IPv4?"; then
        ENABLE_PUBLIC_TLS=true
        while true; do
            read -r -p "Let's Encrypt account email: " ACME_EMAIL
            validate_email "$ACME_EMAIL" && break
            printf 'Enter a valid contact email address.\n'
        done
        if [[ $ENABLE_UPNP == false ]]; then
            printf '%s\n' \
                'Let'"'"'s Encrypt HTTP-01 requires public TCP port 80.' \
                "Map public TCP 80 to $LAN_IP:9080 for issuance and renewals."
            confirm "Continue with a manual TCP 80 mapping?" \
                || die "public certificate setup cancelled"
        fi
    fi
else
    printf '%s\n' \
        'Automatic Let'"'"'s Encrypt IP certificates require a globally routable IPv4.' \
        'The portal will use an independent self-signed certificate.'
fi

printf '\nConfiguration summary\n'
printf '  Invitation policy  : high-assurance by default; compatible by explicit choice\n'
printf '  Physical interface : %s\n' "$DEFAULT_INTERFACE"
printf '  LAN address        : %s\n' "$LAN_IP"
printf '  Default gateway    : %s\n' "${DEFAULT_GATEWAY:-unknown}"
printf '  Public endpoint    : %s:%s/UDP\n' "$REMOTE_HOST" "$VPN_PORT"
printf '  Enrollment portal  : %s:%s/TCP\n' "$REMOTE_HOST" "$ENROLLMENT_PORT"
printf '  Virtual LAN        : %s\n' "$VPN_CIDR"
printf '  Virtual server     : %s\n' "$VPN_SERVER_IP"
printf '  Client pool        : %s - %s\n' "$VPN_POOL_START" "$VPN_POOL_END"
printf '  Automatic UPnP     : %s\n\n' "$ENABLE_UPNP"
if [[ $ENABLE_PUBLIC_TLS == true ]]; then
    printf '  Portal TLS         : Let'"'"'s Encrypt short-lived IP certificate\n'
    printf '  ACME challenge     : public TCP 80 -> %s:9080\n\n' "$LAN_IP"
else
    printf '  Portal TLS         : self-signed (manual fingerprint check)\n\n'
fi

confirm "Install this configuration?" || die "installation cancelled"

if [[ $ENABLE_PUBLIC_TLS == true ]]; then
    install -m 644 "$ASSETS_DIR/openvpn-lan-party-backports.sources" \
        /etc/apt/sources.list.d/openvpn-lan-party-backports.sources
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y -t trixie-backports lego
fi

printf '\nGenerating a new, independent PKI...\n'
EASYRSA_BATCH=1 EASYRSA_PKI=/root/openvpn-pki EASYRSA_REQ_CN='OPENVPN LAN PARTY' \
    EASYRSA_ALGO=ec EASYRSA_CURVE=prime256v1 \
    /usr/share/easy-rsa/easyrsa init-pki
install -d -m 700 /root/openvpn-pki/x509-types
install -m 644 "$ASSETS_DIR/x509-types/vpn-player" \
    /root/openvpn-pki/x509-types/vpn-player
EASYRSA_BATCH=1 EASYRSA_PKI=/root/openvpn-pki EASYRSA_REQ_CN='OPENVPN LAN PARTY' \
    EASYRSA_ALGO=ec EASYRSA_CURVE=prime256v1 \
    /usr/share/easy-rsa/easyrsa build-ca nopass
EASYRSA_BATCH=1 EASYRSA_PKI=/root/openvpn-pki \
    EASYRSA_ALGO=ec EASYRSA_CURVE=prime256v1 \
    /usr/share/easy-rsa/easyrsa build-server-full server nopass
EASYRSA_BATCH=1 EASYRSA_PKI=/root/openvpn-pki EASYRSA_CRL_DAYS=3650 \
    /usr/share/easy-rsa/easyrsa gen-crl
openvpn --genkey tls-crypt-v2-server /root/openvpn-pki/tls-crypt-v2-server.key

chmod 711 /etc/openvpn
chown root:root /etc/openvpn
install -d -o root -g nogroup -m 710 /etc/openvpn/server
install -d -m 755 /var/lib/openvpn /usr/local/share/vpn-manager/windows /usr/local/libexec
install -d -o root -g root -m 700 /var/lib/openvpn-lan-party/enrollment
printf '%s\n' '{"credentials":{},"schema":1}' \
    > /var/lib/openvpn/credential-registry.json
chown root:nogroup /var/lib/openvpn/credential-registry.json
chmod 640 /var/lib/openvpn/credential-registry.json

if ! getent passwd vpnportal >/dev/null; then
    useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin vpnportal
fi
chown root:vpnportal /var/lib/openvpn-lan-party
chmod 710 /var/lib/openvpn-lan-party
install -d -o vpnportal -g vpnportal -m 700 \
    /var/lib/openvpn-lan-party/enrollment-portal
install -d -o root -g vpnportal -m 750 /etc/openvpn-lan-party

if ! getent passwd vpncompanion >/dev/null; then
    useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin vpncompanion
fi
install -d -o root -g vpncompanion -m 750 /etc/openvpn-lan-companion
render "$ASSETS_DIR/lan-party-companion.json.in" \
    /etc/openvpn-lan-companion/config.json
install -o root -g vpncompanion -m 640 \
    "$ASSETS_DIR/lan-party-companion-players.json" \
    /etc/openvpn-lan-companion/players.json
chown root:vpncompanion /etc/openvpn-lan-companion/config.json
chmod 640 /etc/openvpn-lan-companion/config.json
COMPANION_VERSION=$(python3 "$ASSETS_DIR/lan-party-companion.py" --version) \
    || die "the LAN Party Companion source cannot report its version"
python3 "$ASSETS_DIR/lan-party-companion.py" \
    --config /etc/openvpn-lan-companion/config.json validate >/dev/null \
    || die "the generated Companion configuration is invalid"

if validate_ipv4 "$REMOTE_HOST"; then
    PORTAL_SAN="IP:$REMOTE_HOST"
else
    PORTAL_SAN="DNS:$REMOTE_HOST"
fi
openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 397 \
    -subj '/CN=OpenVPN LAN Party Enrollment Portal' \
    -addext "subjectAltName=$PORTAL_SAN" \
    -keyout /etc/openvpn-lan-party/tls.key \
    -out /etc/openvpn-lan-party/tls.crt >/dev/null 2>&1
chown root:vpnportal \
    /etc/openvpn-lan-party/tls.key \
    /etc/openvpn-lan-party/tls.crt
chmod 640 /etc/openvpn-lan-party/tls.key
chmod 644 /etc/openvpn-lan-party/tls.crt

render "$ASSETS_DIR/vpn-enrollment-portal.json.in" \
    /etc/openvpn-lan-party/enrollment-portal.json
chown root:vpnportal /etc/openvpn-lan-party/enrollment-portal.json
chmod 640 /etc/openvpn-lan-party/enrollment-portal.json

render "$ASSETS_DIR/server.conf.in" /etc/openvpn/server/server.conf
chmod 600 /etc/openvpn/server/server.conf
install -m 644 /root/openvpn-pki/ca.crt /etc/openvpn/server/ca.crt
install -m 644 /root/openvpn-pki/issued/server.crt /etc/openvpn/server/server.crt
install -m 600 /root/openvpn-pki/private/server.key /etc/openvpn/server/server.key
install -m 644 /root/openvpn-pki/crl.pem /etc/openvpn/server/crl.pem
install -m 600 /root/openvpn-pki/tls-crypt-v2-server.key \
    /etc/openvpn/server/tls-crypt-v2-server.key

install -m 644 "$ASSETS_DIR/windows/Enroll-VPN-High-Assurance.ps1" \
    /usr/local/share/vpn-manager/windows/Enroll-VPN-High-Assurance.ps1
install -m 644 "$ASSETS_DIR/windows/Test-VPN-High-Assurance.ps1" \
    /usr/local/share/vpn-manager/windows/Test-VPN-High-Assurance.ps1
install -m 644 "$ASSETS_DIR/windows/Leave-OpenVPN-LAN-Party.ps1" \
    /usr/local/share/vpn-manager/windows/Leave-OpenVPN-LAN-Party.ps1
install -m 644 "$ASSETS_DIR/windows/JOIN-VPN.cmd" \
    /usr/local/share/vpn-manager/windows/JOIN-VPN.cmd
install -m 644 "$ASSETS_DIR/windows/Join-VPN.ps1" \
    /usr/local/share/vpn-manager/windows/Join-VPN.ps1
install -m 644 "$ASSETS_DIR/windows/Remove-VPN-Disposable-Identity.ps1" \
    /usr/local/share/vpn-manager/windows/Remove-VPN-Disposable-Identity.ps1
install -m 644 "$ASSETS_DIR/windows/LAN-Party-Companion.ps1" \
    /usr/local/share/vpn-manager/windows/LAN-Party-Companion.ps1
install -m 644 "$ASSETS_DIR/windows/LAN-PARTY.cmd" \
    /usr/local/share/vpn-manager/windows/LAN-PARTY.cmd
install -m 755 "$ASSETS_DIR/vpn-player-enrollment.py" \
    /usr/local/libexec/vpn-player-enrollment.py
install -m 755 "$ASSETS_DIR/vpn-enrollment-csr.py" \
    /usr/local/libexec/vpn-enrollment-csr.py
install -m 755 "$ASSETS_DIR/vpn-enrollment-admin.py" \
    /usr/local/libexec/vpn-enrollment-admin.py
install -m 755 "$ASSETS_DIR/vpn-enrollment-portal.py" \
    /usr/local/libexec/vpn-enrollment-portal.py
install -m 755 "$ASSETS_DIR/verify-tls-crypt-v2-player" \
    /usr/local/libexec/verify-tls-crypt-v2-player
install -m 755 "$ASSETS_DIR/audit-openvpn-lan-party" \
    /usr/local/sbin/audit-openvpn-lan-party
render "$ASSETS_DIR/vpn-enrollment-admin.in" /usr/local/sbin/vpn-enrollment-admin
chmod 755 /usr/local/sbin/vpn-enrollment-admin
install -m 755 "$ASSETS_DIR/lan-party-companion.py" \
    /usr/local/libexec/lan-party-companion
install -m 644 "$ASSETS_DIR/vpn-enrollment-portal.service" \
    /etc/systemd/system/vpn-enrollment-portal.service
install -m 644 "$ASSETS_DIR/lan-party-companion.service" \
    /etc/systemd/system/lan-party-companion.service

if [[ $ENABLE_PUBLIC_TLS == true ]]; then
    install -d -o root -g root -m 700 /etc/vpn-enrollment-acme
    install -m 755 "$ASSETS_DIR/vpn-profile-acme.py" \
        /usr/local/libexec/vpn-enrollment-acme
    install -m 644 "$ASSETS_DIR/vpn-profile-acme-renew.service" \
        /etc/systemd/system/vpn-enrollment-acme-renew.service
    install -m 644 "$ASSETS_DIR/vpn-profile-acme-renew.timer" \
        /etc/systemd/system/vpn-enrollment-acme-renew.timer
    REMOTE_HOST="$REMOTE_HOST" LAN_IP="$LAN_IP" ACME_EMAIL="$ACME_EMAIL" \
        PORTAL_UPNP="$PORTAL_UPNP" \
        python3 - "$ASSETS_DIR/vpn-profile-acme.json.in" \
            /etc/vpn-enrollment-acme/config.json <<'PY'
import json
import os
import sys

template = open(sys.argv[1], encoding="utf-8").read()
template = template.replace('"__REMOTE_HOST__"', json.dumps(os.environ["REMOTE_HOST"]))
template = template.replace('"__LAN_IP__"', json.dumps(os.environ["LAN_IP"]))
template = template.replace('"__ACME_EMAIL__"', json.dumps(os.environ["ACME_EMAIL"]))
template = template.replace("__PORTAL_UPNP__", os.environ["PORTAL_UPNP"])
config = json.loads(template)
with open(sys.argv[2], "w", encoding="utf-8") as handle:
    json.dump(config, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY
    chmod 600 /etc/vpn-enrollment-acme/config.json
fi

render "$ASSETS_DIR/openvpn-tap-bridge.service.in" /etc/systemd/system/openvpn-tap-bridge.service
chmod 644 /etc/systemd/system/openvpn-tap-bridge.service
install -d -m 755 /etc/systemd/system/openvpn-server@server.service.d
install -m 644 "$ASSETS_DIR/openvpn-server-bridge.conf" \
    /etc/systemd/system/openvpn-server@server.service.d/bridge.conf

if [[ $ENABLE_UPNP == true ]]; then
    render "$ASSETS_DIR/openvpn-upnp.service.in" /etc/systemd/system/openvpn-upnp.service
    chmod 644 /etc/systemd/system/openvpn-upnp.service
    install -m 644 "$ASSETS_DIR/openvpn-upnp.timer" /etc/systemd/system/openvpn-upnp.timer
fi

systemctl daemon-reload

PUBLIC_TLS_READY=false
if [[ $ENABLE_PUBLIC_TLS == true ]]; then
    if /usr/local/libexec/vpn-enrollment-acme \
        --config /etc/vpn-enrollment-acme/config.json issue; then
        PUBLIC_TLS_READY=true
    else
        printf '%s\n' >&2 \
            'Warning: the public portal certificate could not be issued yet.' \
            'The fallback certificate remains self-signed, and new invitations' \
            'will fail closed until the ACME issue is corrected.'
    fi
    systemctl enable --now vpn-enrollment-acme-renew.timer
fi

systemctl enable --now openvpn-server@server.service
systemctl enable --now lan-party-companion.service
systemctl enable --now vpn-enrollment-portal.service

if [[ $ENABLE_UPNP == true ]]; then
    systemctl enable --now openvpn-upnp.timer
    systemctl start openvpn-upnp.service
fi

systemctl is-active --quiet openvpn-server@server.service \
    || die "OpenVPN did not start"
systemctl is-active --quiet lan-party-companion.service \
    || die "the LAN Party Companion service did not start"
systemctl is-active --quiet vpn-enrollment-portal.service \
    || die "the enrollment portal did not start"
ip -4 address show dev br-vpn | grep -Fq "$VPN_SERVER_IP/24" \
    || die "the isolated bridge did not receive $VPN_SERVER_IP/24"
ss -lun | grep -Eq ":${VPN_PORT}[[:space:]]" \
    || die "OpenVPN is not listening on UDP port $VPN_PORT"
PORTAL_READY=false
for _attempt in {1..50}; do
    if ss -ltn | grep -Eq ":${ENROLLMENT_PORT}[[:space:]]"; then
        PORTAL_READY=true
        break
    fi
    systemctl is-active --quiet vpn-enrollment-portal.service \
        || break
    sleep 0.2
done
[[ $PORTAL_READY == true ]] \
    || die "the enrollment portal is not listening on TCP port $ENROLLMENT_PORT"
COMPANION_READY=false
for _attempt in {1..30}; do
    COMPANION_HEALTH=$(curl --noproxy '*' -fsS \
        "http://$VPN_SERVER_IP:8787/healthz" 2>/dev/null || true)
    if [[ $COMPANION_HEALTH == *'"service":"lan-party-companion"'* \
        && $COMPANION_HEALTH == *"\"version\":\"$COMPANION_VERSION\""* ]]; then
        COMPANION_READY=true
        break
    fi
    sleep 0.2
done
[[ $COMPANION_READY == true ]] \
    || die "the LAN Party Companion health check failed"
if ss -lntH 'sport = :8787' \
    | awk -v expected="$VPN_SERVER_IP:8787" \
        '$4 != expected { unexpected = 1 } END { exit !unexpected }'; then
    die "the LAN Party Companion listener is not restricted to the VPN address"
fi
PHYSICAL_SOURCE_IP=$(ip -4 route get 1.1.1.1 2>/dev/null \
    | awk '{ for (i = 1; i <= NF; i++) if ($i == "src") { print $(i + 1); exit } }')
if [[ -n $PHYSICAL_SOURCE_IP && $PHYSICAL_SOURCE_IP != "$VPN_SERVER_IP" ]] \
    && curl --noproxy '*' --connect-timeout 1 -fsS \
        "http://$PHYSICAL_SOURCE_IP:8787/healthz" >/dev/null 2>&1; then
    die "the LAN Party Companion unexpectedly answers on the physical LAN address"
fi

cat > /root/VPN-SERVER-INFO.txt <<EOF
VPN server deployment summary
=============================

Installed: $(date --iso-8601=seconds)
Physical interface: $DEFAULT_INTERFACE
LAN address: $LAN_IP
Public endpoint: $REMOTE_HOST:$VPN_PORT/UDP
Enrollment portal: $REMOTE_HOST:$ENROLLMENT_PORT/TCP
Invitation policy: high-assurance by default; compatible requires explicit administrator acknowledgement
Virtual LAN: $VPN_CIDR
Virtual server: $VPN_SERVER_IP
LAN Party Companion: http://$VPN_SERVER_IP:8787
Client pool: $VPN_POOL_START - $VPN_POOL_END
Automatic UPnP: $ENABLE_UPNP
Portal public TLS requested: $ENABLE_PUBLIC_TLS
Portal public TLS ready: $PUBLIC_TLS_READY

Create a portal-hosted Windows invitation: vpn-enrollment-admin create --player PLAYER
The command prints the download URL, archive password and separate one-time token.
Windows acceptance: /usr/local/share/vpn-manager/windows/Test-VPN-High-Assurance.ps1
Windows disposable key-loss helper: /usr/local/share/vpn-manager/windows/Remove-VPN-Disposable-Identity.ps1
Windows local offboarding helper: /usr/local/share/vpn-manager/windows/Leave-OpenVPN-LAN-Party.ps1
PKI: /root/openvpn-pki
EOF
chmod 600 /root/VPN-SERVER-INFO.txt

printf '\nInstallation completed successfully.\n'
printf 'Create the first portal-hosted Windows invitation with: vpn-enrollment-admin create --player PLAYER\n'
printf 'Send its archive password and one-time token separately from the download link.\n'
printf 'Important: reserve %s for this server in DHCP or configure it statically.\n' "$LAN_IP"
printf 'If a firewall is enabled, allow UDP port %s.\n' "$VPN_PORT"
printf 'For enrollment, forward TCP port %s to this server.\n' "$ENROLLMENT_PORT"
if [[ $ENABLE_PUBLIC_TLS == true ]]; then
    printf 'Let'"'"'s Encrypt status: /usr/local/libexec/vpn-enrollment-acme --config /etc/vpn-enrollment-acme/config.json status\n'
    printf 'ACME HTTP-01 uses public TCP port 80 only during issuance or renewal.\n'
fi
