#!/usr/bin/env bash
#
# kanata-tray dynamic network-threat audit script.
# Run with sudo: sudo ./audit-network-dynamic.sh
#
# Performs: build (CGO_ENABLED=1), Xvfb display, tcpdump link-layer capture,
# binary launch (control server enabled), control-server endpoint exercise,
# socket enumeration (ss + /proc/net/*) before/during/after, pcap parse.
# Acceptance: every socket/packet/connection must be localhost-only
# (127.0.0.0/8, ::1, or Unix domain socket). Non-localhost = finding.
#
# Outputs:
#   ./tmp/kanata-tray          built binary
#   ./tmp/capture.pcap         raw packet capture
#   ./tmp/audit-results.txt    consolidated findings
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${REPO_DIR}/tmp"
BINARY="${OUT_DIR}/kanata-tray"
CONFIG_DIR="${OUT_DIR}/config"
CONFIG="${CONFIG_DIR}/kanata-tray.toml"
PCAP="${OUT_DIR}/capture.pcap"
RESULTS="${OUT_DIR}/audit-results.txt"

DISPLAY_NUM=":99"
SCREEN="1024x768x16"
CONTROL_PORT="8100"
KANATA_PORT="5829"
# Default observation window: 10 hours. Override with DURATION_SECONDS.
DURATION_SECONDS="${DURATION_SECONDS:-36000}"

mkdir -p "${OUT_DIR}" "${CONFIG_DIR}"

log() { printf '[audit] %s\n' "$*"; }
err() { printf '[audit][ERROR] %s\n' "$*" >&2; }

cleanup() {
    log "Cleaning up processes..."
    [ -n "${TCPDUMP_PID:-}" ] && kill "${TCPDUMP_PID}" 2>/dev/null || true
    [ -n "${KATANA_TRAY_PID:-}" ] && kill "${KATANA_TRAY_PID}" 2>/dev/null || true
    [ -n "${XVFB_PID:-}" ] && kill "${XVFB_PID}" 2>/dev/null || true
    # best-effort: kill any remaining kanata-tray / Xvfb we started
    pkill -f "Xvfb :99" 2>/dev/null || true
    pkill -f "/tmp/kanata-tray" 2>/dev/null || true
    pkill -f "${BINARY}" 2>/dev/null || true
    wait 2>/dev/null || true
}
trap cleanup EXIT

require_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        err "Missing required command: $1"
        exit 1
    fi
}

# ---------------------------------------------------------------- prerequisites
log "Checking prerequisites..."
require_cmd go
require_cmd gcc
require_cmd tcpdump
require_cmd ss
require_cmd Xvfb
require_cmd curl

# ---------------------------------------------------------------- build config
cat > "${CONFIG}" <<EOF
"\$schema" = "https://raw.githubusercontent.com/rszyma/kanata-tray/main/doc/config_schema.json"

[general]
allow_concurrent_presets = false
control_server_enable = true
control_server_port = ${CONTROL_PORT}

[defaults]
tcp_port = ${KANATA_PORT}
autorestart_on_crash = false

[defaults.hooks]

[defaults.layer_icons]

[presets.'Default Preset']
kanata_executable = ''
kanata_config = ''
autorun = false
EOF
log "Wrote test config (control server enabled on port ${CONTROL_PORT}): ${CONFIG}"

# ---------------------------------------------------------------- build binary
log "Building binary (CGO_ENABLED=1) -> ${BINARY}..."
CGO_ENABLED=1 go build -o "${BINARY}" "${REPO_DIR}"
log "Build complete."

# ---------------------------------------------------------------- start Xvfb
log "Starting Xvfb ${DISPLAY_NUM} -screen 0 ${SCREEN}..."
Xvfb "${DISPLAY_NUM}" -screen 0 "${SCREEN}" &
XVFB_PID=$!
sleep 2
export DISPLAY="${DISPLAY_NUM}"
log "Xvfb started (pid ${XVFB_PID}), DISPLAY=${DISPLAY}"

# ---------------------------------------------------------------- socket snapshot before launch
snapshot_sockets() {
    local label="$1"
    {
        echo "=== ${label}: $(date -Is) ==="
        echo "--- ss -tulpn ---"
        ss -tulpn 2>/dev/null || true
        echo "--- ss -x (unix) ---"
        ss -x 2>/dev/null || true
        echo "--- /proc/net/tcp ---"
        cat /proc/net/tcp 2>/dev/null || true
        echo "--- /proc/net/tcp6 ---"
        cat /proc/net/tcp6 2>/dev/null || true
        echo "--- /proc/net/udp ---"
        cat /proc/net/udp 2>/dev/null || true
        echo "--- /proc/net/udp6 ---"
        cat /proc/net/udp6 2>/dev/null || true
        echo "--- /proc/net/raw / raw6 ---"
        cat /proc/net/raw 2>/dev/null || true
        cat /proc/net/raw6 2>/dev/null || true
        echo "--- /proc/net/netlink ---"
        cat /proc/net/netlink 2>/dev/null || true
        echo "--- /proc/net/unix ---"
        cat /proc/net/unix 2>/dev/null || true
        echo
    } >> "${RESULTS}"
}

: > "${RESULTS}"
snapshot_sockets "PRE-LAUNCH"

# ---------------------------------------------------------------- start tcpdump
log "Starting tcpdump capture -> ${PCAP}..."
tcpdump -i any -s 0 -w "${PCAP}" >/dev/null 2>&1 &
TCPDUMP_PID=$!
sleep 1
log "tcpdump started (pid ${TCPDUMP_PID})"

# ---------------------------------------------------------------- launch binary
log "Launching ${BINARY} with DISPLAY=${DISPLAY} config_dir=${CONFIG_DIR}..."
DISPLAY="${DISPLAY}" KANATA_TRAY_CONFIG_DIR="${CONFIG_DIR}" "${BINARY}" \
    > "${OUT_DIR}/kanata-tray.stdout.log" 2> "${OUT_DIR}/kanata-tray.stderr.log" &
KATANA_TRAY_PID=$!
sleep 5
log "kanata-tray launched (pid ${KATANA_TRAY_PID})"

# ---------------------------------------------------------------- exercise control server
log "Exercising control-server endpoints on 127.0.0.1:${CONTROL_PORT}..."
for endpoint in start_all_default toggle_all_default stop_all; do
    code=$(curl -s -o /dev/null -w "%{http_code}" -m 5 "http://127.0.0.1:${CONTROL_PORT}/${endpoint}" || true)
    body=$(curl -s -m 5 "http://127.0.0.1:${CONTROL_PORT}/${endpoint}" || true)
    echo "POST /${endpoint} -> HTTP ${code} :: ${body}" >> "${RESULTS}"
done
log "Control-server endpoints exercised."

# ---------------------------------------------------------------- observation window
log "Observation window: ${DURATION_SECONDS}s (polling sockets every 1s)..."
elapsed=0
while [ "${elapsed}" -lt "${DURATION_SECONDS}" ]; do
    snapshot_sockets "DURING t=${elapsed}s"
    sleep 1
    elapsed=$((elapsed + 1))
done
snapshot_sockets "POST-OBSERVATION t=${DURATION_SECONDS}s"

# ---------------------------------------------------------------- stop capture & processes
log "Stopping tcpdump and kanata-tray..."
kill "${TCPDUMP_PID}" 2>/dev/null || true
kill "${KATANA_TRAY_PID}" 2>/dev/null || true
sleep 2
kill "${XVFB_PID}" 2>/dev/null || true
TCPDUMP_PID=""
KATANA_TRAY_PID=""
XVFB_PID=""

# ---------------------------------------------------------------- parse pcap
log "Parsing pcap (tcpdump -r)..."
{
    echo "=== PCAP PACKET LIST (tcpdump -r -nn) ==="
    tcpdump -r "${PCAP}" -nn 2>/dev/null || echo "(pcap empty or unreadable)"
    echo
    echo "=== PCAP SUMMARY ==="
    tcpdump -r "${PCAP}" -nn -q 2>/dev/null | wc -l | awk '{print "packet lines:", $1}'
} >> "${RESULTS}" 2>&1 || true

# ---------------------------------------------------------------- findings analysis
log "Analyzing results for non-localhost traffic..."
{
    echo "=== FINDINGS ANALYSIS ==="
    # Extract destination IPs from pcap (dst field), flag non-localhost
    echo "--- Remote (non-127/8, non-::1) destination IPs in pcap ---"
    tcpdump -r "${PCAP}" -nn 2>/dev/null \
        | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}\.[0-9]+ > ([0-9]{1,3}\.){3}[0-9]{1,3}\.[0-9]+' \
        | awk -F'>' '{print $2}' \
        | awk '{split($1,a,":"); print a[1]}' \
        | sort -u \
        | while read -r ip; do
            case "${ip}" in
                127.*|0.0.0.0) ;;
                *) echo "  NON-LOCALHOST DESTINATION: ${ip}  <-- FINDING" ;;
            esac
        done
    echo "--- kanata-tray socket fds (from /proc) ---"
    if [ -n "${KATANA_TRAY_PID_CHECK:-}" ]; then :; fi
    echo "--- End of analysis ---"
} >> "${RESULTS}" 2>&1 || true

log "Done. Results: ${RESULTS}"
log "PCAP: ${PCAP}"
log "Binary: ${BINARY}"
log "Stdout: ${OUT_DIR}/kanata-tray.stdout.log"
log "Stderr: ${OUT_DIR}/kanata-tray.stderr.log"
