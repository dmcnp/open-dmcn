#!/usr/bin/env bash
# Install dmcnd as a systemd service.
#
#   sudo deploy/install.sh [--binary PATH] [--data DIR | --identity FILE]
#                          [--bridge-credential FILE] [--dkim-key FILE] [--audit-log FILE]
#
#   --binary PATH    the dmcnd binary to install. Default: bin/dmcnd in this checkout (after
#                    `make build`), then ./dmcnd, then whatever `dmcnd` is on PATH.
#   --data DIR       move an existing deployment over: copy the data directory a manually run
#                    daemon used (its DMCND_DATA_DIR, `data` by default) into /var/lib/dmcnd.
#                    Stop that daemon first. Refused if /var/lib/dmcnd already holds anything.
#   --identity FILE  keep only the node's libp2p identity (its node.key) and start everything
#                    else fresh, e.g. when the host moves to a different domain but the peer ID
#                    should stay. Refused if a different identity is already installed.
#
# The bridge's files, for a deployment that already runs one. The service cannot read anything
# under /home (ProtectHome), so files a hand-run daemon used from there have to move:
#   --bridge-credential FILE   -> /etc/dmcnd/bridge.cred           (root:dmcnd 0640)
#   --dkim-key FILE            -> /etc/dmcnd/dkim.pem              (root:dmcnd 0640)
#   --audit-log FILE           -> /var/lib/dmcnd/bridge-audit.jsonl (dmcnd 0600; the daemon appends)
# These are the paths dmcnd.env already names. Each is refused if a different file is already
# there: a replaced DKIM key breaks signing until DNS catches up, and a replaced audit log loses
# the hash chain.
#
# What it does: creates the `dmcnd` system user, installs the binary to /usr/local/bin, the unit
# to /etc/systemd/system/dmcnd.service and, only if none exists yet, the settings template to
# /etc/dmcnd/dmcnd.env. It prints the node's peer ID (what `dmcndcli domain init --seed` needs)
# and opens the firewall when ufw is active. It never starts or restarts the service.
#
# Safe to re-run, which is also how you upgrade: pass the new binary, then restart the service.
# The unit is always rewritten from this checkout; your dmcnd.env and data are never touched.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SVC_USER="dmcnd"
STATE_DIR="/var/lib/dmcnd"
CONF_DIR="/etc/dmcnd"
ENV_FILE="${CONF_DIR}/dmcnd.env"
UNIT_FILE="/etc/systemd/system/dmcnd.service"
INSTALL_BIN="/usr/local/bin/dmcnd"
IDENTITY="${STATE_DIR}/node.key"
CRED_DEST="${CONF_DIR}/bridge.cred"
DKIM_DEST="${CONF_DIR}/dkim.pem"
AUDIT_DEST="${STATE_DIR}/bridge-audit.jsonl"

die() { echo "error: $*" >&2; exit 1; }

# refuse_replace SRC DEST: fail unless DEST is absent or already identical to SRC.
refuse_replace() {
  [[ -f "$1" ]] || die "$1 is not a file"
  if [[ -e "$2" ]] && ! cmp -s "$1" "$2"; then
    die "$2 already exists and differs from $1; not replacing it"
  fi
}

BIN_SRC=""
DATA_SRC=""
IDENTITY_SRC=""
CRED_SRC=""
DKIM_SRC=""
AUDIT_SRC=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --binary)   BIN_SRC="${2:?--binary needs a path}"; shift 2 ;;
    --data)     DATA_SRC="${2:?--data needs a directory}"; shift 2 ;;
    --identity) IDENTITY_SRC="${2:?--identity needs a file}"; shift 2 ;;
    --bridge-credential) CRED_SRC="${2:?--bridge-credential needs a file}"; shift 2 ;;
    --dkim-key)  DKIM_SRC="${2:?--dkim-key needs a file}"; shift 2 ;;
    --audit-log) AUDIT_SRC="${2:?--audit-log needs a file}"; shift 2 ;;
    -h|--help)  awk 'NR == 1 { next } !/^#/ { exit } { sub(/^# ?/, ""); print }' "${BASH_SOURCE[0]}"; exit 0 ;;
    *)          die "unknown argument: $1 (see --help)" ;;
  esac
done

[[ "${EUID}" -eq 0 ]] || die "run as root (sudo)"
command -v systemctl >/dev/null 2>&1 || die "systemd not found; this installer only writes a systemd unit"
[[ -n "${DATA_SRC}" && -n "${IDENTITY_SRC}" ]] && die "--data already carries node.key; pass one or the other"
[[ -f "${SCRIPT_DIR}/dmcnd.service" && -f "${SCRIPT_DIR}/dmcnd.env" ]] \
  || die "dmcnd.service and dmcnd.env must sit next to this script (run it from a checkout's deploy/)"

if [[ -z "${BIN_SRC}" ]]; then
  for cand in "${SCRIPT_DIR}/../bin/dmcnd" "./dmcnd" "$(command -v dmcnd 2>/dev/null || true)"; do
    if [[ -n "${cand}" && -x "${cand}" && "$(realpath "${cand}")" != "${INSTALL_BIN}" ]]; then
      BIN_SRC="${cand}"; break
    fi
  done
fi
if [[ -z "${BIN_SRC}" && -x "${INSTALL_BIN}" ]]; then
  BIN_SRC="${INSTALL_BIN}"  # re-run with nothing new: keep the installed binary
fi
[[ -n "${BIN_SRC}" && -f "${BIN_SRC}" ]] \
  || die "dmcnd binary not found; build it (make build) or pass --binary PATH. Under sudo, ~/go/bin is not on PATH"
"${BIN_SRC}" version >/dev/null 2>&1 || die "${BIN_SRC} does not run here (wrong OS or architecture?)"

if [[ -n "${DATA_SRC}" ]]; then
  [[ -d "${DATA_SRC}" ]] || die "--data ${DATA_SRC} is not a directory"
  [[ -f "${DATA_SRC}/node.key" ]] || die "--data ${DATA_SRC} has no node.key; is this the daemon's data directory?"
  if [[ -d "${STATE_DIR}" ]] && [[ -n "$(ls -A "${STATE_DIR}")" ]]; then
    die "${STATE_DIR} is not empty; refusing to copy ${DATA_SRC} over an existing deployment"
  fi
fi
if [[ -n "${IDENTITY_SRC}" ]]; then
  [[ -f "${IDENTITY_SRC}" ]] || die "--identity ${IDENTITY_SRC} is not a file"
  if [[ -f "${IDENTITY}" ]] && ! cmp -s "${IDENTITY_SRC}" "${IDENTITY}"; then
    die "${IDENTITY} already holds a different identity; its peer ID may be in DNS, so it is not replaced"
  fi
fi
if [[ -n "${CRED_SRC}" ]]; then refuse_replace "${CRED_SRC}" "${CRED_DEST}"; fi
if [[ -n "${DKIM_SRC}" ]]; then refuse_replace "${DKIM_SRC}" "${DKIM_DEST}"; fi
if [[ -n "${AUDIT_SRC}" ]]; then
  refuse_replace "${AUDIT_SRC}" "${AUDIT_DEST}"
  # --data lands first; a log of the same name inside it would be the one replaced.
  if [[ -n "${DATA_SRC}" ]]; then
    refuse_replace "${AUDIT_SRC}" "${DATA_SRC}/$(basename "${AUDIT_DEST}")"
  fi
fi

echo "==> System user '${SVC_USER}'"
if ! id -u "${SVC_USER}" >/dev/null 2>&1; then
  useradd --system --home-dir "${STATE_DIR}" --shell /usr/sbin/nologin "${SVC_USER}"
fi

if [[ "$(realpath "${BIN_SRC}")" != "${INSTALL_BIN}" ]]; then
  echo "==> Installing ${BIN_SRC} to ${INSTALL_BIN}"
  install -m 0755 "${BIN_SRC}" "${INSTALL_BIN}"
fi
echo "    $("${INSTALL_BIN}" version)"

echo "==> Directories"
install -d -o "${SVC_USER}" -g "${SVC_USER}" -m 0700 "${STATE_DIR}"
# Root-owned and group-readable: the daemon reads its settings and credentials, never writes them.
install -d -o root -g "${SVC_USER}" -m 0750 "${CONF_DIR}"

if [[ -n "${DATA_SRC}" ]]; then
  echo "==> Copying ${DATA_SRC} into ${STATE_DIR}"
  cp -a "${DATA_SRC}/." "${STATE_DIR}/"
  chown -R "${SVC_USER}:${SVC_USER}" "${STATE_DIR}"
  chmod -R go-rwx "${STATE_DIR}"
elif [[ -n "${IDENTITY_SRC}" && ! -f "${IDENTITY}" ]]; then
  echo "==> Installing identity from ${IDENTITY_SRC}"
  install -o "${SVC_USER}" -g "${SVC_USER}" -m 0600 "${IDENTITY_SRC}" "${IDENTITY}"
fi

BRIDGE_LINES=""
if [[ -n "${CRED_SRC}" ]]; then
  echo "==> Bridge credential -> ${CRED_DEST}"
  install -o root -g "${SVC_USER}" -m 0640 "${CRED_SRC}" "${CRED_DEST}"
  BRIDGE_LINES+="       DMCND_BRIDGE_CREDENTIAL=${CRED_DEST}"$'\n'
fi
if [[ -n "${DKIM_SRC}" ]]; then
  echo "==> DKIM key -> ${DKIM_DEST}"
  install -o root -g "${SVC_USER}" -m 0640 "${DKIM_SRC}" "${DKIM_DEST}"
  BRIDGE_LINES+="       DMCND_BRIDGE_DKIM_KEY=${DKIM_DEST}"$'\n'
fi
if [[ -n "${AUDIT_SRC}" ]]; then
  echo "==> Bridge audit log -> ${AUDIT_DEST}"
  install -o "${SVC_USER}" -g "${SVC_USER}" -m 0600 "${AUDIT_SRC}" "${AUDIT_DEST}"
  BRIDGE_LINES+="       DMCND_BRIDGE_AUDIT_LOG=${AUDIT_DEST}"$'\n'
fi

# Creates node.key when there is none yet, so the peer ID exists before the domain is set up.
PEER_ID="$(runuser -u "${SVC_USER}" -- env DMCND_DATA_DIR="${STATE_DIR}" "${INSTALL_BIN}" peer-id)"
chmod 0600 "${IDENTITY}"

echo "==> Unit ${UNIT_FILE}"
install -m 0644 "${SCRIPT_DIR}/dmcnd.service" "${UNIT_FILE}"

if [[ -f "${ENV_FILE}" ]]; then
  echo "==> ${ENV_FILE} exists, left untouched"
else
  echo "==> Writing settings template ${ENV_FILE}"
  install -o root -g "${SVC_USER}" -m 0640 "${SCRIPT_DIR}/dmcnd.env" "${ENV_FILE}"
fi
systemctl daemon-reload

if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
  echo "==> Opening 443/tcp (webmail) and 7400/tcp (libp2p)"
  ufw allow 443/tcp >/dev/null
  ufw allow 7400/tcp >/dev/null
  # On a first install dmcnd.env is still the template, with the bridge commented out, so the
  # settings alone cannot say whether a bridge is coming. Being handed its files does. The values
  # are the ones the daemon reads as true, and nothing else.
  if [[ -n "${CRED_SRC}${DKIM_SRC}${AUDIT_SRC}" ]] \
     || grep -Eq '^DMCND_BRIDGE_ENABLED=(1|true)$' "${ENV_FILE}"; then
    echo "==> Opening 25/tcp (SMTP bridge)"
    ufw allow 25/tcp >/dev/null
  else
    echo "    25/tcp left closed (no bridge yet). With one: sudo ufw allow 25/tcp"
  fi
else
  echo "==> ufw not active: make sure 443/tcp, 7400/tcp (and 25/tcp with the bridge) are reachable"
fi

cat <<EOF

dmcnd is installed.

  Peer ID:  ${PEER_ID}
  Settings: ${ENV_FILE}
  Data:     ${STATE_DIR}

EOF
if [[ -n "${BRIDGE_LINES}" ]]; then
  printf 'Bridge files are in place. dmcnd.env must name them exactly so:\n\n%s\n' "${BRIDGE_LINES}"
fi
if systemctl is-active --quiet dmcnd; then
  cat <<EOF
The service is running the binary it started with. To run this one:

  sudo systemctl restart dmcnd && journalctl -u dmcnd -f
EOF
else
  cat <<EOF
Next:
  1. Edit ${ENV_FILE}. Settings from a shell profile move over without the \`export \`.
     Any path under /home is unreadable to the service: move those files and point at the copies
     (the --bridge-credential, --dkim-key and --audit-log flags do it for the bridge's).
  2. If dmcnd is still running by hand (tmux, nohup), stop it: two daemons cannot share the ports.
  3. sudo systemctl enable --now dmcnd && journalctl -u dmcnd -f
     A new domain then waits for its authority record: on your admin machine,
       dmcndcli domain publish --domain <domain> --peers /ip4/<public-ip>/tcp/7400/p2p/${PEER_ID}
EOF
fi
