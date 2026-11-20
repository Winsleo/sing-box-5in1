#!/usr/bin/env bash
# sing-box 5-in-1 one-click deploy: VLESS-Reality + Hysteria2 + TUICv5 + VMess-WS-TLS + AnyTLS
#
# One command (from the repo):
#   sudo bash install.sh [--domain example.com] [--reality-target www.microsoft.com]
#
# What it does:
#   1. Hardens the server: SSH key-only login (only if a key is already installed),
#      fail2ban, UFW default-deny with only the node ports open, automatic security
#      updates, BBR congestion control.
#   2. Downloads sing-box ONLY from the official SagerNet GitHub release, and
#      verifies the SHA-256 digest published by the GitHub API before installing.
#      No third-party binaries, no mystery scripts.
#   3. Generates all keys/passwords/UUIDs locally, writes /etc/s-box/config.json,
#      installs a systemd service, and prints a ready-to-use Clash (Mihomo) config
#      plus per-protocol share links.
#
# Target: Ubuntu 22.04+ / Debian 12+ (x86_64 or aarch64), run as root.
# After install you must ALSO open these ports in your cloud security list
# (e.g. Oracle VCN security list), because the OS firewall alone is not enough:
#   443/tcp (VLESS-Reality), 8443/udp (Hysteria2), 8444/udp (TUIC),
#   8445/tcp (VMess-WS-TLS), 8446/tcp (AnyTLS)
#
set -euo pipefail

SBOX_DIR="/etc/s-box"
BIN="/usr/local/bin/sing-box"
FALLBACK_VERSION="v1.14.3"   # used only if the GitHub API cannot be reached
REALITY_TARGET="www.microsoft.com"
DOMAIN=""                    # optional: your own domain, used as SNI for the TLS protocols

while [[ $# -gt 0 ]]; do
  case "$1" in
    --domain) DOMAIN="$2"; shift 2 ;;
    --reality-target) REALITY_TARGET="$2"; shift 2 ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

need_root() {
  if [[ "$(id -u)" -ne 0 ]]; then echo "Please run as root (sudo)." >&2; exit 1; fi
}

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64)  SB_ARCH="amd64" ;;
  aarch64) SB_ARCH="arm64" ;;
  *) echo "Unsupported architecture: $ARCH" >&2; exit 1 ;;
esac

echo "==> Detecting public IP..."
PUBLIC_IP="$(curl -fsSL --max-time 15 https://api.ipify.org || true)"
if [[ -z "$PUBLIC_IP" ]]; then echo "Cannot detect public IP. Check network." >&2; exit 1; fi
SNI="${DOMAIN:-$PUBLIC_IP}"
echo "    Public IP: $PUBLIC_IP | SNI: $SNI"

# ---------------------------------------------------------------- hardening ---
echo "==> Hardening SSH (key-only, only if a key is already installed)..."
SSH_PORT="$(grep -E '^[[:space:]]*Port[[:space:]]+' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | head -n1 || true)"
SSH_PORT="${SSH_PORT:-22}"
KEY_PRESENT=0
for u in root ubuntu; do
  if [[ -s "/home/$u/.ssh/authorized_keys" || ( "$u" = "root" && -s /root/.ssh/authorized_keys ) ]]; then KEY_PRESENT=1; fi
done
if [[ "$KEY_PRESENT" -eq 1 ]]; then
  cp -n /etc/ssh/sshd_config /etc/ssh/sshd_config.bak 2>/dev/null || true
  sed -i -E 's/^[[:space:]]*#?[[:space:]]*PasswordAuthentication[[:space:]]+.*/PasswordAuthentication no/' /etc/ssh/sshd_config
  grep -q '^PasswordAuthentication' /etc/ssh/sshd_config || echo 'PasswordAuthentication no' >> /etc/ssh/sshd_config
  sed -i -E 's/^[[:space:]]*#?[[:space:]]*PermitRootLogin[[:space:]]+.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
  grep -q '^PermitRootLogin' /etc/ssh/sshd_config || echo 'PermitRootLogin prohibit-password' >> /etc/ssh/sshd_config
  sed -i -E 's/^[[:space:]]*#?[[:space:]]*PubkeyAuthentication[[:space:]]+.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config
  grep -q '^PubkeyAuthentication' /etc/ssh/sshd_config || echo 'PubkeyAuthentication yes' >> /etc/ssh/sshd_config
  sed -i -E 's/^[[:space:]]*#?[[:space:]]*MaxAuthTries[[:space:]]+.*/MaxAuthTries 3/' /etc/ssh/sshd_config
  grep -q '^MaxAuthTries' /etc/ssh/sshd_config || echo 'MaxAuthTries 3' >> /etc/ssh/sshd_config
  sshd -t && systemctl restart sshd
  echo "    SSH is now key-only (password login disabled)."
else
  echo "    WARNING: no SSH public key found for root/ubuntu, skipping the"
  echo "    password-login change so you do not lock yourself out. Install a"
  echo "    key first, then re-run this script to apply SSH hardening."
fi

echo "==> Installing dependencies and enabling firewall / fail2ban / auto-updates..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq curl openssl jq tar ca-certificates ufw fail2ban unattended-upgrades > /dev/null
systemctl enable --now fail2ban
# BBR (helps TUIC / Hysteria2 on lossy links)
if ! sysctl net.ipv4.tcp_congestion_control 2>/dev/null | grep -q bbr; then
  { echo 'net.core.default_qdisc=fq'; echo 'net.ipv4.tcp_congestion_control=bbr'; } > /etc/sysctl.d/99-sbox-bbr.conf
  sysctl -p /etc/sysctl.d/99-sbox-bbr.conf 2>/dev/null || true
fi
ufw allow "${SSH_PORT}/tcp" > /dev/null
ufw allow 443/tcp > /dev/null
ufw allow 8443/udp > /dev/null
ufw allow 8444/udp > /dev/null
ufw allow 8445/tcp > /dev/null
ufw allow 8446/tcp > /dev/null
ufw --force enable > /dev/null
echo "    UFW default-deny on. Open ports: ${SSH_PORT}/tcp, 443/tcp, 8443/udp, 8444/udp, 8445/tcp, 8446/tcp."

echo "==> Saving disk: capping logs and enabling regular cleanup..."
mkdir -p /etc/systemd/journald.conf.d
cat > /etc/systemd/journald.conf.d/99-sbox.conf <<'EOF'
[Journal]
SystemMaxUse=100M
RuntimeMaxUse=50M
MaxFileSec=7day
EOF
systemctl restart systemd-journald 2>/dev/null || true
# Rotate any file logs the node writes under /etc/s-box (3 days kept, compressed).
cat > /etc/logrotate.d/sing-box <<'EOF'
/etc/s-box/*.log {
    daily
    rotate 3
    compress
    missingok
    notifempty
    copytruncate
}
EOF
# Weekly cleanup: apt cache + journals older than 7 days / over 100 MB.
cat > /usr/local/bin/sbox-cleanup <<'EOF'
#!/usr/bin/env bash
apt-get autoclean -qq >/dev/null 2>&1 || true
journalctl --vacuum-size=100M >/dev/null 2>&1 || true
journalctl --vacuum-time=7d >/dev/null 2>&1 || true
EOF
chmod +x /usr/local/bin/sbox-cleanup
cat > /etc/systemd/system/sbox-cleanup.service <<'EOF'
[Unit]
Description=Weekly disk cleanup for sing-box node
[Service]
Type=oneshot
ExecStart=/usr/local/bin/sbox-cleanup
EOF
cat > /etc/systemd/system/sbox-cleanup.timer <<'EOF'
[Unit]
Description=Run disk cleanup weekly
[Timer]
OnCalendar=weekly
Persistent=true
[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
systemctl enable --now sbox-cleanup.timer
echo "    Logs capped at 100 MB, weekly cleanup enabled."

# ------------------------------------------------- official sing-box binary ---
echo "==> Downloading official sing-box (SagerNet release, SHA-256 verified)..."
TAG="$(curl -fsSL --max-time 20 https://api.github.com/repos/SagerNet/sing-box/releases/latest 2>/dev/null | jq -r .tag_name 2>/dev/null || true)"
if [[ -z "$TAG" || "$TAG" = "null" ]]; then TAG="$FALLBACK_VERSION"; echo "    GitHub API unreachable, falling back to $TAG."; fi
VERSION="${TAG#v}"
FILE="sing-box-${VERSION}-linux-${SB_ARCH}.tar.gz"
URL="https://github.com/SagerNet/sing-box/releases/download/${TAG}/${FILE}"
cd /tmp
curl -fsSL --max-time 120 -o "$FILE" "$URL"
EXPECTED="$(curl -fsSL --max-time 20 "https://api.github.com/repos/SagerNet/sing-box/releases/tags/${TAG}" 2>/dev/null | jq -r --arg n "$FILE" '.assets[] | select(.name == $n) | .digest // empty' 2>/dev/null || true)"
if [[ -n "$EXPECTED" ]]; then
  ACTUAL="sha256:$(sha256sum "$FILE" | awk '{print $1}')"
  if [[ "$ACTUAL" != "$EXPECTED" ]]; then echo "SHA-256 mismatch for $FILE, aborting." >&2; exit 1; fi
  echo "    SHA-256 verified against the GitHub release API."
else
  echo "    WARNING: could not fetch the published digest; proceeding after"
  echo "    'sing-box version' check below. Re-run later to verify."
fi
tar -xzf "$FILE"
install -m 0755 "sing-box-${VERSION}-linux-${SB_ARCH}/sing-box" "$BIN"
"$BIN" version
rm -rf "$FILE" "sing-box-${VERSION}-linux-${SB_ARCH}"

# ------------------------------------------------------ keys and certificates ---
echo "==> Generating keys, UUIDs and passwords (locally)..."
mkdir -p "$SBOX_DIR"
chmod 700 "$SBOX_DIR"

VLESS_UUID="$("$BIN" generate uuid)"
TUIC_UUID="$("$BIN" generate uuid)"
VMESS_UUID="$("$BIN" generate uuid)"
HY2_PASS="$(openssl rand -base64 18 | tr -d '/+=' | head -c 20)"
OBFS_PASS="$(openssl rand -base64 18 | tr -d '/+=' | head -c 20)"
TUIC_PASS="$(openssl rand -base64 18 | tr -d '/+=' | head -c 20)"
ANYTLS_PASS="$(openssl rand -base64 18 | tr -d '/+=' | head -c 20)"
REALITY_KEYS="$("$BIN" generate reality-keypair)"
REALITY_PRIV="$(echo "$REALITY_KEYS" | awk '/PrivateKey/{print $2}')"
REALITY_PUB="$(echo "$REALITY_KEYS" | awk '/PublicKey/{print $2}')"
SHORT_ID="$(openssl rand -hex 4)"

# Self-signed cert for the TLS-based protocols (Hysteria2 / TUIC / VMess / AnyTLS).
# Clients use skip-cert-verify. For production use, replace with a real ACME cert
# and set --domain to your own domain.
if [[ -n "$DOMAIN" ]]; then SAN="DNS:${DOMAIN},IP:${PUBLIC_IP}"; else SAN="IP:${PUBLIC_IP}"; fi
openssl req -x509 -newkey rsa:2048 -keyout "$SBOX_DIR/key.pem" -out "$SBOX_DIR/cert.pem" \
  -days 3650 -nodes -subj "/CN=${SNI}" -addext "subjectAltName=${SAN}" 2>/dev/null
chmod 600 "$SBOX_DIR/key.pem"

# ------------------------------------------------------------------- config ---
echo "==> Writing sing-box config..."
jq -n \
  --arg vless_uuid "$VLESS_UUID" \
  --arg tuic_uuid "$TUIC_UUID" \
  --arg vmess_uuid "$VMESS_UUID" \
  --arg hy2_pass "$HY2_PASS" \
  --arg obfs_pass "$OBFS_PASS" \
  --arg tuic_pass "$TUIC_PASS" \
  --arg anytls_pass "$ANYTLS_PASS" \
  --arg reality_priv "$REALITY_PRIV" \
  --arg short_id "$SHORT_ID" \
  --arg target "$REALITY_TARGET" \
  --arg sni "$SNI" \
  --arg cert "$SBOX_DIR/cert.pem" \
  --arg key "$SBOX_DIR/key.pem" \
  '{
    log: {level: "info", timestamp: true},
    inbounds: [
      {type: "vless", tag: "vless-reality", listen: "::", listen_port: 443,
       users: [{uuid: $vless_uuid, flow: "xtls-rdrp-vision"}],
       tls: {enabled: true, server_name: $target,
             reality: {enabled: true,
                       handshake: {server: $target, server_port: 443},
                       private_key: $reality_priv, short_id: [$short_id]}}},
      {type: "hysteria2", tag: "hysteria2", listen: "::", listen_port: 8443,
       users: [{password: $hy2_pass}],
       obfs: {type: "salamander", password: $obfs_pass},
       tls: {enabled: true, alpn: ["h3"], certificate_path: $cert, key_path: $key}},
      {type: "tuic", tag: "tuic", listen: "::", listen_port: 8444,
       users: [{uuid: $tuic_uuid, password: $tuic_pass}],
       congestion_control: "bbr",
       tls: {enabled: true, alpn: ["h3"], certificate_path: $cert, key_path: $key}},
      {type: "vmess", tag: "vmess-ws-tls", listen: "::", listen_port: 8445,
       users: [{uuid: $vmess_uuid, alterId: 0}],
       transport: {type: "ws", path: "/vmess", headers: {Host: $sni}},
       tls: {enabled: true, server_name: $sni, certificate_path: $cert, key_path: $key}},
      {type: "anytls", tag: "anytls", listen: "::", listen_port: 8446,
       users: [{name: "user", password: $anytls_pass}],
       tls: {enabled: true, certificate_path: $cert, key_path: $key}}
    ],
    outbounds: [{type: "direct", tag: "direct"}, {type: "block", tag: "block"}]
  }' > "$SBOX_DIR/config.json"
chmod 600 "$SBOX_DIR/config.json"

cat > /etc/systemd/system/sing-box.service <<EOF
[Unit]
Description=sing-box service
Documentation=https://sing-box.sagernet.org/
After=network.target nss-lookup.target

[Service]
User=root
WorkingDirectory=$SBOX_DIR
ExecStart=$BIN run -c $SBOX_DIR/config.json
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

"$BIN" check -c "$SBOX_DIR/config.json"
systemctl daemon-reload
systemctl enable --now sing-box
sleep 2
systemctl is-active --quiet sing-box || { echo "sing-box failed to start, see: journalctl -u sing-box -n 50" >&2; exit 1; }
echo "    sing-box is running."
ss -tlnp | grep -E ':(443|8443|8444|8445|8446)\b' || true

# ------------------------------------------------------- Clash config + links ---
VMESS_JSON="$(jq -nc \
  --arg add "$PUBLIC_IP" --arg id "$VMESS_UUID" --arg sni "$SNI" \
  '{v:"2", ps:"Oracle-VMess-WS-TLS", add:$add, port:"8445", id:$id, aid:"0",
    scy:"auto", net:"ws", type:"none", host:$sni, path:"/vmess",
    tls:"tls", sni:$sni, "skip-cert-verify":true}')"
VMESS_B64="$(echo -n "$VMESS_JSON" | base64 -w0 | tr '+/' '-_' | tr -d '=')"

cat > "$SBOX_DIR/clash.yaml" <<EOF
# Clash Verge / Mihomo config for this node. Import it, or copy the proxies
# section into your existing config. Self-signed certs: skip-cert-verify is on.
proxies:
  - name: "Oracle-VLESS-Reality"
    type: vless
    server: $PUBLIC_IP
    port: 443
    uuid: $VLESS_UUID
    network: tcp
    tls: true
    servername: $REALITY_TARGET
    reality-opts:
      public-key: $REALITY_PUB
      short-id: $SHORT_ID
    flow: xtls-rdrp-vision
    packet-encoding: xudp
    udp: true
  - name: "Oracle-Hysteria2"
    type: hysteria2
    server: $PUBLIC_IP
    port: 8443
    password: $HY2_PASS
    sni: $SNI
    skip-cert-verify: true
    alpn: [h3]
    obfs: salamander
    obfs-password: $OBFS_PASS
    udp: true
  - name: "Oracle-TUIC"
    type: tuic
    server: $PUBLIC_IP
    port: 8444
    uuid: $TUIC_UUID
    password: $TUIC_PASS
    sni: $SNI
    alpn: [h3]
    skip-cert-verify: true
    congestion-controller: bbr
    udp-relay-mode: native
    udp: true
  - name: "Oracle-VMess-WS-TLS"
    type: vmess
    server: $PUBLIC_IP
    port: 8445
    uuid: $VMESS_UUID
    alterId: 0
    cipher: auto
    network: ws
    ws-opts:
      path: /vmess
      headers: {Host: $SNI}
    tls: true
    servername: $SNI
    skip-cert-verify: true
    udp: true
  - name: "Oracle-AnyTLS"
    type: anytls
    server: $PUBLIC_IP
    port: 8446
    password: $ANYTLS_PASS
    sni: $SNI
    skip-cert-verify: true
    alpn: [h2, http/1.1]
    udp: true
EOF

cat > "$SBOX_DIR/links.txt" <<EOF
vless://${VLESS_UUID}@${PUBLIC_IP}:443?encryption=none&flow=xtls-rdrp-vision&security=reality&sni=${REALITY_TARGET}&fp=chrome&pbk=${REALITY_PUB}&sid=${SHORT_ID}&type=tcp#Oracle-VLESS-Reality
hysteria2://${HY2_PASS}@${PUBLIC_IP}:8443/?sni=${SNI}&insecure=1&obfs=salamander&obfs-password=${OBFS_PASS}&alpn=h3#Oracle-Hysteria2
tuic://${TUIC_UUID}:${TUIC_PASS}@${PUBLIC_IP}:8444?congestion_control=bbr&udp_relay_mode=native&alpn=h3&allow_insecure=1&sni=${SNI}#Oracle-TUIC
vmess://${VMESS_B64}
anytls://${ANYTLS_PASS}@${PUBLIC_IP}:8446?insecure=1&sni=${SNI}#Oracle-AnyTLS
EOF
chmod 600 "$SBOX_DIR/clash.yaml" "$SBOX_DIR/links.txt"

cat > "$SBOX_DIR/credentials.txt" <<EOF
# KEEP PRIVATE. Anyone with these values can use your node.
# Server: $PUBLIC_IP
VLESS UUID:        $VLESS_UUID
VLESS Reality public key: $REALITY_PUB
VLESS Reality short-id:  $SHORT_ID
VLESS Reality target:    $REALITY_TARGET
Hysteria2 password:      $HY2_PASS
Hysteria2 obfs password: $OBFS_PASS
TUIC UUID:               $TUIC_UUID
TUIC password:           $TUIC_PASS
VMess UUID:              $VMESS_UUID
AnyTLS password:         $ANYTLS_PASS
EOF
chmod 600 "$SBOX_DIR/credentials.txt"

echo
echo "=========================== DONE ==========================="
echo "Node is up on $PUBLIC_IP"
echo "  VLESS+Reality  TCP 443   (main, most stealthy)"
echo "  Hysteria2      UDP 8443  (fastest at peak hours)"
echo "  TUIC v5        UDP 8444"
echo "  VMess-WS-TLS   TCP 8445  (self-signed cert)"
echo "  AnyTLS         TCP 8446  (self-signed cert)"
echo
echo "Files on the server:"
echo "  $SBOX_DIR/config.json      sing-box config"
echo "  $SBOX_DIR/clash.yaml      Clash Verge config (import this)"
echo "  $SBOX_DIR/links.txt       share links for the 5 protocols"
echo "  $SBOX_DIR/credentials.txt all keys/passwords - KEEP PRIVATE"
echo
echo "REMINDER: also open these ports in your cloud security list"
echo "(Oracle VCN security list / security group):"
echo "  443/tcp, 8443/udp, 8444/udp, 8445/tcp, 8446/tcp"
echo "Without that, the OS firewall is open but the cloud still blocks them."
echo "============================================================"
