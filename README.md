# sing-box 5-in-1 — one-click VPN node

One script that turns a fresh Ubuntu 22.04+ server into a five-protocol proxy
node, with server hardening included. Built after a previous node was
compromised through a third-party one-click script, so the design goal here is
**no mystery binaries**: sing-box comes only from the official SagerNet
release, and its SHA-256 is verified against GitHub's own release API before
install. Everything else (keys, passwords, certificates) is generated locally
on your server.

## Protocols (all five run at once)

| Protocol | Port | Notes |
|---|---|---|
| VLESS + Reality + Vision | 443/tcp | Main. Looks like TLS 1.3 to a real site, no domain or cert needed |
| Hysteria2 (+ Salamander obfs) | 8443/udp | Fastest at peak hours / on lossy networks |
| TUIC v5 | 8444/udp | QUIC-based, BBR congestion control |
| VMess + WS + TLS | 8445/tcp | Self-signed cert; use your own domain + ACME cert for best results |
| AnyTLS | 8446/tcp | Self-signed cert |

All five are supported by Clash Verge (Mihomo core). The installer writes a
ready-to-import `clash.yaml` plus one share link per protocol.

## Install (one command, as root)

```bash
sudo bash install.sh [--domain example.com] [--reality-target www.microsoft.com]
```

- `--domain`: your own domain. It becomes the SNI for the TLS protocols.
  Without it, the server IP is used with a self-signed certificate and the
  clients skip certificate verification.
- `--reality-target`: the real website Reality imitates (default
  `www.microsoft.com`).

What the script does, in order:

1. **Hardening** — SSH key-only login, but only if a public key is already
   installed (it checks first so it can never lock you out); `fail2ban` for
   SSH; UFW default-deny with only SSH + the five node ports open; automatic
   security updates; BBR.
2. **Disk saving** — systemd journal capped at 100 MB (7 days max), logrotate
   for node logs (3 days, compressed), and a weekly cleanup timer (apt cache
   + old journals). The node itself needs under 5 GB; the 47 GB minimum boot
   volume is plenty.
2. **Official sing-box** — latest release from `SagerNet/sing-box`, SHA-256
   verified against the GitHub release API, installed to
   `/usr/local/bin/sing-box`.
3. **Keys & config** — UUIDs, passwords, Reality keypair and a self-signed
   cert are generated locally; config goes to `/etc/s-box/config.json` and
   runs as a systemd service.
4. **Client files** — `/etc/s-box/clash.yaml` (import into Clash Verge),
   `/etc/s-box/links.txt` (five share links), `/etc/s-box/credentials.txt`
   (all secrets, mode 600 — keep private).

## Don't forget the cloud firewall

The script opens the ports in the OS firewall (UFW), but your cloud provider
has a second firewall. In Oracle Cloud, open these in the VCN security list:

```
443/tcp, 8443/udp, 8444/udp, 8445/tcp, 8446/tcp
```

## Uninstall

```bash
sudo bash uninstall.sh
```

Removes sing-box, the service, config and keys. SSH hardening, fail2ban and
UFW rules are deliberately left in place.

## Security notes

- Never reuse credentials from a previously compromised server. Fresh
  install, fresh keys.
- If a server is ever confirmed compromised, rebuild it — killing a miner
  process is not enough, backdoors persist.
- Re-running `install.sh` regenerates all keys and passwords; update your
  clients afterwards.
- Keep `/etc/s-box/credentials.txt` private. Anyone with those values can
  use (and abuse) your node.
