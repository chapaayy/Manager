# XPPN Manager 1.6.0 Alpha

Single installer and `.env` for the central Manager. Read [README_RU.md](README_RU.md) for instructions and migration safety.

```bash
curl -fsSL https://raw.githubusercontent.com/chapaayy/Manager/main/install.sh -o /tmp/xppn-install.sh && sudo bash /tmp/xppn-install.sh
```

The installer preserves existing secrets and SQLite volumes, sets up Docker/Caddy/login and enables the web updater. It does not deploy or restart any VPN node.
