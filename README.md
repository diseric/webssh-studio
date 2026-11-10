# WebSSH Studio

**WebSSH Studio** is a self-hosted, single-container browser SSH2 terminal, auto-syncing SFTP file manager, remote code editor, live server telemetry HUD, and parameterized playbook runner built for homelabs, DevOps engineers, and system administrators.

Think **MobaXterm + Termius in a single Docker container**—accessible from any browser with zero agents required on your target servers.

---

## ✨ Key Features

- 🖥️ **Multi-Tab Interactive SSH2 Terminal (`xterm.js`)**
  - Password and OpenSSH/PEM Private Key authentication
  - **Broadcast Mode**: Type once to execute commands across all open SSH tabs simultaneously
  - **Side-by-Side Split View**: View and interact with two SSH sessions side-by-side
  - **Terminal Search & Log Export**: Search terminal scrollback and download session transcripts (`.log`)
- 📁 **Drag-and-Drop SFTP File Transfer & Auto-Syncing Browser**
  - Drag and drop files or entire folder trees from your desktop directly into the remote server
  - **Auto-Sync on `cd` (OSC-7)**: Navigating directories in the SSH terminal automatically updates the SFTP file browser and drop target path
  - One-click **Download Folder as `.zip`** archive
- ✏️ **In-Browser Remote File Editor & Live Log Tailing**
  - Click any remote configuration or code file to edit and save directly over SFTP (`Ctrl+S`)
  - **Auto-Tail Live Log (`2s`)** mode for streaming remote `.log` files in real time, plus inline image preview
- ⚡ **Parameterized Command Playbooks (`{{var:default}}`)**
  - Comes pre-loaded with **15 sysadmin & DevOps playbooks** across *Diagnostics*, *Storage*, *Networking*, *Security*, and *Containers & Git*
  - Supports dynamic template placeholders like `{{limit:11}}` or `{{target_host:1.1.1.1}}` that prompt for values with live command preview before execution
- 📊 **Live Server Telemetry HUD & Process Inspector**
  - Agentless real-time **CPU %**, **RAM %**, **Disk %**, **Uptime**, and **Top Processes** table polled over the active SSH connection
- 🔐 **Encrypted Connection Vault, `~/.ssh/config` Importer, `ProxyJump` & Port Tunnels**
  - Saves host profiles and credentials encrypted at rest (`Fernet` AES-128-CBC + HMAC) in `/data`
  - Import hosts directly from `~/.ssh/config` (including `ProxyJump` bastion chains)
  - Create local SSH port-forwarding tunnels (`-L`) from the UI
- 🔒 **App-Level Master Password Lock & Reverse-Proxy SSO**
  - Protect the web UI with a PBKDF2-SHA256 Master Password (`WEBSSH_APP_PASSWORD` or configured in the UI)
  - Optional Reverse-Proxy header pass-through (`Remote-User`, `X-Authentik-Username`, `Cf-Access-Authenticated-User-Email`) for Authentik, Authelia, and Cloudflare Zero Trust
- 🎨 **3 Selectable Workspace Designs & Layouts**
  - **1. Obsidian**: Classic dark slate DevOps split (Terminal Left, Sidebar Right)
  - **2. Cyber Deck**: Phosphor CRT Matrix theme with Full-Width Top Terminal + Horizontal Bottom Command Deck
  - **3. Nordic Glass**: Daylight frosted glass floating islands (Sidebar Left, Terminal Right)

---

## 🚀 Quick Start (Docker Compose)

```yaml
services:
  webssh-studio:
    image: diseric/webssh-studio:latest
    container_name: webssh-studio
    restart: unless-stopped
    ports:
      - "8090:8090"
    environment:
      - WEBSSH_DATA_DIR=/data
      - WEBSSH_APP_PASSWORD=change-me-optional
      - WEBSSH_TRUST_PROXY_HEADERS=false
    volumes:
      - ./data:/data
```

Run:

```bash
docker compose up -d
```

Then open **http://localhost:8090** in your browser.

---

## 🛠️ Local Development (Python 3.11+)

```bash
pip install -r requirements.txt
python server.py
```

---

## ⚙️ Environment Variables

| Variable | Default | Description |
| :--- | :--- | :--- |
| `WEBSSH_HOST` | `127.0.0.1` (`0.0.0.0` in Docker) | Bind address for the FastAPI/Uvicorn web server |
| `WEBSSH_PORT` | `8090` | HTTP/WebSocket port for the WebSSH Studio UI |
| `WEBSSH_DATA_DIR` | `./data` (`/data` in Docker) | Persistent storage directory for `vault.key`, `profiles.json`, `playbooks.json`, and `auth_config.json` |
| `WEBSSH_APP_PASSWORD` | *(unset)* | Optional initial Master Password to lock the web UI on startup |
| `WEBSSH_TRUST_PROXY_HEADERS` | `false` | Set to `true` when behind Authentik, Authelia, or Cloudflare Zero Trust |
