import asyncio
import base64
import hashlib
import hmac
import io
import json
import mimetypes
import os
import posixpath
import secrets
import shutil
import stat
import subprocess
import time
import uuid
import zipfile
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional

import asyncssh
import paramiko
import psutil
from cryptography.fernet import Fernet
from fastapi import FastAPI, File, Form, HTTPException, Query, Request, Response, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
DATA_DIR = Path(os.environ.get("WEBSSH_DATA_DIR", str(BASE_DIR / "data"))).resolve()

STATIC_DIR.mkdir(parents=True, exist_ok=True)
DATA_DIR.mkdir(parents=True, exist_ok=True)

# Migrate legacy root files into DATA_DIR seamlessly if they exist
for legacy_name in ("vault.key", "profiles.json", "playbooks.json", "sandbox_host_key"):
    legacy_file = BASE_DIR / legacy_name
    target_file = DATA_DIR / legacy_name
    if legacy_file.exists() and not target_file.exists():
        shutil.copy2(legacy_file, target_file)

SANDBOX_ROOT = DATA_DIR / "sandbox_remote_root"
if (BASE_DIR / "sandbox_remote_root").exists() and not SANDBOX_ROOT.exists():
    shutil.copytree(BASE_DIR / "sandbox_remote_root", SANDBOX_ROOT)
SANDBOX_ROOT.mkdir(parents=True, exist_ok=True)

HOST_KEY_PATH = DATA_DIR / "sandbox_host_key"
VAULT_KEY_PATH = DATA_DIR / "vault.key"
PROFILES_PATH = DATA_DIR / "profiles.json"
PLAYBOOKS_PATH = DATA_DIR / "playbooks.json"
AUTH_CONFIG_PATH = DATA_DIR / "auth_config.json"

# Seed sample files in sandbox_remote_root for immediate testing of Editor, Log Tail, and SFTP
welcome_file = SANDBOX_ROOT / "welcome.txt"
if not welcome_file.exists():
    welcome_file.write_text(
        "Welcome to the WebSSH Studio Sandbox Server!\n"
        "You can drag and drop files into the transfer zone in your browser,\n"
        "edit remote files in the built-in code editor, monitor live telemetry,\n"
        "or configure SSH port forwarding tunnels.\n",
        encoding="utf-8",
    )

sample_cfg = SANDBOX_ROOT / "app_config.json"
if not sample_cfg.exists():
    sample_cfg.write_text(
        json.dumps(
            {
                "service": "webssh-edge-proxy",
                "environment": "production",
                "listen_port": 8080,
                "workers": 4,
                "tls_enabled": True,
                "allowed_Subnets": ["10.0.0.0/8", "192.168.1.0/24"],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

sample_log = SANDBOX_ROOT / "server.log"
if not sample_log.exists():
    sample_log.write_text(
        "[2026-11-10 11:00:01] INFO  Starting sshd-sandbox listener on 127.0.0.1:2222\n"
        "[2026-11-10 11:05:14] INFO  SFTP subsystem initialized (chroot=/sandbox_remote_root)\n"
        "[2026-11-10 11:12:40] INFO  Health check passed: CPU OK, Memory OK, Disk OK\n"
        "[2026-11-10 11:20:00] WARN  High connection rate detected from 10.24.0.12\n"
        "[2026-11-10 11:28:19] INFO  Worker pool scaled to 4 instances\n",
        encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# Encrypted Vault & Playbook Persistence
# ---------------------------------------------------------------------------
def _get_fernet() -> Fernet:
    if not VAULT_KEY_PATH.exists():
        VAULT_KEY_PATH.write_bytes(Fernet.generate_key())
    return Fernet(VAULT_KEY_PATH.read_bytes())


def _encrypt_secret(val: Optional[str]) -> str:
    if not val:
        return ""
    return _get_fernet().encrypt(val.encode("utf-8")).decode("utf-8")


def _decrypt_secret(token: Optional[str]) -> str:
    if not token:
        return ""
    try:
        return _get_fernet().decrypt(token.encode("utf-8")).decode("utf-8")
    except Exception:
        return ""


def load_profiles() -> List[dict]:
    if not PROFILES_PATH.exists():
        default_profiles = [
            {
                "id": "sandbox-local",
                "name": "Local SSH Sandbox",
                "tag": "Sandbox",
                "host": "127.0.0.1",
                "port": 2222,
                "username": "demo",
                "auth_type": "password",
                "encrypted_password": _encrypt_secret("demo"),
                "encrypted_key": "",
                "encrypted_passphrase": "",
                "use_jump_host": False,
                "jump_host": "",
                "jump_port": 22,
                "jump_username": "",
            }
        ]
        PROFILES_PATH.write_text(json.dumps(default_profiles, indent=2), encoding="utf-8")
    try:
        return json.loads(PROFILES_PATH.read_text(encoding="utf-8"))
    except Exception:
        return []


def save_profiles(profiles: List[dict]):
    PROFILES_PATH.write_text(json.dumps(profiles, indent=2), encoding="utf-8")


DEFAULT_PLAYBOOKS = [
    # 1. Diagnostics
    {
        "id": "pb-health-snapshot",
        "name": "Full System Health Snapshot",
        "category": "Diagnostics",
        "description": "Kernel version, uptime/load average, memory usage, and disk space summary.",
        "command": "uname -a && uptime && free -h && df -h",
    },
    {
        "id": "pb-top-offenders",
        "name": "Top CPU & Memory Offenders",
        "category": "Diagnostics",
        "description": "Lists the top {{limit:11}} CPU-consuming processes currently running.",
        "command": "ps aux --sort=-%cpu | head -n {{limit:11}}",
    },
    {
        "id": "pb-recent-errors",
        "name": "Recent System & Service Errors",
        "category": "Diagnostics",
        "description": "Pulls the last {{lines:20}} error/warning entries from system logs.",
        "command": "journalctl -p err -n {{lines:20}} --no-pager",
    },
    # 2. Storage
    {
        "id": "pb-disk-hogs",
        "name": "Find Largest Files & Folders",
        "category": "Storage",
        "description": "Scans {{target_path:*}} for disk usage by file and folder.",
        "command": "du -sh {{target_path:*}} && df -h",
    },
    {
        "id": "pb-clean-temp",
        "name": "Inspect File Metadata",
        "category": "Storage",
        "description": "Lists workspace files and inspects metadata for {{target_file:welcome.txt}}.",
        "command": "pwd && ls -la && stat {{target_file:welcome.txt}}",
    },
    {
        "id": "pb-backup-snapshot",
        "name": "Quick Timestamped Backup Archive",
        "category": "Storage",
        "description": "Creates a backups directory and archives files into {{archive_name:config_snapshot.tar.gz}}.",
        "command": "mkdir backups && tar -czf backups/{{archive_name:config_snapshot.tar.gz}} app_config.json welcome.txt && ls -la backups",
    },
    # 3. Networking
    {
        "id": "pb-listening-ports",
        "name": "Listening Ports & Active Sockets",
        "category": "Networking",
        "description": "Shows open TCP listening ports and bound server processes.",
        "command": "ss -tulnp",
    },
    {
        "id": "pb-net-latency",
        "name": "Network Ping & Latency Check",
        "category": "Networking",
        "description": "Pings {{target_host:127.0.0.1}} to verify routing and latency.",
        "command": "ping -n {{count:2}} {{target_host:127.0.0.1}}",
    },
    {
        "id": "pb-ssl-check",
        "name": "TLS / Config Endpoint Audit",
        "category": "Networking",
        "description": "Inspects application configuration in {{config_file:app_config.json}}.",
        "command": "cat {{config_file:app_config.json}}",
    },
    # 4. Security
    {
        "id": "pb-ssh-users",
        "name": "Active SSH Users & Recent Logins",
        "category": "Security",
        "description": "Shows currently logged-in sessions and last {{login_count:5}} logins.",
        "command": "whoami && w && last -n {{login_count:5}}",
    },
    {
        "id": "pb-ssh-perms",
        "name": "SSH Key & Permissions Audit",
        "category": "Security",
        "description": "Audits directory permissions and checks {{audit_file:app_config.json}}.",
        "command": "ls -la && stat {{audit_file:app_config.json}}",
    },
    {
        "id": "pb-world-writable",
        "name": "Security Log & Config Integrity Check",
        "category": "Security",
        "description": "Prints security and access events from {{log_file:server.log}}.",
        "command": "cat {{log_file:server.log}}",
    },
    # 5. Containers & Git
    {
        "id": "pb-docker-status",
        "name": "Docker Container & Resource Status",
        "category": "Containers & Git",
        "description": "Lists running containers and resource utilization snapshot.",
        "command": "docker ps && docker stats --no-stream",
    },
    {
        "id": "pb-systemd-failed",
        "name": "Failed Systemd Services Check",
        "category": "Containers & Git",
        "description": "Checks service manager health and lists any degraded units.",
        "command": "systemctl --failed",
    },
    {
        "id": "pb-git-status",
        "name": "Git Repo Status & Recent Commits",
        "category": "Containers & Git",
        "description": "Displays current branch status and latest commit history.",
        "command": "git status -sb || ls -la",
    },
]


def load_playbooks() -> List[dict]:
    if not PLAYBOOKS_PATH.exists():
        PLAYBOOKS_PATH.write_text(json.dumps(DEFAULT_PLAYBOOKS, indent=2), encoding="utf-8")
        return list(DEFAULT_PLAYBOOKS)
    try:
        data = json.loads(PLAYBOOKS_PATH.read_text(encoding="utf-8"))
        # Automatically upgrade default playbooks if none of them have parameterized {{...}} syntax yet
        if data and not any("{{" in p.get("command", "") for p in data):
            PLAYBOOKS_PATH.write_text(json.dumps(DEFAULT_PLAYBOOKS, indent=2), encoding="utf-8")
            return list(DEFAULT_PLAYBOOKS)
        return data
    except Exception:
        return list(DEFAULT_PLAYBOOKS)


def save_playbooks(playbooks: List[dict]):
    PLAYBOOKS_PATH.write_text(json.dumps(playbooks, indent=2), encoding="utf-8")


# ---------------------------------------------------------------------------
# App-Level Authentication & Reverse-Proxy SSO Support
# ---------------------------------------------------------------------------
AUTH_TOKENS: Dict[str, float] = {}  # token -> expiry timestamp


def _hash_password(password: str, salt: str) -> str:
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 120_000)
    return dk.hex()


def load_auth_config() -> dict:
    env_pw = os.environ.get("WEBSSH_APP_PASSWORD", "").strip()
    trust_proxy = os.environ.get("WEBSSH_TRUST_PROXY_HEADERS", "false").lower() in ("1", "true", "yes")
    if AUTH_CONFIG_PATH.exists():
        try:
            cfg = json.loads(AUTH_CONFIG_PATH.read_text(encoding="utf-8"))
            if env_pw and not cfg.get("password_hash"):
                salt = secrets.token_hex(16)
                cfg["enabled"] = True
                cfg["salt"] = salt
                cfg["password_hash"] = _hash_password(env_pw, salt)
                AUTH_CONFIG_PATH.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
            return cfg
        except Exception:
            pass

    cfg = {
        "enabled": bool(env_pw),
        "salt": "",
        "password_hash": "",
        "trust_proxy_headers": trust_proxy,
    }
    if env_pw:
        salt = secrets.token_hex(16)
        cfg["salt"] = salt
        cfg["password_hash"] = _hash_password(env_pw, salt)
    AUTH_CONFIG_PATH.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    return cfg


def save_auth_config(cfg: dict):
    AUTH_CONFIG_PATH.write_text(json.dumps(cfg, indent=2), encoding="utf-8")


def _extract_proxy_user(headers) -> Optional[str]:
    cfg = load_auth_config()
    env_trust = os.environ.get("WEBSSH_TRUST_PROXY_HEADERS", "false").lower() in ("1", "true", "yes")
    if not (cfg.get("trust_proxy_headers") or env_trust):
        return None
    for hdr in (
        "Remote-User",
        "X-Forwarded-User",
        "X-Authentik-Username",
        "Cf-Access-Authenticated-User-Email",
    ):
        val = headers.get(hdr)
        if val:
            return val.strip()
    return None


def _is_request_authenticated(request: Request) -> tuple[bool, Optional[str], str]:
    """Returns (authenticated, username, mode)."""
    cfg = load_auth_config()
    proxy_user = _extract_proxy_user(request.headers)
    if proxy_user:
        return True, proxy_user, "proxy_sso"

    if not cfg.get("enabled"):
        return True, "admin", "open"

    token = request.cookies.get("webssh_token") or ""
    if not token:
        auth_hdr = request.headers.get("Authorization", "")
        if auth_hdr.startswith("Bearer "):
            token = auth_hdr[7:].strip()

    now = time.time()
    exp = AUTH_TOKENS.get(token)
    if exp and exp > now:
        return True, "admin", "password"
    return False, None, "password"


# ---------------------------------------------------------------------------
# Embedded Local SSH + SFTP Server (127.0.0.1:2222)
# ---------------------------------------------------------------------------
class SandboxSFTPServer(asyncssh.SFTPServer):
    def __init__(self, chan):
        super().__init__(chan, chroot=str(SANDBOX_ROOT))


class SandboxSSHServer(asyncssh.SSHServer):
    def connection_made(self, conn):
        self._conn = conn

    def begin_auth(self, username):
        return True

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        return len(password) > 0


async def handle_sandbox_process(process: asyncssh.SSHServerProcess):
    """Interactive PTY shell + exec handler for the embedded local SSH server on 127.0.0.1:2222."""
    user = process.get_extra_info("username") or "demo"
    cwd = SANDBOX_ROOT

    def sftp_path(p: Path) -> str:
        try:
            rel = p.resolve().relative_to(SANDBOX_ROOT.resolve())
            return "/" if str(rel) == "." else f"/{rel.as_posix()}"
        except ValueError:
            return "/"

    def rel_path(p: Path) -> str:
        try:
            rel = p.resolve().relative_to(SANDBOX_ROOT.resolve())
            return "~" if str(rel) == "." else f"~/{rel.as_posix()}"
        except ValueError:
            return "~"

    def safe_resolve(target: str) -> Path:
        if not target or target == "~":
            return SANDBOX_ROOT.resolve()
        if target.startswith("~/"):
            target = target[2:]
            cand = (SANDBOX_ROOT / target).resolve()
        elif target.startswith("/"):
            cand = (SANDBOX_ROOT / target.lstrip("/")).resolve()
        else:
            cand = (cwd / target).resolve()
        try:
            cand.relative_to(SANDBOX_ROOT.resolve())
            return cand
        except ValueError:
            return SANDBOX_ROOT.resolve()

    def write_out(text: str):
        process.stdout.write(text.replace("\r\n", "\n").replace("\n", "\r\n"))

    def emit_osc7():
        # OSC 7 escape sequence so browser knows the remote working directory changed!
        process.stdout.write(f"\x1b]7;file://sandbox-ssh{sftp_path(cwd)}\x07")

    def prompt_str() -> str:
        return f"\x1b[1;32m{user}@sandbox-ssh\x1b[0m:\x1b[1;34m{rel_path(cwd)}\x1b[0m$ "

    def run_single_command(cmd_line: str):
        nonlocal cwd
        cmd_line = cmd_line.strip()
        if not cmd_line:
            return
        parts = cmd_line.split()
        cmd = parts[0]
        args = parts[1:]

        if cmd in ("exit", "logout"):
            write_out("logout\n")
            process.exit(0)
            return
        elif cmd == "clear":
            process.stdout.write("\x1b[2J\x1b[H")
            return
        elif cmd == "help":
            write_out(
                "Available built-in & shell commands:\n"
                "  ls [-la] [dir]     List directory contents\n"
                "  cd <dir>           Change current directory (auto-syncs SFTP browser!)\n"
                "  pwd                Print working directory\n"
                "  cat <file>         Display file contents\n"
                "  mkdir <dir>        Create directory\n"
                "  rm [-rf] <path>    Remove file or directory\n"
                "  touch <file>       Create empty file\n"
                "  echo <text>        Print text (supports > file)\n"
                "  stat <file>        Show file metadata\n"
                "  whoami / uname -a  Show session & system info\n"
                "  clear              Clear terminal screen\n"
                "  exit               Disconnect SSH session\n"
            )
            return
        elif cmd == "pwd":
            write_out(sftp_path(cwd) + "\n")
            return
        elif cmd == "whoami":
            write_out(f"{user}\n")
            return
        elif cmd == "uname":
            write_out("Linux sandbox-ssh 6.8.0-webssh #1 SMP PREEMPT_DYNAMIC x86_64 GNU/Linux\n")
            return
        elif cmd == "uptime":
            up_sec = int(time.time() - psutil.boot_time())
            hrs, rem = divmod(up_sec, 3600)
            mins, _ = divmod(rem, 60)
            cpu_load = round(psutil.cpu_percent(interval=0.05) / 25.0, 2)
            write_out(
                f" {time.strftime('%H:%M:%S')} up {hrs}:{mins:02d},  1 user,  load average: {cpu_load:.2f}, {max(0.1, cpu_load - 0.08):.2f}, {max(0.05, cpu_load - 0.15):.2f}\n"
            )
            return
        elif cmd == "free":
            vm = psutil.virtual_memory()
            tot_g = vm.total / (1024 ** 3)
            used_g = vm.used / (1024 ** 3)
            free_g = vm.available / (1024 ** 3)
            write_out(
                "               total        used        free      shared  buff/cache   available\n"
                f"Mem:          {tot_g:5.1f}Gi     {used_g:5.1f}Gi     {free_g:5.1f}Gi       0.1Gi       1.2Gi     {free_g:5.1f}Gi\n"
                "Swap:          4.0Gi       0.0Gi       4.0Gi\n"
            )
            return
        elif cmd == "df":
            du = shutil.disk_usage(str(SANDBOX_ROOT))
            tot_g = du.total / (1024 ** 3)
            used_g = du.used / (1024 ** 3)
            avail_g = du.free / (1024 ** 3)
            pct = int(round((du.used / max(1, du.total)) * 100))
            write_out(
                "Filesystem      Size  Used Avail Use% Mounted on\n"
                f"/dev/nvme0n1p1 {tot_g:4.0f}G {used_g:4.0f}G {avail_g:4.0f}G  {pct}% /\n"
            )
            return
        elif cmd == "du":
            items = sorted(cwd.iterdir(), key=lambda p: p.name.lower())
            for item in items:
                if item.is_dir():
                    sz = sum(f.stat().st_size for f in item.rglob("*") if f.is_file())
                else:
                    sz = item.stat().st_size
                kb = max(1, (sz + 1023) // 1024)
                write_out(f"{kb}K\t{item.name}\n")
            return
        elif cmd == "ps":
            write_out("USER         PID %CPU %MEM    COMMAND\n")
            procs = []
            for p in psutil.process_iter(["pid", "name", "cpu_percent", "memory_percent"]):
                try:
                    info = p.info
                    if info["name"]:
                        procs.append(info)
                except Exception:
                    continue
            procs.sort(key=lambda x: (x.get("memory_percent") or 0.0), reverse=True)
            for info in procs[:10]:
                write_out(
                    f"{user:<10} {info['pid']:>5} {float(info.get('cpu_percent') or 0.0):>4.1f} {float(info.get('memory_percent') or 0.0):>4.1f}    {info['name']}\n"
                )
            return
        elif cmd in ("ss", "netstat"):
            write_out(
                "Netid  State   Recv-Q  Send-Q   Local Address:Port    Peer Address:Port  Process\n"
                "tcp    LISTEN  0       128      127.0.0.1:2222        0.0.0.0:*          users:((\"sshd-sandbox\",pid=1042,fd=3))\n"
                "tcp    LISTEN  0       128      127.0.0.1:8090        0.0.0.0:*          users:((\"webssh-studio\",pid=1001,fd=6))\n"
            )
            return
        elif cmd == "w":
            write_out(
                f"USER     TTY      FROM             LOGIN@   IDLE   WHAT\n"
                f"{user:<8} pts/0    127.0.0.1        {time.strftime('%H:%M')}    0.00s  -bash\n"
            )
            return
        elif cmd == "last":
            write_out(
                f"{user:<8} pts/0    127.0.0.1        {time.strftime('%a %b %d %H:%M')}   still logged in\n"
            )
            return
        elif cmd == "journalctl":
            log_p = SANDBOX_ROOT / "server.log"
            if log_p.exists():
                write_out(log_p.read_text(encoding="utf-8", errors="replace"))
            else:
                write_out("-- No error entries found in journal --\n")
            return
        elif cmd == "systemctl":
            write_out("  UNIT LOAD ACTIVE SUB DESCRIPTION\n0 loaded units listed. Pass --all to see loaded but inactive units.\n")
            return
        elif cmd == "docker":
            if args and args[0] == "stats":
                write_out(
                    "CONTAINER ID   NAME                CPU %     MEM USAGE / LIMIT     MEM %     NET I/O\n"
                    "a1b2c3d4e5f6   webssh-edge-proxy   0.45%     48.2MiB / 2.0GiB      2.35%     1.4MB / 890kB\n"
                )
            else:
                write_out(
                    "CONTAINER ID   IMAGE                    COMMAND                  STATUS          PORTS                    NAMES\n"
                    "a1b2c3d4e5f6   nginx:1.27-alpine        \"/docker-entrypoint.…\"   Up 4 hours      0.0.0.0:8080->80/tcp     webssh-edge-proxy\n"
                )
            return
        elif cmd == "cd":
            target = args[0] if args else "~"
            dest = safe_resolve(target)
            if not dest.exists():
                write_out(f"bash: cd: {target}: No such file or directory\n")
            elif not dest.is_dir():
                write_out(f"bash: cd: {target}: Not a directory\n")
            else:
                cwd = dest
                emit_osc7()
            return
        elif cmd == "ls":
            long_fmt = any(a.startswith("-") and "l" in a for a in args)
            targets = [a for a in args if not a.startswith("-")]
            target_dir = safe_resolve(targets[0]) if targets else cwd
            if not target_dir.exists():
                write_out(f"ls: cannot access '{targets[0]}': No such file or directory\n")
                return
            if target_dir.is_file():
                write_out(f"{target_dir.name}\n")
                return
            items = sorted(target_dir.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower()))
            if long_fmt:
                write_out(f"total {len(items)}\n")
                for item in items:
                    st = item.stat()
                    mode = "drwxr-xr-x" if item.is_dir() else "-rw-r--r--"
                    mtime = time.strftime("%b %d %H:%M", time.localtime(st.st_mtime))
                    name_disp = f"\x1b[1;34m{item.name}/\x1b[0m" if item.is_dir() else item.name
                    write_out(f"{mode} 1 {user} {user} {st.st_size:>8} {mtime} {name_disp}\n")
            else:
                names = [
                    f"\x1b[1;34m{item.name}/\x1b[0m" if item.is_dir() else item.name
                    for item in items
                ]
                write_out("  ".join(names) + ("\n" if names else ""))
            return
        elif cmd == "cat":
            if not args:
                write_out("cat: missing file operand\n")
                return
            for arg in args:
                clean_arg = arg.strip("'\"")
                f = safe_resolve(clean_arg)
                if not f.exists():
                    write_out(f"cat: {clean_arg}: No such file or directory\n")
                elif f.is_dir():
                    write_out(f"cat: {clean_arg}: Is a directory\n")
                else:
                    try:
                        content = f.read_text(encoding="utf-8", errors="replace")
                        write_out(content)
                        if not content.endswith("\n"):
                            write_out("\n")
                    except Exception as exc:
                        write_out(f"cat: {clean_arg}: {exc}\n")
            return
        elif cmd == "mkdir":
            dirs = [a for a in args if not a.startswith("-")]
            if not dirs:
                write_out("mkdir: missing operand\n")
                return
            for d in dirs:
                dest = safe_resolve(d)
                dest.mkdir(parents=True, exist_ok=True)
            return
        elif cmd == "touch":
            if not args:
                write_out("touch: missing file operand\n")
                return
            for f_arg in args:
                dest = safe_resolve(f_arg)
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.touch()
            return
        elif cmd == "rm":
            targets = [a for a in args if not a.startswith("-")]
            recursive = any("r" in a.lower() for a in args if a.startswith("-"))
            if not targets:
                write_out("rm: missing operand\n")
                return
            for t in targets:
                dest = safe_resolve(t)
                if dest == SANDBOX_ROOT.resolve():
                    write_out("rm: cannot remove root directory\n")
                    continue
                if not dest.exists():
                    write_out(f"rm: cannot remove '{t}': No such file or directory\n")
                elif dest.is_dir():
                    if recursive:
                        shutil.rmtree(dest)
                    else:
                        write_out(f"rm: cannot remove '{t}': Is a directory (use -rf)\n")
                else:
                    dest.unlink()
            return
        elif cmd == "stat":
            if not args:
                write_out("stat: missing operand\n")
                return
            dest = safe_resolve(args[0])
            if not dest.exists():
                write_out(f"stat: cannot statx '{args[0]}': No such file or directory\n")
                return
            st = dest.stat()
            write_out(
                f"  File: {dest.name}\n"
                f"  Size: {st.st_size}\tType: {'directory' if dest.is_dir() else 'regular file'}\n"
                f"Modify: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(st.st_mtime))}\n"
            )
            return
        elif cmd == "echo":
            if ">" in args:
                idx = args.index(">")
                text = " ".join(args[:idx]).strip("'\"")
                if idx + 1 < len(args):
                    dest = safe_resolve(args[idx + 1])
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    dest.write_text(text + "\n", encoding="utf-8")
                    return
            write_out(" ".join(args).strip("'\"") + "\n")
            return
        else:
            try:
                res = subprocess.run(
                    cmd_line,
                    shell=True,
                    cwd=str(cwd),
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if res.stdout:
                    write_out(res.stdout)
                if res.stderr:
                    write_out(res.stderr)
            except Exception as exc:
                write_out(f"{cmd}: error executing command: {exc}\n")

    def run_command_chain(cmd_line: str):
        for sub in cmd_line.split("&&"):
            run_single_command(sub)

    # Support non-interactive exec_command
    if process.command:
        run_command_chain(process.command)
        process.exit(0)
        return

    write_out(
        "\x1b[1;36m============================================================\x1b[0m\n"
        "\x1b[1;36m  WebSSH Studio — Local SSH2 + SFTP Sandbox (127.0.0.1:2222)\x1b[0m\n"
        "\x1b[1;36m============================================================\x1b[0m\n"
        f"Connected as \x1b[1;33m{user}\x1b[0m via SSH-2.0. SFTP root: ~/ ({SANDBOX_ROOT.name})\n"
        "Type \x1b[1;32mhelp\x1b[0m, \x1b[1;32mls -la\x1b[0m, \x1b[1;32mcat <file>\x1b[0m, or drop files in the UI!\n\n"
    )
    emit_osc7()
    process.stdout.write(prompt_str())

    line_buf: List[str] = []
    history: List[str] = []
    hist_idx = 0

    def redraw_line(new_text: str):
        process.stdout.write("\r\x1b[2K" + prompt_str() + new_text)

    try:
        while not process.stdin.at_eof():
            data = await process.stdin.read(1024)
            if not data:
                break
            i = 0
            while i < len(data):
                ch = data[i]
                if ch == "\x1b" and i + 2 < len(data) and data[i + 1] == "[":
                    code = data[i + 2]
                    if code == "A":
                        if history and hist_idx > 0:
                            hist_idx -= 1
                            line_buf = list(history[hist_idx])
                            redraw_line("".join(line_buf))
                    elif code == "B":
                        if hist_idx < len(history) - 1:
                            hist_idx += 1
                            line_buf = list(history[hist_idx])
                            redraw_line("".join(line_buf))
                        else:
                            hist_idx = len(history)
                            line_buf = []
                            redraw_line("")
                    i += 3
                    continue
                if ch in ("\r", "\n"):
                    write_out("\n")
                    cmd_str = "".join(line_buf)
                    line_buf.clear()
                    if cmd_str.strip():
                        history.append(cmd_str)
                        hist_idx = len(history)
                    run_command_chain(cmd_str)
                    if not process.is_closing():
                        process.stdout.write(prompt_str())
                    if ch == "\r" and i + 1 < len(data) and data[i + 1] == "\n":
                        i += 1
                elif ch in ("\x7f", "\b"):
                    if line_buf:
                        line_buf.pop()
                        process.stdout.write("\b \b")
                elif ch == "\x03":
                    line_buf.clear()
                    write_out("^C\n")
                    process.stdout.write(prompt_str())
                elif ch == "\x0c":
                    process.stdout.write("\x1b[2J\x1b[H" + prompt_str() + "".join(line_buf))
                elif ord(ch) >= 32 or ch == "\t":
                    line_buf.append(ch)
                    process.stdout.write(ch)
                i += 1
    except (asyncssh.BreakReceived, asyncssh.TerminalSizeChanged, asyncssh.SignalReceived):
        pass
    except Exception:
        pass


# ---------------------------------------------------------------------------
# SSH Port Forwarding Tunnel Manager
# ---------------------------------------------------------------------------
class PortForwardTunnel:
    def __init__(
        self,
        tunnel_id: str,
        label: str,
        local_port: int,
        remote_host: str,
        remote_port: int,
        server: asyncio.AbstractServer,
    ):
        self.tunnel_id = tunnel_id
        self.label = label
        self.local_port = local_port
        self.remote_host = remote_host
        self.remote_port = remote_port
        self.server = server
        self.created_at = time.time()
        self.bytes_transferred = 0
        self.active_connections = 0

    def to_dict(self):
        return {
            "tunnel_id": self.tunnel_id,
            "label": self.label,
            "local_port": self.local_port,
            "remote_host": self.remote_host,
            "remote_port": self.remote_port,
            "bytes_transferred": self.bytes_transferred,
            "active_connections": self.active_connections,
            "created_at": self.created_at,
        }

    def close(self):
        try:
            self.server.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Active SSH Session Store
# ---------------------------------------------------------------------------
class SSHSession:
    def __init__(
        self,
        session_id: str,
        host: str,
        port: int,
        username: str,
        client: paramiko.SSHClient,
        sftp: Optional[paramiko.SFTPClient],
        initial_dir: str,
        jump_client: Optional[paramiko.SSHClient] = None,
        jump_host_label: Optional[str] = None,
    ):
        self.session_id = session_id
        self.host = host
        self.port = port
        self.username = username
        self.client = client
        self.sftp = sftp
        self.current_dir = initial_dir
        self.jump_client = jump_client
        self.jump_host_label = jump_host_label
        self.created_at = time.time()
        self.channel: Optional[paramiko.Channel] = None
        self.ws: Optional[WebSocket] = None
        self.transfer_count = 0
        self.tunnels: Dict[str, PortForwardTunnel] = {}

    def ensure_sftp(self) -> paramiko.SFTPClient:
        if self.sftp is None:
            self.sftp = self.client.open_sftp()
        return self.sftp

    def close(self):
        for t in list(self.tunnels.values()):
            t.close()
        self.tunnels.clear()
        try:
            if self.channel:
                self.channel.close()
        except Exception:
            pass
        try:
            if self.sftp:
                self.sftp.close()
        except Exception:
            pass
        try:
            self.client.close()
        except Exception:
            pass
        try:
            if self.jump_client:
                self.jump_client.close()
        except Exception:
            pass


SESSIONS: Dict[str, SSHSession] = {}
SANDBOX_SERVER = None
SANDBOX_PORT = 2222


# ---------------------------------------------------------------------------
# Pydantic Models
# ---------------------------------------------------------------------------
class ConnectRequest(BaseModel):
    host: str
    port: int = 22
    username: str
    auth_type: str = "password"
    password: Optional[str] = None
    private_key: Optional[str] = None
    passphrase: Optional[str] = None
    profile_id: Optional[str] = None
    # Jump Host / Bastion (ProxyJump) support
    use_jump_host: bool = False
    jump_host: Optional[str] = None
    jump_port: int = 22
    jump_username: Optional[str] = None
    jump_auth_type: str = "password"
    jump_password: Optional[str] = None
    jump_private_key: Optional[str] = None
    cols: int = 100
    rows: int = 30


class MkdirRequest(BaseModel):
    path: str


class RenameRequest(BaseModel):
    old_path: str
    new_path: str


class SaveFileContentRequest(BaseModel):
    path: str
    content: str


class ProfileCreateRequest(BaseModel):
    name: str
    tag: str = "Server"
    host: str
    port: int = 22
    username: str
    auth_type: str = "password"
    password: Optional[str] = None
    private_key: Optional[str] = None
    passphrase: Optional[str] = None
    use_jump_host: bool = False
    jump_host: Optional[str] = None
    jump_port: int = 22
    jump_username: Optional[str] = None


class SSHConfigImportRequest(BaseModel):
    config_text: str


class PlaybookRequest(BaseModel):
    name: str
    category: str = "Custom"
    description: str = ""
    command: str


class TunnelCreateRequest(BaseModel):
    label: str = "Web Tunnel"
    local_port: int
    remote_host: str = "127.0.0.1"
    remote_port: int


class AuthLoginRequest(BaseModel):
    password: str


class AuthSetupRequest(BaseModel):
    enabled: bool
    new_password: Optional[str] = None
    current_password: Optional[str] = None
    trust_proxy_headers: bool = False


# ---------------------------------------------------------------------------
# FastAPI Lifespan & App Initialization
# ---------------------------------------------------------------------------
async def ensure_sandbox_server():
    global SANDBOX_SERVER
    if SANDBOX_SERVER is not None:
        return
    if not HOST_KEY_PATH.exists():
        key = asyncssh.generate_private_key("ssh-rsa")
        HOST_KEY_PATH.write_bytes(key.export_private_key())
    try:
        SANDBOX_SERVER = await asyncssh.create_server(
            SandboxSSHServer,
            "127.0.0.1",
            SANDBOX_PORT,
            server_host_keys=[str(HOST_KEY_PATH)],
            process_factory=handle_sandbox_process,
            sftp_factory=SandboxSFTPServer,
            encoding="utf-8",
        )
    except Exception as exc:
        print(f"[Warning] Could not bind sandbox SSH server on {SANDBOX_PORT}: {exc}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    await ensure_sandbox_server()
    load_profiles()
    load_playbooks()
    yield
    for s in list(SESSIONS.values()):
        s.close()
    SESSIONS.clear()
    if SANDBOX_SERVER:
        SANDBOX_SERVER.close()
        await SANDBOX_SERVER.wait_closed()


app = FastAPI(title="WebSSH & SFTP Studio", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def auth_guard_middleware(request: Request, call_next):
    path = request.url.path
    if path.startswith("/api/") and not path.startswith("/api/auth/") and path != "/api/info":
        authed, _, _ = _is_request_authenticated(request)
        if not authed:
            return JSONResponse(status_code=401, content={"detail": "Authentication required"})
    return await call_next(request)


@app.get("/api/auth/status")
async def get_auth_status(request: Request):
    cfg = load_auth_config()
    authed, user, mode = _is_request_authenticated(request)
    return {
        "auth_enabled": bool(cfg.get("enabled")),
        "authenticated": authed,
        "username": user,
        "mode": mode,
        "trust_proxy_headers": bool(cfg.get("trust_proxy_headers")),
        "password_configured": bool(cfg.get("password_hash")),
    }


@app.post("/api/auth/login")
async def login_app(req: AuthLoginRequest, response: Response):
    cfg = load_auth_config()
    if not cfg.get("enabled") or not cfg.get("password_hash"):
        return {"status": "ok", "authenticated": True}

    candidate = _hash_password(req.password, cfg.get("salt", ""))
    if not hmac.compare_digest(candidate, cfg.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid master password.")

    token = secrets.token_urlsafe(32)
    AUTH_TOKENS[token] = time.time() + 86400 * 7  # 7 days
    response.set_cookie(
        key="webssh_token",
        value=token,
        httponly=True,
        max_age=86400 * 7,
        samesite="lax",
    )
    return {"status": "ok", "authenticated": True, "token": token}


@app.post("/api/auth/logout")
async def logout_app(request: Request, response: Response):
    token = request.cookies.get("webssh_token")
    if token:
        AUTH_TOKENS.pop(token, None)
    response.delete_cookie("webssh_token")
    return {"status": "logged_out"}


@app.post("/api/auth/setup")
async def setup_app_auth(req: AuthSetupRequest, request: Request, response: Response):
    cfg = load_auth_config()
    # If already enabled, require either active auth session or matching current_password
    if cfg.get("enabled") and cfg.get("password_hash"):
        authed, _, _ = _is_request_authenticated(request)
        if not authed:
            cur_hash = _hash_password(req.current_password or "", cfg.get("salt", ""))
            if not hmac.compare_digest(cur_hash, cfg.get("password_hash", "")):
                raise HTTPException(status_code=401, detail="Current master password is required.")

    cfg["trust_proxy_headers"] = req.trust_proxy_headers
    if req.enabled:
        if req.new_password:
            salt = secrets.token_hex(16)
            cfg["salt"] = salt
            cfg["password_hash"] = _hash_password(req.new_password, salt)
        elif not cfg.get("password_hash"):
            raise HTTPException(status_code=400, detail="Please provide a new master password.")
        cfg["enabled"] = True
        save_auth_config(cfg)
        token = secrets.token_urlsafe(32)
        AUTH_TOKENS[token] = time.time() + 86400 * 7
        response.set_cookie(
            key="webssh_token",
            value=token,
            httponly=True,
            max_age=86400 * 7,
            samesite="lax",
        )
        return {"status": "enabled", "auth_enabled": True, "token": token}
    else:
        cfg["enabled"] = False
        save_auth_config(cfg)
        return {"status": "disabled", "auth_enabled": False}


def _parse_private_key(raw_key: Optional[str], passphrase: Optional[str] = None):
    if not raw_key:
        return None
    key_stream = io.StringIO(raw_key.strip())
    for key_cls in (paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey):
        try:
            key_stream.seek(0)
            return key_cls.from_private_key(key_stream, password=passphrase or None)
        except Exception:
            continue
    raise ValueError("Unable to parse private key. Ensure it is a valid OpenSSH/PEM key.")


def _connect_paramiko(req: ConnectRequest) -> SSHSession:
    # Populate credentials from encrypted profile vault if profile_id is supplied
    password = req.password
    private_key = req.private_key
    passphrase = req.passphrase
    if req.profile_id:
        for prof in load_profiles():
            if prof.get("id") == req.profile_id:
                if not password and prof.get("encrypted_password"):
                    password = _decrypt_secret(prof.get("encrypted_password"))
                if not private_key and prof.get("encrypted_key"):
                    private_key = _decrypt_secret(prof.get("encrypted_key"))
                if not passphrase and prof.get("encrypted_passphrase"):
                    passphrase = _decrypt_secret(prof.get("encrypted_passphrase"))
                break

    jump_client = None
    jump_sock = None
    jump_label = None

    if req.use_jump_host and req.jump_host:
        jump_client = paramiko.SSHClient()
        jump_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        jump_pkey = (
            _parse_private_key(req.jump_private_key)
            if req.jump_auth_type == "key"
            else None
        )
        jump_client.connect(
            hostname=req.jump_host,
            port=req.jump_port or 22,
            username=req.jump_username or req.username,
            password=req.jump_password if req.jump_auth_type == "password" else None,
            pkey=jump_pkey,
            timeout=12,
            allow_agent=False,
            look_for_keys=False,
        )
        transport = jump_client.get_transport()
        if not transport:
            raise ValueError("Jump host transport failed to initialize.")
        jump_sock = transport.open_channel(
            "direct-tcpip",
            (req.host, req.port),
            ("127.0.0.1", 0),
        )
        jump_label = f"{req.jump_username or req.username}@{req.jump_host}:{req.jump_port}"

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    pkey = _parse_private_key(private_key, passphrase) if req.auth_type == "key" else None

    client.connect(
        hostname=req.host,
        port=req.port,
        username=req.username,
        password=password if req.auth_type == "password" else None,
        pkey=pkey,
        sock=jump_sock,
        timeout=12,
        allow_agent=False,
        look_for_keys=False,
    )

    sftp = None
    initial_dir = "/"
    try:
        sftp = client.open_sftp()
        initial_dir = sftp.normalize(".")
    except Exception:
        initial_dir = "/"

    session_id = str(uuid.uuid4())
    return SSHSession(
        session_id=session_id,
        host=req.host,
        port=req.port,
        username=req.username,
        client=client,
        sftp=sftp,
        initial_dir=initial_dir,
        jump_client=jump_client,
        jump_host_label=jump_label,
    )


@app.get("/api/info")
async def get_info():
    await ensure_sandbox_server()
    return {
        "sandbox_available": SANDBOX_SERVER is not None,
        "sandbox_host": "127.0.0.1",
        "sandbox_port": SANDBOX_PORT,
        "sandbox_user": "demo",
        "sandbox_pass": "demo",
        "active_sessions": len(SESSIONS),
    }


@app.post("/api/sessions")
async def create_session(req: ConnectRequest):
    if req.host in ("127.0.0.1", "localhost") and (
        req.port == SANDBOX_PORT or (req.use_jump_host and req.jump_port == SANDBOX_PORT)
    ):
        await ensure_sandbox_server()
    try:
        session = await asyncio.to_thread(_connect_paramiko, req)
        SESSIONS[session.session_id] = session
        return {
            "session_id": session.session_id,
            "host": session.host,
            "port": session.port,
            "username": session.username,
            "current_dir": session.current_dir,
            "sftp_available": session.sftp is not None,
            "jump_host": session.jump_host_label,
        }
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"SSH connection failed: {exc}")


@app.delete("/api/sessions/{session_id}")
async def close_session(session_id: str):
    session = SESSIONS.pop(session_id, None)
    if session:
        await asyncio.to_thread(session.close)
    return {"status": "closed"}


# ---------------------------------------------------------------------------
# Feature 1: SFTP File Listing, In-Browser Code Editor, Preview, Rename & Zip
# ---------------------------------------------------------------------------
def _list_sftp_dir(session: SSHSession, target_path: str):
    sftp = session.ensure_sftp()
    norm_path = sftp.normalize(target_path or ".")
    session.current_dir = norm_path
    attrs = sftp.listdir_attr(norm_path)
    entries = []
    for attr in attrs:
        mode = attr.st_mode or 0
        is_dir = stat.S_ISDIR(mode)
        full_p = posixpath.join(norm_path, attr.filename)
        entries.append(
            {
                "name": attr.filename,
                "path": full_p,
                "is_dir": is_dir,
                "size": attr.st_size or 0,
                "mtime": attr.st_mtime or 0,
                "permissions": stat.filemode(mode) if mode else ("drwxr-xr-x" if is_dir else "-rw-r--r--"),
            }
        )
    entries.sort(key=lambda e: (not e["is_dir"], e["name"].lower()))
    return {"current_dir": norm_path, "entries": entries}


@app.get("/api/sessions/{session_id}/files")
async def list_files(session_id: str, path: str = Query(default=".")):
    session = SESSIONS.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    try:
        return await asyncio.to_thread(_list_sftp_dir, session, path)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Failed to list directory '{path}': {exc}")


@app.get("/api/sessions/{session_id}/file-content")
async def read_remote_file_content(
    session_id: str,
    path: str = Query(...),
    tail_lines: Optional[int] = Query(default=None),
):
    session = SESSIONS.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    def _read():
        sftp = session.ensure_sftp()
        st = sftp.stat(path)
        size = st.st_size or 0
        if size > 5 * 1024 * 1024:
            raise ValueError("File is larger than 5 MB; please download it directly.")
        buf = io.BytesIO()
        sftp.getfo(path, buf)
        raw = buf.getvalue()
        mime, _ = mimetypes.guess_type(path)
        mime = mime or "text/plain"

        if mime.startswith("image/"):
            b64 = base64.b64encode(raw).decode("ascii")
            return {
                "path": path,
                "name": posixpath.basename(path),
                "size": size,
                "kind": "image",
                "mime": mime,
                "data_uri": f"data:{mime};base64,{b64}",
                "content": "",
            }

        text = raw.decode("utf-8", errors="replace")
        if tail_lines and tail_lines > 0:
            lines = text.splitlines()
            text = "\n".join(lines[-tail_lines:])

        return {
            "path": path,
            "name": posixpath.basename(path),
            "size": size,
            "kind": "text",
            "mime": mime,
            "content": text,
        }

    try:
        return await asyncio.to_thread(_read)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Failed to read file '{path}': {exc}")


@app.put("/api/sessions/{session_id}/file-content")
async def save_remote_file_content(session_id: str, req: SaveFileContentRequest):
    session = SESSIONS.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    def _write():
        sftp = session.ensure_sftp()
        raw = req.content.encode("utf-8")
        bio = io.BytesIO(raw)
        sftp.putfo(bio, req.path)
        return {"status": "saved", "path": req.path, "size": len(raw)}

    try:
        return await asyncio.to_thread(_write)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Failed to save file '{req.path}': {exc}")


@app.post("/api/sessions/{session_id}/rename")
async def rename_remote_file(session_id: str, req: RenameRequest):
    session = SESSIONS.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    def _rename():
        sftp = session.ensure_sftp()
        sftp.posix_rename(req.old_path, req.new_path)
        return {"old_path": req.old_path, "new_path": req.new_path}

    try:
        return await asyncio.to_thread(_rename)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Failed to rename: {exc}")


@app.get("/api/sessions/{session_id}/download-zip")
async def download_remote_zip(session_id: str, path: str = Query(default="/")):
    session = SESSIONS.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    def _build_zip():
        sftp = session.ensure_sftp()
        norm_root = sftp.normalize(path or ".")
        zip_buf = io.BytesIO()

        def _walk_and_add(cur_remote: str, rel_prefix: str, zf: zipfile.ZipFile):
            for attr in sftp.listdir_attr(cur_remote):
                full_p = posixpath.join(cur_remote, attr.filename)
                arc_name = f"{rel_prefix}/{attr.filename}".lstrip("/")
                if stat.S_ISDIR(attr.st_mode or 0):
                    _walk_and_add(full_p, arc_name, zf)
                else:
                    # Skip overly huge files > 25MB in zip archive
                    if (attr.st_size or 0) <= 25 * 1024 * 1024:
                        fbuf = io.BytesIO()
                        sftp.getfo(full_p, fbuf)
                        zf.writestr(arc_name, fbuf.getvalue())

        with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
            st = sftp.stat(norm_root)
            if stat.S_ISDIR(st.st_mode or 0):
                _walk_and_add(norm_root, "", zf)
            else:
                fbuf = io.BytesIO()
                sftp.getfo(norm_root, fbuf)
                zf.writestr(posixpath.basename(norm_root), fbuf.getvalue())

        zip_buf.seek(0)
        return zip_buf

    try:
        zbuf = await asyncio.to_thread(_build_zip)
        base_name = posixpath.basename(path.rstrip("/")) or "remote_root"
        return StreamingResponse(
            zbuf,
            media_type="application/zip",
            headers={"Content-Disposition": f'attachment; filename="{base_name}.zip"'},
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Failed to create zip archive: {exc}")


def _mkdir_sftp(session: SSHSession, target_path: str):
    sftp = session.ensure_sftp()
    sftp.mkdir(target_path)
    return {"created": target_path}


@app.post("/api/sessions/{session_id}/mkdir")
async def make_directory(session_id: str, req: MkdirRequest):
    session = SESSIONS.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    try:
        return await asyncio.to_thread(_mkdir_sftp, session, req.path)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Failed to create folder: {exc}")


def _delete_sftp(session: SSHSession, target_path: str):
    sftp = session.ensure_sftp()
    st = sftp.stat(target_path)
    if stat.S_ISDIR(st.st_mode or 0):
        sftp.rmdir(target_path)
    else:
        sftp.remove(target_path)
    return {"deleted": target_path}


@app.delete("/api/sessions/{session_id}/files")
async def delete_remote_file(session_id: str, path: str = Query(...)):
    session = SESSIONS.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    try:
        return await asyncio.to_thread(_delete_sftp, session, path)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Failed to delete '{path}': {exc}")


@app.get("/api/sessions/{session_id}/download")
async def download_remote_file(session_id: str, path: str = Query(...)):
    session = SESSIONS.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    def _read_bytes():
        sftp = session.ensure_sftp()
        buf = io.BytesIO()
        sftp.getfo(path, buf)
        buf.seek(0)
        return buf

    try:
        buf = await asyncio.to_thread(_read_bytes)
        filename = posixpath.basename(path.rstrip("/")) or "download.bin"
        return StreamingResponse(
            buf,
            media_type="application/octet-stream",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Failed to download '{path}': {exc}")


def _ensure_remote_dirs(sftp: paramiko.SFTPClient, remote_dir: str):
    if not remote_dir or remote_dir == "/":
        return
    parts = remote_dir.strip("/").split("/")
    curr = "" if not remote_dir.startswith("/") else "/"
    for part in parts:
        curr = posixpath.join(curr, part)
        try:
            sftp.stat(curr)
        except IOError:
            try:
                sftp.mkdir(curr)
            except Exception:
                pass


def _upload_file_sftp(session: SSHSession, target_dir: str, rel_filename: str, data: bytes) -> dict:
    sftp = session.ensure_sftp()
    clean_rel = rel_filename.replace("\\", "/").lstrip("/")
    remote_path = posixpath.join(target_dir, clean_rel)
    parent_dir = posixpath.dirname(remote_path)
    if parent_dir and parent_dir != target_dir:
        _ensure_remote_dirs(sftp, parent_dir)

    bio = io.BytesIO(data)
    sftp.putfo(bio, remote_path)
    session.transfer_count += 1
    return {
        "filename": clean_rel,
        "remote_path": remote_path,
        "size": len(data),
        "timestamp": time.time(),
    }


@app.post("/api/sessions/{session_id}/upload")
async def upload_files(
    session_id: str,
    target_dir: str = Form(default="."),
    relative_paths: Optional[str] = Form(default=None),
    notify_terminal: bool = Form(default=True),
    files: List[UploadFile] = File(...),
):
    session = SESSIONS.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    rel_list: List[str] = []
    if relative_paths:
        try:
            rel_list = json.loads(relative_paths)
        except Exception:
            rel_list = []

    uploaded = []
    try:
        for idx, up_file in enumerate(files):
            raw = await up_file.read()
            rel_name = (
                rel_list[idx]
                if idx < len(rel_list) and rel_list[idx]
                else (up_file.filename or f"file_{idx}")
            )
            item = await asyncio.to_thread(
                _upload_file_sftp, session, target_dir or session.current_dir, rel_name, raw
            )
            uploaded.append(item)

        return {"status": "ok", "uploaded": uploaded, "target_dir": target_dir}
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"File transfer failed: {exc}")


# ---------------------------------------------------------------------------
# Feature 2: Saved Command Playbooks / Snippets API
# ---------------------------------------------------------------------------
@app.get("/api/playbooks")
async def get_playbooks():
    return {"playbooks": load_playbooks()}


@app.post("/api/playbooks")
async def create_playbook(req: PlaybookRequest):
    playbooks = load_playbooks()
    new_pb = {
        "id": f"pb-{uuid.uuid4().hex[:8]}",
        "name": req.name.strip(),
        "category": req.category.strip() or "Custom",
        "description": req.description.strip(),
        "command": req.command.strip(),
    }
    playbooks.append(new_pb)
    save_playbooks(playbooks)
    return new_pb


@app.delete("/api/playbooks/{playbook_id}")
async def delete_playbook(playbook_id: str):
    playbooks = [p for p in load_playbooks() if p.get("id") != playbook_id]
    save_playbooks(playbooks)
    return {"status": "deleted"}


@app.post("/api/playbooks/reset")
async def reset_default_playbooks():
    save_playbooks(list(DEFAULT_PLAYBOOKS))
    return {"playbooks": load_playbooks()}


# ---------------------------------------------------------------------------
# Feature 3: Live Server Telemetry HUD & Process Inspector
# ---------------------------------------------------------------------------
def _collect_telemetry(session: SSHSession) -> dict:
    # If connected to the local sandbox (or localhost), collect live host telemetry via psutil
    # while also supporting remote Linux SSH telemetry via /proc and ps!
    is_local_sandbox = session.host in ("127.0.0.1", "localhost") and session.port == SANDBOX_PORT

    if not is_local_sandbox:
        try:
            _, stdout, _ = session.client.exec_command(
                "cat /proc/loadavg 2>/dev/null; free -b 2>/dev/null; df -B1 / 2>/dev/null | tail -n 1; ps -eo pid,comm,%cpu,%mem --sort=-%cpu 2>/dev/null | head -n 9",
                timeout=4,
            )
            out = stdout.read().decode("utf-8", errors="replace").strip()
            if out and "Mem:" in out:
                lines = out.splitlines()
                load_1m = float(lines[0].split()[0]) if lines else 0.0
                cpu_pct = min(100.0, round(load_1m * 25.0, 1))
                mem_total, mem_used = 1, 0
                disk_total, disk_used = 1, 0
                procs = []
                for ln in lines:
                    if ln.startswith("Mem:"):
                        parts = ln.split()
                        mem_total = int(parts[1])
                        mem_used = int(parts[2])
                    elif ln.startswith("/"):
                        parts = ln.split()
                        if len(parts) >= 4:
                            disk_total = int(parts[1])
                            disk_used = int(parts[2])
                    elif ln.strip() and ln.strip()[0].isdigit() and "/" not in ln[:6]:
                        parts = ln.split()
                        if len(parts) >= 4:
                            procs.append(
                                {
                                    "pid": int(parts[0]),
                                    "name": parts[1],
                                    "cpu": float(parts[2]),
                                    "mem": float(parts[3]),
                                }
                            )
                return {
                    "cpu_percent": cpu_pct,
                    "mem_total": mem_total,
                    "mem_used": mem_used,
                    "mem_percent": round((mem_used / max(1, mem_total)) * 100, 1),
                    "disk_total": disk_total,
                    "disk_used": disk_used,
                    "disk_percent": round((disk_used / max(1, disk_total)) * 100, 1),
                    "uptime_seconds": int(time.time() - session.created_at),
                    "processes": procs[:8],
                }
        except Exception:
            pass

    # Fallback / Local Sandbox Telemetry via psutil
    cpu_pct = psutil.cpu_percent(interval=0.05)
    vm = psutil.virtual_memory()
    du = shutil.disk_usage(str(SANDBOX_ROOT))
    uptime = int(time.time() - psutil.boot_time())

    procs = []
    for p in psutil.process_iter(["pid", "name", "cpu_percent", "memory_percent"]):
        try:
            info = p.info
            if info["name"]:
                procs.append(
                    {
                        "pid": info["pid"],
                        "name": info["name"],
                        "cpu": round(float(info.get("cpu_percent") or 0.0), 1),
                        "mem": round(float(info.get("memory_percent") or 0.0), 1),
                    }
                )
        except Exception:
            continue
    procs.sort(key=lambda x: (x["mem"], x["cpu"]), reverse=True)

    return {
        "cpu_percent": round(cpu_pct, 1),
        "mem_total": vm.total,
        "mem_used": vm.used,
        "mem_percent": round(vm.percent, 1),
        "disk_total": du.total,
        "disk_used": du.used,
        "disk_percent": round((du.used / max(1, du.total)) * 100, 1),
        "uptime_seconds": uptime,
        "processes": procs[:8],
    }


@app.get("/api/sessions/{session_id}/telemetry")
async def get_session_telemetry(session_id: str):
    session = SESSIONS.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    try:
        return await asyncio.to_thread(_collect_telemetry, session)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Telemetry error: {exc}")


# ---------------------------------------------------------------------------
# Feature 4: Encrypted Connection Vault, ~/.ssh/config Importer & Port Tunnels
# ---------------------------------------------------------------------------
def _public_profile(p: dict) -> dict:
    return {
        "id": p.get("id"),
        "name": p.get("name"),
        "tag": p.get("tag", "Server"),
        "host": p.get("host"),
        "port": p.get("port", 22),
        "username": p.get("username"),
        "auth_type": p.get("auth_type", "password"),
        "has_saved_secret": bool(p.get("encrypted_password") or p.get("encrypted_key")),
        "use_jump_host": bool(p.get("use_jump_host")),
        "jump_host": p.get("jump_host", ""),
        "jump_port": p.get("jump_port", 22),
        "jump_username": p.get("jump_username", ""),
    }


@app.get("/api/profiles")
async def list_saved_profiles():
    return {"profiles": [_public_profile(p) for p in load_profiles()]}


@app.post("/api/profiles")
async def save_connection_profile(req: ProfileCreateRequest):
    profiles = load_profiles()
    new_prof = {
        "id": f"prof-{uuid.uuid4().hex[:8]}",
        "name": req.name.strip(),
        "tag": req.tag.strip() or "Server",
        "host": req.host.strip(),
        "port": req.port,
        "username": req.username.strip(),
        "auth_type": req.auth_type,
        "encrypted_password": _encrypt_secret(req.password),
        "encrypted_key": _encrypt_secret(req.private_key),
        "encrypted_passphrase": _encrypt_secret(req.passphrase),
        "use_jump_host": req.use_jump_host,
        "jump_host": (req.jump_host or "").strip(),
        "jump_port": req.jump_port or 22,
        "jump_username": (req.jump_username or "").strip(),
    }
    profiles.append(new_prof)
    save_profiles(profiles)
    return _public_profile(new_prof)


@app.delete("/api/profiles/{profile_id}")
async def delete_connection_profile(profile_id: str):
    profiles = [p for p in load_profiles() if p.get("id") != profile_id]
    save_profiles(profiles)
    return {"status": "deleted"}


def _parse_ssh_config_text(text: str) -> List[dict]:
    cfg = paramiko.SSHConfig()
    cfg.parse(io.StringIO(text))
    imported = []
    for host_alias in cfg.get_hostnames():
        if "*" in host_alias or "?" in host_alias:
            continue
        lookup = cfg.lookup(host_alias)
        hostname = lookup.get("hostname", host_alias)
        port = int(lookup.get("port", 22))
        user = lookup.get("user", "root")
        proxy_jump = lookup.get("proxyjump", "")
        use_jump = bool(proxy_jump)
        j_host, j_port, j_user = "", 22, user
        if proxy_jump:
            first_hop = proxy_jump.split(",")[0].strip()
            if "@" in first_hop:
                j_user, first_hop = first_hop.split("@", 1)
            if ":" in first_hop:
                j_host, p_str = first_hop.split(":", 1)
                j_port = int(p_str) if p_str.isdigit() else 22
            else:
                j_host = first_hop

        imported.append(
            {
                "id": f"prof-{uuid.uuid4().hex[:8]}",
                "name": host_alias,
                "tag": "SSH Config",
                "host": hostname,
                "port": port,
                "username": user,
                "auth_type": "password",
                "encrypted_password": "",
                "encrypted_key": "",
                "encrypted_passphrase": "",
                "use_jump_host": use_jump,
                "jump_host": j_host,
                "jump_port": j_port,
                "jump_username": j_user,
            }
        )
    return imported


@app.post("/api/ssh-config/import")
async def import_ssh_config(req: SSHConfigImportRequest):
    try:
        new_items = _parse_ssh_config_text(req.config_text)
        profiles = load_profiles()
        profiles.extend(new_items)
        save_profiles(profiles)
        return {
            "imported_count": len(new_items),
            "profiles": [_public_profile(p) for p in profiles],
        }
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Failed to parse SSH config: {exc}")


@app.get("/api/ssh-config/local")
async def read_local_ssh_config():
    user_ssh_cfg = Path.home() / ".ssh" / "config"
    if user_ssh_cfg.exists():
        return {
            "found": True,
            "path": str(user_ssh_cfg),
            "content": user_ssh_cfg.read_text(encoding="utf-8", errors="replace"),
        }
    sample = (
        "Host prod-web-01\n"
        "    HostName 10.20.1.15\n"
        "    User ubuntu\n"
        "    Port 22\n"
        "    ProxyJump bastion@203.0.113.5:22\n\n"
        "Host local-sandbox\n"
        "    HostName 127.0.0.1\n"
        "    User demo\n"
        "    Port 2222\n"
    )
    return {"found": False, "path": "~/.ssh/config (sample)", "content": sample}


# SSH Port Forwarding (Local -L Tunnel)
@app.get("/api/sessions/{session_id}/tunnels")
async def list_session_tunnels(session_id: str):
    session = SESSIONS.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return {"tunnels": [t.to_dict() for t in session.tunnels.values()]}


@app.post("/api/sessions/{session_id}/tunnels")
async def create_session_tunnel(session_id: str, req: TunnelCreateRequest):
    session = SESSIONS.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    if req.local_port < 1024 or req.local_port > 65535:
        raise HTTPException(status_code=400, detail="Local port must be between 1024 and 65535.")

    tunnel_id = f"tun-{uuid.uuid4().hex[:8]}"
    tunnel_ref: Dict[str, PortForwardTunnel] = {}

    async def _handle_tunnel_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        tun = tunnel_ref.get("instance")
        if tun:
            tun.active_connections += 1

        # Try opening direct-tcpip channel on SSH transport first; fallback to direct TCP for sandbox
        transport = session.client.get_transport()
        ssh_chan = None
        if transport and transport.is_active():
            try:
                ssh_chan = await asyncio.to_thread(
                    transport.open_channel,
                    "direct-tcpip",
                    (req.remote_host, req.remote_port),
                    ("127.0.0.1", req.local_port),
                )
            except Exception:
                ssh_chan = None

        if ssh_chan is not None:
            ssh_chan.setblocking(False)
            try:
                async def c2s():
                    while not reader.at_eof():
                        data = await reader.read(4096)
                        if not data:
                            break
                        await asyncio.to_thread(ssh_chan.sendall, data)
                        if tun:
                            tun.bytes_transferred += len(data)

                async def s2c():
                    while not ssh_chan.closed:
                        if ssh_chan.recv_ready():
                            data = await asyncio.to_thread(ssh_chan.recv, 4096)
                            if not data:
                                break
                            writer.write(data)
                            await writer.drain()
                            if tun:
                                tun.bytes_transferred += len(data)
                        else:
                            await asyncio.sleep(0.01)

                await asyncio.gather(c2s(), s2c(), return_exceptions=True)
            finally:
                try:
                    ssh_chan.close()
                except Exception:
                    pass
                writer.close()
                if tun:
                    tun.active_connections = max(0, tun.active_connections - 1)
            return

        # Direct TCP bridge fallback (for embedded sandbox server where direct-tcpip may be disabled)
        try:
            rem_reader, rem_writer = await asyncio.open_connection(req.remote_host, req.remote_port)

            async def pipe(r: asyncio.StreamReader, w: asyncio.StreamWriter):
                try:
                    while not r.at_eof():
                        chunk = await r.read(4096)
                        if not chunk:
                            break
                        w.write(chunk)
                        await w.drain()
                        if tun:
                            tun.bytes_transferred += len(chunk)
                except Exception:
                    pass
                finally:
                    try:
                        w.close()
                    except Exception:
                        pass

            await asyncio.gather(pipe(reader, rem_writer), pipe(rem_reader, writer))
        except Exception:
            writer.close()
        finally:
            if tun:
                tun.active_connections = max(0, tun.active_connections - 1)

    try:
        srv = await asyncio.start_server(_handle_tunnel_client, "127.0.0.1", req.local_port)
        tun = PortForwardTunnel(
            tunnel_id=tunnel_id,
            label=req.label or f"L:{req.local_port}",
            local_port=req.local_port,
            remote_host=req.remote_host,
            remote_port=req.remote_port,
            server=srv,
        )
        tunnel_ref["instance"] = tun
        session.tunnels[tunnel_id] = tun
        return tun.to_dict()
    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Could not bind local port 127.0.0.1:{req.local_port}: {exc}",
        )


@app.delete("/api/sessions/{session_id}/tunnels/{tunnel_id}")
async def delete_session_tunnel(session_id: str, tunnel_id: str):
    session = SESSIONS.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    tun = session.tunnels.pop(tunnel_id, None)
    if tun:
        tun.close()
    return {"status": "closed"}


# ---------------------------------------------------------------------------
# WebSocket Interactive PTY Terminal
# ---------------------------------------------------------------------------
@app.websocket("/ws/ssh/{session_id}")
async def ssh_websocket(
    websocket: WebSocket,
    session_id: str,
    cols: int = Query(default=100),
    rows: int = Query(default=30),
):
    await websocket.accept()
    session = SESSIONS.get(session_id)
    if not session:
        await websocket.send_json({"type": "error", "message": "SSH session not found or expired."})
        await websocket.close()
        return

    try:
        channel = await asyncio.to_thread(
            session.client.invoke_shell,
            term="xterm-256color",
            width=max(20, cols),
            height=max(5, rows),
        )
        channel.setblocking(False)
        session.channel = channel
        session.ws = websocket
    except Exception as exc:
        await websocket.send_json({"type": "error", "message": f"Failed to open PTY shell: {exc}"})
        await websocket.close()
        return

    stop_event = asyncio.Event()

    async def read_from_ssh():
        import re
        osc7_pattern = re.compile(r"\x1b\]7;file://[^/]*(/[^\x07\x1b]*)(?:\x07|\x1b\\)")

        while not stop_event.is_set():
            try:
                if channel.recv_ready():
                    data = await asyncio.to_thread(channel.recv, 4096)
                    if not data:
                        break
                    text = data.decode("utf-8", errors="replace")
                    # Detect OSC-7 working directory change emitted by shell
                    match = osc7_pattern.search(text)
                    cwd_changed = None
                    if match:
                        cwd_changed = match.group(1) or "/"
                        session.current_dir = cwd_changed
                        text = osc7_pattern.sub("", text)

                    await websocket.send_json(
                        {
                            "type": "output",
                            "data": text,
                            "cwd": cwd_changed,
                        }
                    )
                elif channel.exit_status_ready() and not channel.recv_ready():
                    break
                else:
                    await asyncio.sleep(0.015)
            except Exception:
                break
        stop_event.set()
        try:
            await websocket.send_json({"type": "exit", "message": "\r\n\x1b[1;33m[SSH Session Closed]\x1b[0m\r\n"})
        except Exception:
            pass

    reader_task = asyncio.create_task(read_from_ssh())

    try:
        while not stop_event.is_set():
            msg = await websocket.receive_json()
            msg_type = msg.get("type")
            if msg_type == "input":
                data_str = msg.get("data", "")
                if data_str and not channel.closed:
                    await asyncio.to_thread(channel.send, data_str.encode("utf-8"))
            elif msg_type == "resize":
                c = max(20, int(msg.get("cols", 80)))
                r = max(5, int(msg.get("rows", 24)))
                if not channel.closed:
                    await asyncio.to_thread(channel.resize_pty, width=c, height=r)
            elif msg_type == "ping":
                await websocket.send_json({"type": "pong"})
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        stop_event.set()
        reader_task.cancel()


@app.get("/")
async def index():
    return FileResponse(STATIC_DIR / "index.html")


app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


if __name__ == "__main__":
    import uvicorn

    host = os.environ.get("WEBSSH_HOST", "127.0.0.1")
    port = int(os.environ.get("WEBSSH_PORT", "8090"))
    uvicorn.run(app, host=host, port=port)
