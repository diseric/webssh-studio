// WebSSH Studio — Full-Featured Frontend (SSH2 Terminal, Drag & Drop SFTP, Remote Editor, Telemetry, Playbooks, Tunnels & Vault)

const state = {
  sessions: new Map(), // sessionId -> SessionObject
  activeSessionId: null,
  broadcastMode: false,
  splitMode: false,
  fontSize: 14,
  totalTransferred: 0,
  transfers: [],
  profiles: [],
  playbooks: [],
  activePlaybookCategory: "All",
  editorPath: null,
  liveTailTimer: null,
  telemetryTimer: null,
};

// DOM Elements
const el = {
  sessionTabs: document.getElementById("session-tabs"),
  btnToggleBroadcast: document.getElementById("btn-toggle-broadcast"),
  btnToggleSplit: document.getElementById("btn-toggle-split"),
  btnOpenSshConfig: document.getElementById("btn-open-ssh-config"),
  btnQuickSandbox: document.getElementById("btn-quick-sandbox"),
  btnNewConnection: document.getElementById("btn-new-connection"),
  btnEmptySandbox: document.getElementById("btn-empty-sandbox"),
  btnEmptyCustom: document.getElementById("btn-empty-custom"),
  statusDot: document.getElementById("status-dot"),
  statusText: document.getElementById("status-text"),
  sessionHostBadge: document.getElementById("session-host-badge"),
  jumpHostBadge: document.getElementById("jump-host-badge"),
  termSearchInput: document.getElementById("term-search-input"),
  btnSearchPrev: document.getElementById("btn-search-prev"),
  btnSearchNext: document.getElementById("btn-search-next"),
  btnFontDec: document.getElementById("btn-font-dec"),
  btnFontInc: document.getElementById("btn-font-inc"),
  btnExportLog: document.getElementById("btn-export-log"),
  btnClearTerm: document.getElementById("btn-clear-term"),
  btnDisconnect: document.getElementById("btn-disconnect"),
  // Telemetry HUD
  telemetryHud: document.getElementById("telemetry-hud"),
  hudCpuFill: document.getElementById("hud-cpu-fill"),
  hudCpuVal: document.getElementById("hud-cpu-val"),
  hudRamFill: document.getElementById("hud-ram-fill"),
  hudRamVal: document.getElementById("hud-ram-val"),
  hudDiskFill: document.getElementById("hud-disk-fill"),
  hudDiskVal: document.getElementById("hud-disk-val"),
  hudUptime: document.getElementById("hud-uptime"),
  chkSyncCwd: document.getElementById("chk-sync-cwd"),
  // Terminal Area
  terminalEmptyState: document.getElementById("terminal-empty-state"),
  terminalContainer: document.getElementById("terminal-container"),
  // Sidebar Tabs & Panels
  sidebarTabs: document.querySelectorAll(".sidebar-tab"),
  panelSftp: document.getElementById("tab-panel-sftp"),
  panelPlaybooks: document.getElementById("tab-panel-playbooks"),
  panelTunnels: document.getElementById("tab-panel-tunnels"),
  panelProcesses: document.getElementById("tab-panel-processes"),
  transferCounterBadge: document.getElementById("transfer-counter-badge"),
  tunnelCounterBadge: document.getElementById("tunnel-counter-badge"),
  // SFTP Controls
  remotePathInput: document.getElementById("remote-path-input"),
  btnDownloadDirZip: document.getElementById("btn-download-dir-zip"),
  btnDirUp: document.getElementById("btn-dir-up"),
  btnDirGo: document.getElementById("btn-dir-go"),
  btnDirMkdir: document.getElementById("btn-dir-mkdir"),
  btnDirRefresh: document.getElementById("btn-dir-refresh"),
  dropzone: document.getElementById("dropzone"),
  fileInput: document.getElementById("file-input"),
  btnBrowseFiles: document.getElementById("btn-browse-files"),
  btnQuickCompose: document.getElementById("btn-quick-compose"),
  btnDemoDrop: document.getElementById("btn-demo-drop"),
  chkEchoTerminal: document.getElementById("chk-echo-terminal"),
  transferQueueSection: document.getElementById("transfer-queue-section"),
  transferList: document.getElementById("transfer-list"),
  btnClearTransfers: document.getElementById("btn-clear-transfers"),
  browserCurDir: document.getElementById("browser-cur-dir"),
  remoteFileCount: document.getElementById("remote-file-count"),
  remoteFileList: document.getElementById("remote-file-list"),
  globalDropOverlay: document.getElementById("global-drop-overlay"),
  overlayTargetDir: document.getElementById("overlay-target-dir"),
  // Playbooks
  playbookForm: document.getElementById("playbook-form"),
  btnResetPlaybooks: document.getElementById("btn-reset-playbooks"),
  playbookCategoryBar: document.getElementById("playbook-category-bar"),
  pbName: document.getElementById("pb-name"),
  pbCategory: document.getElementById("pb-category"),
  pbDescription: document.getElementById("pb-description"),
  pbCommand: document.getElementById("pb-command"),
  playbookList: document.getElementById("playbook-list"),
  // Tunnels
  tunnelForm: document.getElementById("tunnel-form"),
  tunLabel: document.getElementById("tun-label"),
  tunLocalPort: document.getElementById("tun-local-port"),
  tunRemoteHost: document.getElementById("tun-remote-host"),
  tunRemotePort: document.getElementById("tun-remote-port"),
  tunnelList: document.getElementById("tunnel-list"),
  // Processes
  btnRefreshTelemetry: document.getElementById("btn-refresh-telemetry"),
  processTbody: document.getElementById("process-tbody"),
  // Connect Modal & Vault
  connectModal: document.getElementById("connect-modal"),
  btnCloseModal: document.getElementById("btn-close-modal"),
  btnCancelModal: document.getElementById("btn-cancel-modal"),
  btnFillSandbox: document.getElementById("btn-fill-sandbox"),
  savedProfilesList: document.getElementById("saved-profiles-list"),
  sshConnectForm: document.getElementById("ssh-connect-form"),
  sshProfileName: document.getElementById("ssh-profile-name"),
  sshHost: document.getElementById("ssh-host"),
  sshPort: document.getElementById("ssh-port"),
  sshUsername: document.getElementById("ssh-username"),
  sshAuthType: document.getElementById("ssh-auth-type"),
  authPasswordGroup: document.getElementById("auth-password-group"),
  sshPassword: document.getElementById("ssh-password"),
  authKeyGroup: document.getElementById("auth-key-group"),
  sshPrivateKey: document.getElementById("ssh-private-key"),
  sshPassphrase: document.getElementById("ssh-passphrase"),
  chkUseJump: document.getElementById("chk-use-jump"),
  chkSaveProfile: document.getElementById("chk-save-profile"),
  jumpHostFields: document.getElementById("jump-host-fields"),
  jumpHost: document.getElementById("jump-host"),
  jumpPort: document.getElementById("jump-port"),
  jumpUsername: document.getElementById("jump-username"),
  jumpPassword: document.getElementById("jump-password"),
  connectError: document.getElementById("connect-error"),
  btnSubmitConnect: document.getElementById("btn-submit-connect"),
  // Editor Modal
  editorModal: document.getElementById("editor-modal"),
  editorFilePath: document.getElementById("editor-file-path"),
  chkLiveTail: document.getElementById("chk-live-tail"),
  editorSaveStatus: document.getElementById("editor-save-status"),
  btnCloseEditor: document.getElementById("btn-close-editor"),
  btnCancelEditor: document.getElementById("btn-cancel-editor"),
  btnSaveEditor: document.getElementById("btn-save-editor"),
  editorImagePreview: document.getElementById("editor-image-preview"),
  editorImgEl: document.getElementById("editor-img-el"),
  editorTextWrapper: document.getElementById("editor-text-wrapper"),
  editorTextarea: document.getElementById("editor-textarea"),
  // Compose Modal
  composeModal: document.getElementById("compose-modal"),
  btnCloseCompose: document.getElementById("btn-close-compose"),
  btnCancelCompose: document.getElementById("btn-cancel-compose"),
  composeFileForm: document.getElementById("compose-file-form"),
  composeFilename: document.getElementById("compose-filename"),
  composeContent: document.getElementById("compose-content"),
  // SSH Config Modal
  sshConfigModal: document.getElementById("ssh-config-modal"),
  btnCloseSshConfig: document.getElementById("btn-close-ssh-config"),
  btnCancelSshConfig: document.getElementById("btn-cancel-ssh-config"),
  btnConfirmSshConfig: document.getElementById("btn-confirm-ssh-config"),
  sshConfigTextarea: document.getElementById("ssh-config-textarea"),
};

function formatBytes(bytes) {
  if (!bytes || bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + " " + sizes[i];
}

function formatUptime(sec) {
  if (!sec || sec < 0) return "--";
  const h = Math.floor(sec / 3600);
  const m = Math.floor((sec % 3600) / 60);
  const s = sec % 60;
  if (h > 24) return `${Math.floor(h / 24)}d ${h % 24}h`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m ${s}s`;
}

function getActiveSession() {
  if (!state.activeSessionId) return null;
  return state.sessions.get(state.activeSessionId) || null;
}

const TERMINAL_THEMES = {
  obsidian: {
    background: "#090d16",
    foreground: "#f8fafc",
    cursor: "#10b981",
    selectionBackground: "rgba(59, 130, 246, 0.35)",
    black: "#0f172a",
    red: "#ef4444",
    green: "#10b981",
    yellow: "#f59e0b",
    blue: "#3b82f6",
    magenta: "#a855f7",
    cyan: "#06b6d4",
    white: "#f1f5f9",
  },
  cyber: {
    background: "#020503",
    foreground: "#00ff9d",
    cursor: "#ffb800",
    selectionBackground: "rgba(0, 255, 157, 0.28)",
    black: "#030705",
    red: "#ff4d6d",
    green: "#00ff9d",
    yellow: "#ffb800",
    blue: "#00e5ff",
    magenta: "#ff70a6",
    cyan: "#00f5d4",
    white: "#d1fae5",
  },
  nordic: {
    background: "#1e293b",
    foreground: "#f8fafc",
    cursor: "#38bdf8",
    selectionBackground: "rgba(99, 102, 241, 0.4)",
    black: "#0f172a",
    red: "#fb7185",
    green: "#34d399",
    yellow: "#fbbf24",
    blue: "#818cf8",
    magenta: "#c084fc",
    cyan: "#38bdf8",
    white: "#f1f5f9",
  },
};

function applyAppDesign(designName) {
  const valid = ["obsidian", "cyber", "nordic"].includes(designName) ? designName : "obsidian";
  document.body.setAttribute("data-design", valid);
  try {
    localStorage.setItem("webssh_design", valid);
  } catch (_) {}

  document.querySelectorAll(".design-btn").forEach((btn) => {
    btn.classList.toggle("active", btn.getAttribute("data-design") === valid);
  });

  const themeObj = TERMINAL_THEMES[valid] || TERMINAL_THEMES.obsidian;
  for (const s of state.sessions.values()) {
    if (s.termWidget && s.termWidget.isXterm && s.termWidget.term) {
      s.termWidget.term.options.theme = themeObj;
    }
  }

  // Re-fit terminals after layout change (e.g. Cyber Deck full-width vs Split sidebar)
  setTimeout(() => {
    updateTerminalVisibility();
  }, 50);
}

// ---------------------------------------------------------------------------
// Terminal Creation (xterm.js + FitAddon + SearchAddon + WebLinksAddon)
// ---------------------------------------------------------------------------
function createTerminalWidget(mountEl) {
  const currentDesign = document.body.getAttribute("data-design") || "obsidian";
  const initialTheme = TERMINAL_THEMES[currentDesign] || TERMINAL_THEMES.obsidian;
  if (window.Terminal) {
    const term = new window.Terminal({
      cursorBlink: true,
      fontSize: state.fontSize,
      fontFamily: "'JetBrains Mono', Consolas, 'Courier New', monospace",
      theme: initialTheme,
      allowProposedApi: true,
    });

    let fitAddon = null;
    let searchAddon = null;
    if (window.FitAddon && window.FitAddon.FitAddon) {
      fitAddon = new window.FitAddon.FitAddon();
      term.loadAddon(fitAddon);
    }
    if (window.SearchAddon && window.SearchAddon.SearchAddon) {
      searchAddon = new window.SearchAddon.SearchAddon();
      term.loadAddon(searchAddon);
    }
    if (window.WebLinksAddon && window.WebLinksAddon.WebLinksAddon) {
      term.loadAddon(new window.WebLinksAddon.WebLinksAddon());
    }

    term.open(mountEl);
    if (fitAddon) {
      try {
        fitAddon.fit();
      } catch (_) {}
    }

    return {
      isXterm: true,
      term,
      fitAddon,
      searchAddon,
      write(data) {
        term.write(data);
      },
      clear() {
        term.clear();
      },
      focus() {
        term.focus();
      },
      findNext(q) {
        if (searchAddon && q) searchAddon.findNext(q);
      },
      findPrevious(q) {
        if (searchAddon && q) searchAddon.findPrevious(q);
      },
      setFontSize(sz) {
        term.options.fontSize = sz;
        if (fitAddon) {
          try {
            fitAddon.fit();
          } catch (_) {}
        }
      },
      fit() {
        if (fitAddon) {
          try {
            fitAddon.fit();
          } catch (_) {}
        }
      },
      getDimensions() {
        return { cols: term.cols || 100, rows: term.rows || 30 };
      },
      onData(cb) {
        term.onData(cb);
      },
      dispose() {
        term.dispose();
      },
    };
  }

  // Fallback interactive DOM terminal
  const pre = document.createElement("div");
  pre.className = "fallback-terminal";
  pre.tabIndex = 0;
  mountEl.appendChild(pre);
  let dataHandler = null;

  pre.addEventListener("keydown", (e) => {
    if (!dataHandler) return;
    if (e.key === "Enter") {
      e.preventDefault();
      dataHandler("\r");
    } else if (e.key === "Backspace") {
      e.preventDefault();
      dataHandler("\x7f");
    } else if (e.key.length === 1 && !e.ctrlKey && !e.metaKey) {
      e.preventDefault();
      dataHandler(e.key);
    } else if (e.ctrlKey && e.key.toLowerCase() === "c") {
      e.preventDefault();
      dataHandler("\x03");
    }
  });

  return {
    isXterm: false,
    write(data) {
      const clean = data.replace(/\x1b\[[0-9;]*[a-zA-Z]/g, "");
      pre.textContent += clean;
      pre.scrollTop = pre.scrollHeight;
    },
    clear() {
      pre.textContent = "";
    },
    focus() {
      pre.focus();
    },
    findNext() {},
    findPrevious() {},
    setFontSize(sz) {
      pre.style.fontSize = `${sz}px`;
    },
    fit() {},
    getDimensions() {
      return { cols: 100, rows: 30 };
    },
    onData(cb) {
      dataHandler = cb;
    },
    dispose() {
      pre.remove();
    },
  };
}

// ---------------------------------------------------------------------------
// SSH Session Lifecycle & Multi-Tab / Broadcast / Split Support
// ---------------------------------------------------------------------------
async function connectSSH(config) {
  el.connectError.classList.add("hidden");
  el.btnSubmitConnect.disabled = true;
  el.btnSubmitConnect.textContent = "Connecting...";
  updateStatusUI("connecting", `Connecting to ${config.username}@${config.host}:${config.port}...`);

  try {
    // Optionally save to Encrypted Vault if requested
    if (el.chkSaveProfile && el.chkSaveProfile.checked && !config.profile_id) {
      await fetch("/api/profiles", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: el.sshProfileName.value.trim() || `${config.username}@${config.host}`,
          tag: config.use_jump_host ? "Bastion" : "Server",
          host: config.host,
          port: config.port,
          username: config.username,
          auth_type: config.auth_type,
          password: config.password,
          private_key: config.private_key,
          passphrase: config.passphrase,
          use_jump_host: config.use_jump_host,
          jump_host: config.jump_host,
          jump_port: config.jump_port,
          jump_username: config.jump_username,
        }),
      });
      await loadVaultProfiles();
    }

    const resp = await fetch("/api/sessions", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(config),
    });
    const data = await resp.json();
    if (!resp.ok) {
      throw new Error(data.detail || "Connection failed");
    }

    const sessionId = data.session_id;
    const mountWrapper = document.createElement("div");
    mountWrapper.className = "term-slot";
    el.terminalContainer.appendChild(mountWrapper);

    const termWidget = createTerminalWidget(mountWrapper);
    const dims = termWidget.getDimensions();

    const wsProto = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = `${wsProto}//${window.location.host}/ws/ssh/${sessionId}?cols=${dims.cols}&rows=${dims.rows}`;
    const ws = new WebSocket(wsUrl);

    const sessionObj = {
      id: sessionId,
      host: data.host,
      port: data.port,
      username: data.username,
      jumpHost: data.jump_host || null,
      currentDir: data.current_dir || "/",
      mountWrapper,
      termWidget,
      ws,
      connected: true,
      files: [],
      tunnels: [],
      transcript: "",
    };

    ws.onopen = () => {
      termWidget.fit();
      const d = termWidget.getDimensions();
      ws.send(JSON.stringify({ type: "resize", cols: d.cols, rows: d.rows }));
      termWidget.focus();
    };

    ws.onmessage = async (evt) => {
      try {
        const msg = JSON.parse(evt.data);
        if (msg.type === "output") {
          termWidget.write(msg.data);
          // Strip ANSI codes for plain-text session transcript export
          sessionObj.transcript += msg.data.replace(/\x1b\[[0-9;]*[a-zA-Z]/g, "");

          // Feature 2: Auto-Sync SFTP Browser when shell emits OSC-7 cwd change
          if (msg.cwd && el.chkSyncCwd.checked) {
            sessionObj.currentDir = msg.cwd;
            if (state.activeSessionId === sessionId) {
              await refreshRemoteFiles(sessionId, msg.cwd);
            }
          }
        } else if (msg.type === "exit") {
          termWidget.write(msg.message || "\r\n[Disconnected]\r\n");
          sessionObj.connected = false;
          if (state.activeSessionId === sessionId) {
            updateStatusUI("disconnected", "Session ended");
          }
          renderTabs();
        } else if (msg.type === "error") {
          termWidget.write(`\r\n\x1b[1;31m[Error] ${msg.message}\x1b[0m\r\n`);
        }
      } catch (_) {}
    };

    ws.onclose = () => {
      sessionObj.connected = false;
      if (state.activeSessionId === sessionId) {
        updateStatusUI("disconnected", "Disconnected");
      }
      renderTabs();
    };

    termWidget.onData((inputData) => {
      // Feature 2: Broadcast Mode sends input to all open SSH sessions simultaneously!
      if (state.broadcastMode) {
        for (const s of state.sessions.values()) {
          if (s.ws && s.ws.readyState === WebSocket.OPEN) {
            s.ws.send(JSON.stringify({ type: "input", data: inputData }));
          }
        }
      } else if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: "input", data: inputData }));
      }
    });

    state.sessions.set(sessionId, sessionObj);
    closeConnectModal();
    activateSession(sessionId);
    await refreshRemoteFiles(sessionId, sessionObj.currentDir);
    await refreshTunnels(sessionId);
    await refreshTelemetry(sessionId);
  } catch (err) {
    updateStatusUI("disconnected", "Connection failed");
    el.connectError.textContent = err.message;
    el.connectError.classList.remove("hidden");
  } finally {
    el.btnSubmitConnect.disabled = false;
    el.btnSubmitConnect.textContent = "Connect via SSH";
  }
}

function updateTerminalVisibility() {
  const allIds = Array.from(state.sessions.keys());
  el.terminalContainer.classList.toggle("split-mode", state.splitMode && allIds.length >= 2);

  let secondId = null;
  if (state.splitMode && allIds.length >= 2) {
    secondId = allIds.find((id) => id !== state.activeSessionId) || null;
  }

  for (const [id, sess] of state.sessions.entries()) {
    const visible = id === state.activeSessionId || id === secondId;
    sess.mountWrapper.classList.toggle("hidden", !visible);
    if (visible) {
      setTimeout(() => {
        sess.termWidget.fit();
        const d = sess.termWidget.getDimensions();
        if (sess.ws && sess.ws.readyState === WebSocket.OPEN) {
          sess.ws.send(JSON.stringify({ type: "resize", cols: d.cols, rows: d.rows }));
        }
      }, 25);
    }
  }
}

function activateSession(sessionId) {
  state.activeSessionId = sessionId;
  updateTerminalVisibility();

  const active = getActiveSession();
  if (active) {
    active.termWidget.focus();
    el.terminalEmptyState.classList.add("hidden");
    el.telemetryHud.classList.remove("hidden");
    el.btnDisconnect.classList.remove("hidden");
    el.sessionHostBadge.textContent = `${active.username}@${active.host}:${active.port}`;
    el.sessionHostBadge.classList.remove("hidden");
    if (active.jumpHost) {
      el.jumpHostBadge.textContent = `via ${active.jumpHost}`;
      el.jumpHostBadge.classList.remove("hidden");
    } else {
      el.jumpHostBadge.classList.add("hidden");
    }
    updateStatusUI(
      active.connected ? "connected" : "disconnected",
      active.connected ? "Connected (SSH2 + SFTP)" : "Disconnected"
    );
    el.remotePathInput.value = active.currentDir;
    el.browserCurDir.textContent = active.currentDir;
    el.overlayTargetDir.textContent = active.currentDir;
    renderRemoteFiles(active.files);
    renderTunnels(active.tunnels || []);
    refreshTelemetry(active.id);
  } else {
    el.terminalEmptyState.classList.remove("hidden");
    el.telemetryHud.classList.add("hidden");
    el.btnDisconnect.classList.add("hidden");
    el.sessionHostBadge.classList.add("hidden");
    el.jumpHostBadge.classList.add("hidden");
    updateStatusUI("disconnected", "Not connected");
    el.remoteFileList.innerHTML = `<div class="empty-files-msg">Connect to an SSH session to browse, edit, and transfer files.</div>`;
    el.remoteFileCount.textContent = "0 items";
    renderTunnels([]);
  }

  renderTabs();
}

async function disconnectSession(sessionId) {
  const sess = state.sessions.get(sessionId);
  if (!sess) return;
  try {
    if (sess.ws && sess.ws.readyState === WebSocket.OPEN) {
      sess.ws.close();
    }
  } catch (_) {}
  try {
    sess.termWidget.dispose();
    sess.mountWrapper.remove();
  } catch (_) {}
  state.sessions.delete(sessionId);

  try {
    await fetch(`/api/sessions/${sessionId}`, { method: "DELETE" });
  } catch (_) {}

  if (state.activeSessionId === sessionId) {
    const remaining = Array.from(state.sessions.keys());
    activateSession(remaining.length ? remaining[remaining.length - 1] : null);
  } else {
    updateTerminalVisibility();
    renderTabs();
  }
}

function renderTabs() {
  el.sessionTabs.innerHTML = "";
  for (const [id, sess] of state.sessions.entries()) {
    const tab = document.createElement("div");
    tab.className = `session-tab ${id === state.activeSessionId ? "active" : ""}`;
    tab.setAttribute("role", "tab");

    const dot = document.createElement("span");
    dot.className = "tab-dot";
    if (!sess.connected) {
      dot.style.background = "#64748b";
    }

    const label = document.createElement("span");
    label.textContent = `${sess.username}@${sess.host}:${sess.port}`;

    const closeBtn = document.createElement("button");
    closeBtn.className = "tab-close";
    closeBtn.textContent = "✕";
    closeBtn.title = "Close session";
    closeBtn.addEventListener("click", (e) => {
      e.stopPropagation();
      disconnectSession(id);
    });

    tab.append(dot, label, closeBtn);
    tab.addEventListener("click", () => activateSession(id));
    el.sessionTabs.appendChild(tab);
  }
}

function updateStatusUI(status, text) {
  el.statusDot.className = `status-dot ${status}`;
  el.statusText.textContent = text;
}

// ---------------------------------------------------------------------------
// Feature 1: SFTP Remote File Browser, In-Browser Code Editor, & Zip Download
// ---------------------------------------------------------------------------
async function refreshRemoteFiles(sessionId, targetPath = ".") {
  const sess = state.sessions.get(sessionId);
  if (!sess) return;
  try {
    const resp = await fetch(
      `/api/sessions/${sessionId}/files?path=${encodeURIComponent(targetPath)}`
    );
    const data = await resp.json();
    if (!resp.ok) {
      throw new Error(data.detail || "Failed to list directory");
    }
    sess.currentDir = data.current_dir;
    sess.files = data.entries || [];
    if (state.activeSessionId === sessionId) {
      el.remotePathInput.value = sess.currentDir;
      el.browserCurDir.textContent = sess.currentDir;
      el.overlayTargetDir.textContent = sess.currentDir;
      renderRemoteFiles(sess.files);
    }
  } catch (err) {
    console.error("SFTP list error:", err);
  }
}

function renderRemoteFiles(entries) {
  el.remoteFileCount.textContent = `${entries.length} item${entries.length === 1 ? "" : "s"}`;
  if (!entries.length) {
    el.remoteFileList.innerHTML = `<div class="empty-files-msg">Directory is empty. Drag &amp; drop files above to upload here!</div>`;
    return;
  }

  el.remoteFileList.innerHTML = "";
  for (const item of entries) {
    const row = document.createElement("div");
    row.className = `file-row ${item.is_dir ? "is-dir" : ""}`;
    row.setAttribute("role", "listitem");

    const info = document.createElement("div");
    info.className = "file-info";
    info.innerHTML = `
      <span class="file-icon">${item.is_dir ? "📂" : "📄"}</span>
      <div class="file-details">
        <div class="file-name" title="${item.path}">${item.name}${item.is_dir ? "/" : ""}</div>
        <div class="file-sub">${item.permissions} • ${item.is_dir ? "Directory" : formatBytes(item.size)}</div>
      </div>
    `;

    info.addEventListener("click", () => {
      const active = getActiveSession();
      if (!active) return;
      if (item.is_dir) {
        refreshRemoteFiles(active.id, item.path);
      } else {
        openRemoteFileEditor(item.path, false);
      }
    });

    const actions = document.createElement("div");
    actions.className = "file-actions";

    if (item.is_dir) {
      const zipBtn = document.createElement("button");
      zipBtn.className = "file-action-btn";
      zipBtn.textContent = "📦 Zip";
      zipBtn.title = "Download directory as .zip archive";
      zipBtn.addEventListener("click", (e) => {
        e.stopPropagation();
        const active = getActiveSession();
        if (!active) return;
        window.open(
          `/api/sessions/${active.id}/download-zip?path=${encodeURIComponent(item.path)}`,
          "_blank"
        );
      });
      actions.appendChild(zipBtn);
    } else {
      const editBtn = document.createElement("button");
      editBtn.className = "file-action-btn";
      editBtn.textContent = "✏️ Edit";
      editBtn.title = "Open in Remote File Editor (or preview image / tail log)";
      editBtn.addEventListener("click", (e) => {
        e.stopPropagation();
        openRemoteFileEditor(item.path, item.name.endsWith(".log"));
      });

      const catBtn = document.createElement("button");
      catBtn.className = "file-action-btn";
      catBtn.textContent = "cat";
      catBtn.title = "Print file contents in SSH terminal";
      catBtn.addEventListener("click", (e) => {
        e.stopPropagation();
        sendTerminalCommand(`cat "${item.name}"`);
      });

      const dlBtn = document.createElement("button");
      dlBtn.className = "file-action-btn";
      dlBtn.textContent = "⬇";
      dlBtn.title = "Download file from remote server";
      dlBtn.addEventListener("click", (e) => {
        e.stopPropagation();
        const active = getActiveSession();
        if (!active) return;
        window.open(
          `/api/sessions/${active.id}/download?path=${encodeURIComponent(item.path)}`,
          "_blank"
        );
      });

      actions.append(editBtn, catBtn, dlBtn);
    }

    const delBtn = document.createElement("button");
    delBtn.className = "file-action-btn delete";
    delBtn.textContent = "🗑";
    delBtn.title = "Delete from remote server";
    delBtn.addEventListener("click", async (e) => {
      e.stopPropagation();
      const active = getActiveSession();
      if (!active) return;
      try {
        const resp = await fetch(
          `/api/sessions/${active.id}/files?path=${encodeURIComponent(item.path)}`,
          { method: "DELETE" }
        );
        if (resp.ok) {
          await refreshRemoteFiles(active.id, active.currentDir);
        }
      } catch (_) {}
    });

    actions.appendChild(delBtn);
    row.append(info, actions);
    el.remoteFileList.appendChild(row);
  }
}

async function openRemoteFileEditor(remotePath, autoTail = false) {
  const active = getActiveSession();
  if (!active) return;

  state.editorPath = remotePath;
  el.editorFilePath.textContent = remotePath;
  el.editorSaveStatus.textContent = "Loading...";
  el.editorModal.classList.remove("hidden");
  el.chkLiveTail.checked = Boolean(autoTail);

  await fetchEditorContent();
  setupLiveTailTimer();
}

async function fetchEditorContent() {
  const active = getActiveSession();
  if (!active || !state.editorPath) return;

  try {
    const resp = await fetch(
      `/api/sessions/${active.id}/file-content?path=${encodeURIComponent(state.editorPath)}`
    );
    const data = await resp.json();
    if (!resp.ok) {
      throw new Error(data.detail || "Failed to read file");
    }

    if (data.kind === "image") {
      el.editorImagePreview.classList.remove("hidden");
      el.editorTextWrapper.classList.add("hidden");
      el.btnSaveEditor.classList.add("hidden");
      el.editorImgEl.src = data.data_uri;
      el.editorSaveStatus.textContent = `Image (${formatBytes(data.size)})`;
    } else {
      el.editorImagePreview.classList.add("hidden");
      el.editorTextWrapper.classList.remove("hidden");
      el.btnSaveEditor.classList.remove("hidden");
      el.editorTextarea.value = data.content;
      el.editorSaveStatus.textContent = `${formatBytes(data.size)}`;
      if (el.chkLiveTail.checked) {
        el.editorTextarea.scrollTop = el.editorTextarea.scrollHeight;
      }
    }
  } catch (err) {
    el.editorSaveStatus.textContent = `Error: ${err.message}`;
  }
}

async function saveRemoteFileEditor() {
  const active = getActiveSession();
  if (!active || !state.editorPath) return;
  el.editorSaveStatus.textContent = "Saving...";
  try {
    const resp = await fetch(`/api/sessions/${active.id}/file-content`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        path: state.editorPath,
        content: el.editorTextarea.value,
      }),
    });
    const data = await resp.json();
    if (!resp.ok) {
      throw new Error(data.detail || "Save failed");
    }
    el.editorSaveStatus.textContent = `✓ Saved (${formatBytes(data.size)})`;
    await refreshRemoteFiles(active.id, active.currentDir);
  } catch (err) {
    el.editorSaveStatus.textContent = `✕ ${err.message}`;
  }
}

function setupLiveTailTimer() {
  if (state.liveTailTimer) {
    clearInterval(state.liveTailTimer);
    state.liveTailTimer = null;
  }
  if (el.chkLiveTail.checked && !el.editorModal.classList.contains("hidden")) {
    state.liveTailTimer = setInterval(fetchEditorContent, 2000);
  }
}

function closeEditorModal() {
  el.editorModal.classList.add("hidden");
  el.chkLiveTail.checked = false;
  setupLiveTailTimer();
}

// ---------------------------------------------------------------------------
// Drag and Drop SFTP File Transfer Engine
// ---------------------------------------------------------------------------
async function extractDroppedFiles(dataTransfer) {
  const results = [];

  async function traverseEntry(entry, prefix = "") {
    if (!entry) return;
    if (entry.isFile) {
      const file = await new Promise((resolve, reject) => entry.file(resolve, reject));
      results.push({ file, relativePath: prefix ? `${prefix}/${file.name}` : file.name });
    } else if (entry.isDirectory) {
      const reader = entry.createReader();
      const entries = await new Promise((resolve, reject) =>
        reader.readEntries(resolve, reject)
      );
      for (const child of entries) {
        await traverseEntry(child, prefix ? `${prefix}/${entry.name}` : entry.name);
      }
    }
  }

  if (dataTransfer.items && dataTransfer.items.length > 0) {
    const entries = [];
    for (let i = 0; i < dataTransfer.items.length; i++) {
      const item = dataTransfer.items[i];
      if (item.kind === "file") {
        const entry = item.webkitGetAsEntry ? item.webkitGetAsEntry() : null;
        if (entry) {
          entries.push(entry);
        } else {
          const f = item.getAsFile();
          if (f) results.push({ file: f, relativePath: f.name });
        }
      }
    }
    for (const entry of entries) {
      await traverseEntry(entry, "");
    }
  } else if (dataTransfer.files && dataTransfer.files.length > 0) {
    for (const f of dataTransfer.files) {
      results.push({ file: f, relativePath: f.webkitRelativePath || f.name });
    }
  }

  return results;
}

async function uploadFilesToActiveSession(fileItems) {
  if (!fileItems || !fileItems.length) return;

  if (!getActiveSession()) {
    openConnectModal();
    return;
  }

  const active = getActiveSession();
  if (!active) return;

  const targetDir = el.remotePathInput.value.trim() || active.currentDir || "/";
  const transferRecords = fileItems.map((item) => {
    const rec = {
      id: Math.random().toString(36).slice(2),
      name: item.relativePath || item.file.name,
      size: item.file.size,
      remotePath: `${targetDir === "/" ? "" : targetDir}/${item.relativePath || item.file.name}`,
      status: "uploading",
      progress: 0,
    };
    state.transfers.unshift(rec);
    return rec;
  });

  renderTransferQueue();

  const formData = new FormData();
  formData.append("target_dir", targetDir);
  formData.append(
    "relative_paths",
    JSON.stringify(fileItems.map((i) => i.relativePath || i.file.name))
  );
  for (const item of fileItems) {
    formData.append("files", item.file, item.file.name);
  }

  await new Promise((resolve) => {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", `/api/sessions/${active.id}/upload`);

    xhr.upload.onprogress = (evt) => {
      if (evt.lengthComputable) {
        const pct = Math.round((evt.loaded / evt.total) * 100);
        for (const rec of transferRecords) {
          rec.progress = pct;
        }
        renderTransferQueue();
      }
    };

    xhr.onload = async () => {
      if (xhr.status >= 200 && xhr.status < 300) {
        let respData = {};
        try {
          respData = JSON.parse(xhr.responseText);
        } catch (_) {}

        for (const rec of transferRecords) {
          rec.status = "done";
          rec.progress = 100;
        }
        state.totalTransferred += transferRecords.length;
        el.transferCounterBadge.textContent = `${state.totalTransferred}`;
        renderTransferQueue();

        await refreshRemoteFiles(active.id, targetDir);

        if (el.chkEchoTerminal.checked) {
          const uploadedNames = (respData.uploaded || [])
            .map((u) => u.remote_path)
            .join(", ");
          active.termWidget.write(
            `\r\n\x1b[1;32m[SFTP Transfer Complete]\x1b[0m Uploaded ${transferRecords.length} file(s) -> \x1b[1;36m${uploadedNames}\x1b[0m\r\n`
          );
          sendTerminalCommand("ls -la");
        }
      } else {
        for (const rec of transferRecords) {
          rec.status = "error";
        }
        renderTransferQueue();
      }
      resolve();
    };

    xhr.onerror = () => {
      for (const rec of transferRecords) {
        rec.status = "error";
      }
      renderTransferQueue();
      resolve();
    };

    xhr.send(formData);
  });
}

function renderTransferQueue() {
  if (!state.transfers.length) {
    el.transferQueueSection.classList.add("hidden");
    return;
  }
  el.transferQueueSection.classList.remove("hidden");
  el.transferList.innerHTML = "";

  for (const item of state.transfers.slice(0, 15)) {
    const div = document.createElement("div");
    div.className = "transfer-item";
    const statusLabel =
      item.status === "done"
        ? "✓ Transferred"
        : item.status === "error"
        ? "✕ Failed"
        : `${item.progress}%`;

    div.innerHTML = `
      <div class="transfer-item-top">
        <span class="transfer-name" title="${item.remotePath}">${item.name}</span>
        <span class="transfer-status ${item.status}">${statusLabel}</span>
      </div>
      <div class="progress-bar-track">
        <div class="progress-bar-fill" style="width: ${item.progress}%"></div>
      </div>
      <div class="transfer-meta">
        <span>→ ${item.remotePath}</span>
        <span>${formatBytes(item.size)}</span>
      </div>
    `;
    el.transferList.appendChild(div);
  }
}

function sendTerminalCommand(cmd) {
  if (state.broadcastMode) {
    for (const s of state.sessions.values()) {
      if (s.ws && s.ws.readyState === WebSocket.OPEN) {
        s.ws.send(JSON.stringify({ type: "input", data: cmd + "\r" }));
      }
    }
    const active = getActiveSession();
    if (active) active.termWidget.focus();
    return;
  }

  const active = getActiveSession();
  if (!active || !active.ws || active.ws.readyState !== WebSocket.OPEN) return;
  active.ws.send(JSON.stringify({ type: "input", data: cmd + "\r" }));
  active.termWidget.focus();
}

// ---------------------------------------------------------------------------
// Feature 2: Playbooks Manager (with Parameterized {{var:default}} Support)
// ---------------------------------------------------------------------------
function extractPlaybookVariables(cmdText) {
  const regex = /\{\{([^}:]+)(?::([^}]*))?\}\}/g;
  const vars = [];
  const seen = new Set();
  let match;
  while ((match = regex.exec(cmdText)) !== null) {
    const name = match[1].trim();
    const defVal = match[2] !== undefined ? match[2] : "";
    if (!seen.has(name)) {
      seen.add(name);
      vars.push({ name, defaultValue: defVal });
    }
  }
  return vars;
}

function resolvePlaybookCommand(cmdText, valuesMap) {
  return cmdText.replace(/\{\{([^}:]+)(?::([^}]*))?\}\}/g, (_, rawName, defVal) => {
    const name = rawName.trim();
    if (valuesMap && valuesMap[name] !== undefined && valuesMap[name] !== "") {
      return valuesMap[name];
    }
    return defVal !== undefined ? defVal : "";
  });
}

function openParameterizedPlaybookModal(pb, vars) {
  const modal = document.getElementById("pb-params-modal");
  const title = document.getElementById("pb-params-modal-title");
  const desc = document.getElementById("pb-params-desc");
  const inputsContainer = document.getElementById("pb-params-inputs");
  const previewEl = document.getElementById("pb-params-preview");
  const form = document.getElementById("pb-params-form");

  title.textContent = `⚡ ${pb.name}`;
  desc.textContent = pb.description || "Customize playbook parameters before execution:";
  inputsContainer.innerHTML = "";

  const currentValues = {};
  vars.forEach((v) => {
    currentValues[v.name] = v.defaultValue;
    const grp = document.createElement("div");
    grp.className = "form-group";
    grp.innerHTML = `
      <label>{{${v.name}}}</label>
      <input type="text" data-var="${v.name}" value="${v.defaultValue}" required />
    `;
    const input = grp.querySelector("input");
    input.addEventListener("input", () => {
      currentValues[v.name] = input.value;
      previewEl.textContent = resolvePlaybookCommand(pb.command, currentValues);
    });
    inputsContainer.appendChild(grp);
  });

  previewEl.textContent = resolvePlaybookCommand(pb.command, currentValues);
  modal.classList.remove("hidden");
  const firstInput = inputsContainer.querySelector("input");
  if (firstInput) firstInput.focus();

  form.onsubmit = async (e) => {
    e.preventDefault();
    modal.classList.add("hidden");
    const finalCmd = resolvePlaybookCommand(pb.command, currentValues);
    if (!getActiveSession()) {
      openConnectModal();
      return;
    }
    sendTerminalCommand(finalCmd);
  };
}

async function loadPlaybooks() {
  try {
    const resp = await fetch("/api/playbooks");
    if (!resp.ok) return;
    const data = await resp.json();
    state.playbooks = data.playbooks || [];
    renderPlaybookCategories();
    renderPlaybooks();
  } catch (_) {}
}

function renderPlaybookCategories() {
  if (!el.playbookCategoryBar) return;
  const counts = { All: state.playbooks.length };
  for (const pb of state.playbooks) {
    const cat = pb.category || "Custom";
    counts[cat] = (counts[cat] || 0) + 1;
  }

  el.playbookCategoryBar.innerHTML = "";
  for (const [cat, count] of Object.entries(counts)) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = `cat-pill ${state.activePlaybookCategory === cat ? "active" : ""}`;
    btn.textContent = `${cat} (${count})`;
    btn.addEventListener("click", () => {
      state.activePlaybookCategory = cat;
      renderPlaybookCategories();
      renderPlaybooks();
    });
    el.playbookCategoryBar.appendChild(btn);
  }
}

function renderPlaybooks() {
  el.playbookList.innerHTML = "";
  const filtered =
    state.activePlaybookCategory === "All"
      ? state.playbooks
      : state.playbooks.filter((p) => (p.category || "Custom") === state.activePlaybookCategory);

  for (const pb of filtered) {
    const vars = extractPlaybookVariables(pb.command);
    const card = document.createElement("div");
    card.className = "stack-card";
    card.innerHTML = `
      <div class="stack-card-top">
        <div>
          <span class="stack-card-title">${pb.name}</span>
          <span class="badge">${pb.category || "Script"}</span>
          ${vars.length ? `<span class="badge" style="border-color:#f59e0b;color:#fde68a;">⚡ ${vars.length} param${vars.length > 1 ? "s" : ""}</span>` : ""}
        </div>
        <div class="file-actions">
          <button class="btn btn-emerald btn-xs run-pb-btn">${vars.length ? "⚡ Configure & Run" : "▶ Run"}</button>
          <button class="file-action-btn delete del-pb-btn" title="Delete playbook">🗑</button>
        </div>
      </div>
      ${pb.description ? `<div class="stack-card-desc">${pb.description}</div>` : ""}
      <div class="stack-card-cmd">${pb.command}</div>
    `;
    card.querySelector(".run-pb-btn").addEventListener("click", async () => {
      if (vars.length > 0) {
        openParameterizedPlaybookModal(pb, vars);
      } else {
        if (!getActiveSession()) {
          openConnectModal();
          return;
        }
        sendTerminalCommand(pb.command);
      }
    });
    card.querySelector(".del-pb-btn").addEventListener("click", async () => {
      await fetch(`/api/playbooks/${pb.id}`, { method: "DELETE" });
      await loadPlaybooks();
    });
    el.playbookList.appendChild(card);
  }
}

// ---------------------------------------------------------------------------
// Feature 3: Live Server Telemetry & Process Inspector
// ---------------------------------------------------------------------------
async function refreshTelemetry(sessionId) {
  const targetId = sessionId || state.activeSessionId;
  if (!targetId) return;
  const sess = state.sessions.get(targetId);
  if (!sess || !sess.connected) return;

  try {
    const resp = await fetch(`/api/sessions/${targetId}/telemetry`);
    if (!resp.ok) return;
    const t = await resp.json();
    if (state.activeSessionId !== targetId) return;

    el.hudCpuFill.style.width = `${Math.min(100, t.cpu_percent)}%`;
    el.hudCpuVal.textContent = `${t.cpu_percent}%`;

    el.hudRamFill.style.width = `${Math.min(100, t.mem_percent)}%`;
    el.hudRamVal.textContent = `${t.mem_percent}% (${formatBytes(t.mem_used)})`;

    el.hudDiskFill.style.width = `${Math.min(100, t.disk_percent)}%`;
    el.hudDiskVal.textContent = `${t.disk_percent}%`;

    el.hudUptime.textContent = `Uptime: ${formatUptime(t.uptime_seconds)}`;

    const procs = t.processes || [];
    if (!procs.length) {
      el.processTbody.innerHTML = `<tr><td colspan="4" class="empty-files-msg">No processes reported.</td></tr>`;
    } else {
      el.processTbody.innerHTML = procs
        .map(
          (p) => `
          <tr>
            <td>${p.pid}</td>
            <td>${p.name}</td>
            <td>${p.cpu}%</td>
            <td>${p.mem}%</td>
          </tr>
        `
        )
        .join("");
    }
  } catch (_) {}
}

// ---------------------------------------------------------------------------
// Feature 4: Encrypted Profile Vault, SSH Config Importer & Port Tunnels
// ---------------------------------------------------------------------------
async function loadVaultProfiles() {
  try {
    const resp = await fetch("/api/profiles");
    const data = await resp.json();
    state.profiles = data.profiles || [];
    renderVaultProfiles();
  } catch (_) {}
}

function renderVaultProfiles() {
  el.savedProfilesList.innerHTML = "";
  for (const prof of state.profiles) {
    const pill = document.createElement("div");
    pill.className = "profile-pill";
    pill.innerHTML = `
      <span>🔐 <strong>${prof.name}</strong> <small>(${prof.username}@${prof.host}:${prof.port})</small></span>
      <button type="button" class="btn btn-xs btn-primary connect-prof-btn">Connect</button>
    `;
    pill.addEventListener("click", () => {
      el.sshProfileName.value = prof.name;
      el.sshHost.value = prof.host;
      el.sshPort.value = prof.port;
      el.sshUsername.value = prof.username;
      el.sshAuthType.value = prof.auth_type || "password";
      el.chkUseJump.checked = Boolean(prof.use_jump_host);
      el.jumpHostFields.classList.toggle("hidden", !prof.use_jump_host);
      el.jumpHost.value = prof.jump_host || "";
      el.jumpPort.value = prof.jump_port || 22;
      el.jumpUsername.value = prof.jump_username || "";
    });
    pill.querySelector(".connect-prof-btn").addEventListener("click", async (e) => {
      e.stopPropagation();
      await connectSSH({
        profile_id: prof.id,
        host: prof.host,
        port: prof.port,
        username: prof.username,
        auth_type: prof.auth_type || "password",
        use_jump_host: Boolean(prof.use_jump_host),
        jump_host: prof.jump_host || "",
        jump_port: prof.jump_port || 22,
        jump_username: prof.jump_username || "",
      });
    });
    el.savedProfilesList.appendChild(pill);
  }
}

async function refreshTunnels(sessionId) {
  const targetId = sessionId || state.activeSessionId;
  if (!targetId) return;
  const sess = state.sessions.get(targetId);
  if (!sess) return;
  try {
    const resp = await fetch(`/api/sessions/${targetId}/tunnels`);
    if (!resp.ok) return;
    const data = await resp.json();
    sess.tunnels = data.tunnels || [];
    if (state.activeSessionId === targetId) {
      renderTunnels(sess.tunnels);
    }
  } catch (_) {}
}

function renderTunnels(tunnels) {
  el.tunnelCounterBadge.textContent = `${tunnels.length}`;
  if (!tunnels.length) {
    el.tunnelList.innerHTML = `<div class="empty-files-msg">No active port tunnels for this session.</div>`;
    return;
  }

  el.tunnelList.innerHTML = "";
  for (const tun of tunnels) {
    const card = document.createElement("div");
    card.className = "stack-card";
    card.innerHTML = `
      <div class="stack-card-top">
        <div>
          <span class="stack-card-title">🚇 ${tun.label}</span>
          <span class="badge">Active</span>
        </div>
        <div class="file-actions">
          <a href="http://127.0.0.1:${tun.local_port}" target="_blank" class="btn btn-xs btn-outline">🔗 Open</a>
          <button class="file-action-btn delete close-tun-btn" title="Stop tunnel">✕</button>
        </div>
      </div>
      <div class="stack-card-cmd">127.0.0.1:${tun.local_port} ➔ ${tun.remote_host}:${tun.remote_port}</div>
      <div class="transfer-meta">
        <span>Active conns: ${tun.active_connections}</span>
        <span>Traffic: ${formatBytes(tun.bytes_transferred)}</span>
      </div>
    `;
    card.querySelector(".close-tun-btn").addEventListener("click", async () => {
      const active = getActiveSession();
      if (!active) return;
      await fetch(`/api/sessions/${active.id}/tunnels/${tun.tunnel_id}`, {
        method: "DELETE",
      });
      await refreshTunnels(active.id);
    });
    el.tunnelList.appendChild(card);
  }
}

// ---------------------------------------------------------------------------
// Event Listeners & UI Wiring
// ---------------------------------------------------------------------------
function openConnectModal() {
  el.connectError.classList.add("hidden");
  loadVaultProfiles();
  el.connectModal.classList.remove("hidden");
  el.sshHost.focus();
}

function closeConnectModal() {
  el.connectModal.classList.add("hidden");
}

el.btnNewConnection.addEventListener("click", openConnectModal);
el.btnEmptyCustom.addEventListener("click", openConnectModal);
el.btnCloseModal.addEventListener("click", closeConnectModal);
el.btnCancelModal.addEventListener("click", closeConnectModal);

// Broadcast & Split Toggles
el.btnToggleBroadcast.addEventListener("click", () => {
  state.broadcastMode = !state.broadcastMode;
  el.btnToggleBroadcast.classList.toggle("active-toggle", state.broadcastMode);
  el.btnToggleBroadcast.textContent = `📡 Broadcast: ${state.broadcastMode ? "ON" : "Off"}`;
});

el.btnToggleSplit.addEventListener("click", () => {
  state.splitMode = !state.splitMode;
  el.btnToggleSplit.classList.toggle("active-toggle", state.splitMode);
  updateTerminalVisibility();
});

// Sidebar Tool Tabs
el.sidebarTabs.forEach((tabBtn) => {
  tabBtn.addEventListener("click", () => {
    const target = tabBtn.getAttribute("data-tab");
    el.sidebarTabs.forEach((b) => {
      const isMatch = b.getAttribute("data-tab") === target;
      b.classList.toggle("active", isMatch);
      b.setAttribute("aria-selected", isMatch ? "true" : "false");
    });
    el.panelSftp.classList.toggle("hidden", target !== "sftp");
    el.panelPlaybooks.classList.toggle("hidden", target !== "playbooks");
    el.panelTunnels.classList.toggle("hidden", target !== "tunnels");
    el.panelProcesses.classList.toggle("hidden", target !== "processes");
    if (target === "processes") {
      refreshTelemetry();
    } else if (target === "tunnels") {
      refreshTunnels();
    }
  });
});

el.sshAuthType.addEventListener("change", () => {
  const isKey = el.sshAuthType.value === "key";
  el.authPasswordGroup.classList.toggle("hidden", isKey);
  el.authKeyGroup.classList.toggle("hidden", !isKey);
});

el.chkUseJump.addEventListener("change", () => {
  el.jumpHostFields.classList.toggle("hidden", !el.chkUseJump.checked);
});

el.sshConnectForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  await connectSSH({
    host: el.sshHost.value.trim(),
    port: parseInt(el.sshPort.value, 10) || 22,
    username: el.sshUsername.value.trim(),
    auth_type: el.sshAuthType.value,
    password: el.sshPassword.value,
    private_key: el.sshPrivateKey.value,
    passphrase: el.sshPassphrase.value,
    use_jump_host: el.chkUseJump.checked,
    jump_host: el.jumpHost.value.trim(),
    jump_port: parseInt(el.jumpPort.value, 10) || 22,
    jump_username: el.jumpUsername.value.trim(),
    jump_password: el.jumpPassword.value,
  });
});

// Terminal Toolbar & Search
document.querySelectorAll(".chip-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    const cmd = btn.getAttribute("data-cmd");
    if (cmd) sendTerminalCommand(cmd);
  });
});

el.termSearchInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") {
    const active = getActiveSession();
    if (active) active.termWidget.findNext(el.termSearchInput.value);
  }
});

el.btnSearchNext.addEventListener("click", () => {
  const active = getActiveSession();
  if (active) active.termWidget.findNext(el.termSearchInput.value);
});

el.btnSearchPrev.addEventListener("click", () => {
  const active = getActiveSession();
  if (active) active.termWidget.findPrevious(el.termSearchInput.value);
});

el.btnFontDec.addEventListener("click", () => {
  state.fontSize = Math.max(10, state.fontSize - 1);
  for (const s of state.sessions.values()) s.termWidget.setFontSize(state.fontSize);
});

el.btnFontInc.addEventListener("click", () => {
  state.fontSize = Math.min(24, state.fontSize + 1);
  for (const s of state.sessions.values()) s.termWidget.setFontSize(state.fontSize);
});

el.btnExportLog.addEventListener("click", () => {
  const active = getActiveSession();
  if (!active) return;
  const blob = new Blob([active.transcript || ""], { type: "text/plain" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `ssh_session_${active.username}_${active.host}.log`;
  a.click();
  URL.revokeObjectURL(url);
});

el.btnClearTerm.addEventListener("click", () => {
  const active = getActiveSession();
  if (active) active.termWidget.clear();
});

el.btnDisconnect.addEventListener("click", () => {
  if (state.activeSessionId) {
    disconnectSession(state.activeSessionId);
  }
});

// Remote Directory Controls & Zip Download
el.btnDownloadDirZip.addEventListener("click", () => {
  const active = getActiveSession();
  if (!active) return;
  const cur = el.remotePathInput.value.trim() || active.currentDir || "/";
  window.open(
    `/api/sessions/${active.id}/download-zip?path=${encodeURIComponent(cur)}`,
    "_blank"
  );
});

el.btnDirGo.addEventListener("click", () => {
  const active = getActiveSession();
  if (active) {
    refreshRemoteFiles(active.id, el.remotePathInput.value.trim() || "/");
  }
});

el.remotePathInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") {
    e.preventDefault();
    const active = getActiveSession();
    if (active) {
      refreshRemoteFiles(active.id, el.remotePathInput.value.trim() || "/");
    }
  }
});

el.btnDirUp.addEventListener("click", () => {
  const active = getActiveSession();
  if (!active) return;
  const cur = active.currentDir || "/";
  const parent = cur === "/" ? "/" : cur.split("/").slice(0, -1).join("/") || "/";
  refreshRemoteFiles(active.id, parent);
});

el.btnDirRefresh.addEventListener("click", () => {
  const active = getActiveSession();
  if (active) refreshRemoteFiles(active.id, active.currentDir);
});

el.btnDirMkdir.addEventListener("click", async () => {
  const active = getActiveSession();
  if (!active) return;
  const folderName = window.prompt("New remote folder name:", "uploads");
  if (!folderName) return;
  const base = active.currentDir === "/" ? "" : active.currentDir;
  const fullPath = `${base}/${folderName.trim()}`;
  await fetch(`/api/sessions/${active.id}/mkdir`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ path: fullPath }),
  });
  await refreshRemoteFiles(active.id, active.currentDir);
});

// Editor Modal Events
el.btnCloseEditor.addEventListener("click", closeEditorModal);
el.btnCancelEditor.addEventListener("click", closeEditorModal);
el.btnSaveEditor.addEventListener("click", saveRemoteFileEditor);
el.chkLiveTail.addEventListener("change", setupLiveTailTimer);

el.editorTextarea.addEventListener("keydown", (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "s") {
    e.preventDefault();
    saveRemoteFileEditor();
  }
});

// Playbook Form & Reset Button
if (el.btnResetPlaybooks) {
  el.btnResetPlaybooks.addEventListener("click", async () => {
    await fetch("/api/playbooks/reset", { method: "POST" });
    state.activePlaybookCategory = "All";
    await loadPlaybooks();
  });
}

el.playbookForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  await fetch("/api/playbooks", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      name: el.pbName.value.trim(),
      category: el.pbCategory.value.trim() || "Custom",
      description: el.pbDescription ? el.pbDescription.value.trim() : "",
      command: el.pbCommand.value.trim(),
    }),
  });
  el.pbName.value = "";
  if (el.pbDescription) el.pbDescription.value = "";
  el.pbCommand.value = "";
  await loadPlaybooks();
});

// Tunnel Form
el.tunnelForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  if (!getActiveSession()) {
    openConnectModal();
    return;
  }
  const active = getActiveSession();
  if (!active) return;
  const resp = await fetch(`/api/sessions/${active.id}/tunnels`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      label: el.tunLabel.value.trim() || "Port Tunnel",
      local_port: parseInt(el.tunLocalPort.value, 10),
      remote_host: el.tunRemoteHost.value.trim() || "127.0.0.1",
      remote_port: parseInt(el.tunRemotePort.value, 10),
    }),
  });
  if (resp.ok) {
    // Increment default local port so user can add another tunnel easily
    el.tunLocalPort.value = String(parseInt(el.tunLocalPort.value, 10) + 1);
    await refreshTunnels(active.id);
  }
});

el.btnRefreshTelemetry.addEventListener("click", () => refreshTelemetry());

// SSH Config Importer Modal
el.btnOpenSshConfig.addEventListener("click", async () => {
  try {
    const resp = await fetch("/api/ssh-config/local");
    const data = await resp.json();
    el.sshConfigTextarea.value = data.content || "";
  } catch (_) {}
  el.sshConfigModal.classList.remove("hidden");
});

el.btnCloseSshConfig.addEventListener("click", () => el.sshConfigModal.classList.add("hidden"));
el.btnCancelSshConfig.addEventListener("click", () => el.sshConfigModal.classList.add("hidden"));

el.btnConfirmSshConfig.addEventListener("click", async () => {
  const text = el.sshConfigTextarea.value.trim();
  if (!text) return;
  const resp = await fetch("/api/ssh-config/import", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ config_text: text }),
  });
  if (resp.ok) {
    el.sshConfigModal.classList.add("hidden");
    await loadVaultProfiles();
    openConnectModal();
  }
});

// Dropzone & Global Drag-and-Drop Wiring
el.btnBrowseFiles.addEventListener("click", (e) => {
  e.stopPropagation();
  el.fileInput.click();
});

el.dropzone.addEventListener("click", (e) => {
  if (e.target.closest("button")) return;
  el.fileInput.click();
});

el.fileInput.addEventListener("change", async () => {
  if (el.fileInput.files && el.fileInput.files.length > 0) {
    const items = Array.from(el.fileInput.files).map((f) => ({
      file: f,
      relativePath: f.name,
    }));
    await uploadFilesToActiveSession(items);
    el.fileInput.value = "";
  }
});

el.dropzone.addEventListener("dragover", (e) => {
  e.preventDefault();
  e.stopPropagation();
  el.dropzone.classList.add("drag-active");
});

el.dropzone.addEventListener("dragleave", (e) => {
  e.preventDefault();
  e.stopPropagation();
  el.dropzone.classList.remove("drag-active");
});

el.dropzone.addEventListener("drop", async (e) => {
  e.preventDefault();
  e.stopPropagation();
  el.dropzone.classList.remove("drag-active");
  el.globalDropOverlay.classList.add("hidden");
  const items = await extractDroppedFiles(e.dataTransfer);
  await uploadFilesToActiveSession(items);
});

let dragDepth = 0;
window.addEventListener("dragenter", (e) => {
  if (e.dataTransfer && Array.from(e.dataTransfer.types || []).includes("Files")) {
    dragDepth++;
    el.globalDropOverlay.classList.remove("hidden");
  }
});

window.addEventListener("dragover", (e) => {
  if (e.dataTransfer && Array.from(e.dataTransfer.types || []).includes("Files")) {
    e.preventDefault();
  }
});

window.addEventListener("dragleave", () => {
  dragDepth = Math.max(0, dragDepth - 1);
  if (dragDepth === 0) {
    el.globalDropOverlay.classList.add("hidden");
  }
});

window.addEventListener("drop", async (e) => {
  dragDepth = 0;
  el.globalDropOverlay.classList.add("hidden");
  el.dropzone.classList.remove("drag-active");
  if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length > 0) {
    e.preventDefault();
    const items = await extractDroppedFiles(e.dataTransfer);
    await uploadFilesToActiveSession(items);
  }
});

// Quick Sample File Drop & Browser File Composer
el.btnDemoDrop.addEventListener("click", async (e) => {
  e.stopPropagation();
  const timestamp = new Date().toISOString();
  const sampleText = [
    "# Sample File Transferred via WebSSH Studio Drag & Drop",
    `Transferred-At: ${timestamp}`,
    "Protocol: SFTP over SSH-2.0",
    "Status: Verified OK!",
    "",
  ].join("\n");
  const file = new File([sampleText], `sample_drop_${Date.now().toString().slice(-4)}.txt`, {
    type: "text/plain",
  });
  await uploadFilesToActiveSession([{ file, relativePath: file.name }]);
});

el.btnQuickCompose.addEventListener("click", (e) => {
  e.stopPropagation();
  el.composeModal.classList.remove("hidden");
  el.composeFilename.focus();
});

el.btnCloseCompose.addEventListener("click", () => el.composeModal.classList.add("hidden"));
el.btnCancelCompose.addEventListener("click", () => el.composeModal.classList.add("hidden"));

el.composeFileForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const name = el.composeFilename.value.trim() || "untitled.txt";
  const content = el.composeContent.value;
  const file = new File([content], name.split("/").pop(), { type: "text/plain" });
  el.composeModal.classList.add("hidden");
  await uploadFilesToActiveSession([{ file, relativePath: name }]);
});

el.btnClearTransfers.addEventListener("click", () => {
  state.transfers = [];
  renderTransferQueue();
});

// Window Resize -> Resize PTYs
window.addEventListener("resize", () => {
  updateTerminalVisibility();
});

// Initial Bootstrap
document.querySelectorAll(".design-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    applyAppDesign(btn.getAttribute("data-design"));
  });
});
try {
  const savedDesign = localStorage.getItem("webssh_design") || "obsidian";
  applyAppDesign(savedDesign);
} catch (_) {
  applyAppDesign("obsidian");
}

// Parameterized Playbook Modal Close Handlers
const pbParamsModal = document.getElementById("pb-params-modal");
document.getElementById("btn-close-pb-params")?.addEventListener("click", () => pbParamsModal.classList.add("hidden"));
document.getElementById("btn-cancel-pb-params")?.addEventListener("click", () => pbParamsModal.classList.add("hidden"));

// App-Level Security & Lock Screen Wiring
const securityModal = document.getElementById("security-modal");
const lockOverlay = document.getElementById("app-lock-overlay");
const btnOpenSecurity = document.getElementById("btn-open-security");
const chkAuthEnabled = document.getElementById("chk-auth-enabled");
const chkTrustProxy = document.getElementById("chk-trust-proxy");
const secNewPassword = document.getElementById("sec-new-password");
const btnLockNow = document.getElementById("btn-lock-now");
const securityStatusMsg = document.getElementById("security-status-msg");

async function checkAuthStatus() {
  try {
    const resp = await fetch("/api/auth/status");
    const st = await resp.json();
    chkAuthEnabled.checked = Boolean(st.auth_enabled);
    chkTrustProxy.checked = Boolean(st.trust_proxy_headers);
    btnLockNow.classList.toggle("hidden", !st.auth_enabled);
    if (btnOpenSecurity) {
      btnOpenSecurity.textContent = st.auth_enabled ? "🔒 Protected" : "🔓 Security";
    }
    if (st.auth_enabled && !st.authenticated) {
      lockOverlay.classList.remove("hidden");
      document.getElementById("unlock-password")?.focus();
      return false;
    } else {
      lockOverlay.classList.add("hidden");
      return true;
    }
  } catch (_) {
    return true;
  }
}

btnOpenSecurity?.addEventListener("click", async () => {
  securityStatusMsg.classList.add("hidden");
  await checkAuthStatus();
  securityModal.classList.remove("hidden");
});

document.getElementById("btn-close-security")?.addEventListener("click", () => securityModal.classList.add("hidden"));
document.getElementById("btn-cancel-security")?.addEventListener("click", () => securityModal.classList.add("hidden"));

document.getElementById("security-form")?.addEventListener("submit", async (e) => {
  e.preventDefault();
  securityStatusMsg.classList.add("hidden");
  const resp = await fetch("/api/auth/setup", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      enabled: chkAuthEnabled.checked,
      new_password: secNewPassword.value,
      trust_proxy_headers: chkTrustProxy.checked,
    }),
  });
  const data = await resp.json();
  if (!resp.ok) {
    securityStatusMsg.textContent = data.detail || "Failed to update security settings";
    securityStatusMsg.classList.remove("hidden");
    return;
  }
  secNewPassword.value = "";
  securityModal.classList.add("hidden");
  await checkAuthStatus();
});

btnLockNow?.addEventListener("click", async () => {
  await fetch("/api/auth/logout", { method: "POST" });
  securityModal.classList.add("hidden");
  await checkAuthStatus();
});

document.getElementById("app-unlock-form")?.addEventListener("submit", async (e) => {
  e.preventDefault();
  const pwInput = document.getElementById("unlock-password");
  const errEl = document.getElementById("unlock-error");
  errEl.classList.add("hidden");
  const resp = await fetch("/api/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ password: pwInput.value }),
  });
  if (!resp.ok) {
    errEl.textContent = "Invalid master password.";
    errEl.classList.remove("hidden");
    return;
  }
  pwInput.value = "";
  lockOverlay.classList.add("hidden");
  loadVaultProfiles();
  loadPlaybooks();
});

checkAuthStatus().then((unlocked) => {
  if (unlocked) {
    loadVaultProfiles();
    loadPlaybooks();
  }
});
state.telemetryTimer = setInterval(() => {
  if (state.activeSessionId) {
    refreshTelemetry(state.activeSessionId);
  }
}, 4000);
