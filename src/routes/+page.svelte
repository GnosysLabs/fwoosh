<script lang="ts">
  import { onMount } from "svelte";
  import { invoke } from "@tauri-apps/api/core";
  import { listen, type UnlistenFn } from "@tauri-apps/api/event";
  import { getCurrentWindow } from "@tauri-apps/api/window";
  import { isPermissionGranted, requestPermission } from "@tauri-apps/plugin-notification";

  type Theme = "dark" | "light";

  // ---- State ----
  let text = $state("");
  let sending = $state(false);
  let status = $state<"idle" | "ok" | "err">("idle");
  let statusMsg = $state("");
  let clips = $state<ClipDto[]>([]);
  let query = $state("");
  let pairingUri = $state("");
  let joinUri = $state("");
  let showPairing = $state(false);
  let inRoom = $state(false);
  let toast = $state<ToastInfo | null>(null);
  let activeView = $state<"compose" | "history">("compose");
  let devices = $state<DeviceDto[]>([]);
  let theme = $state<Theme>("dark");
  let settingsOpen = $state(false);
  let devicesExpanded = $state(false);
  let confirmDeleteAllOpen = $state(false);
  let deletingAll = $state(false);
  let logoSrc = $derived(theme === "dark" ? "/fwoosh_light.webp" : "/fwoosh_dark.webp");
  let historySearching = $derived(query.trim().length > 0);
  let toastTimer: ReturnType<typeof setTimeout> | null = null;

  interface ClipDto {
    id: number;
    sender: string;
    ts: number;
    text: string;
  }
  interface ToastInfo {
    sender: string;
    preview: string;
    text: string;
    ts?: number;
  }
  interface DeviceDto {
    id: string;
    label: string;
    is_self: boolean;
    is_admin: boolean;
    can_revoke: boolean;
  }

  // ---- Load recent clips on mount + listen for events ----
  let unlisteners: Array<() => void | Promise<void>> = [];

  onMount(() => {
    const savedTheme = localStorage.getItem("fwoosh-theme");
    const preferredTheme =
      savedTheme === "light" || savedTheme === "dark"
        ? savedTheme
        : window.matchMedia?.("(prefers-color-scheme: light)").matches
          ? "light"
          : "dark";
    setTheme(preferredTheme);

    (async () => {
      try {
        clips = await invoke<ClipDto[]>("recent_clips", { limit: 50 });
      } catch {
        /* store empty */
      }

      // Check if we're already in a room (e.g. after restart).
      await refreshRoom();

      unlisteners.push(
        await listen("clip-received", (e) => {
          void handleIncomingClip(e.payload as ToastInfo);
        })
      );
      unlisteners.push(
        await listen("clip-stored", async () => {
          clips = await invoke<ClipDto[]>("recent_clips", { limit: 50 });
        })
      );
      unlisteners.push(
        await listen("roster-updated", async () => {
          await refreshRoom(true);
        })
      );
    })();

    return () => unlisteners.forEach((u) => void u());
  });

  // ---- Actions ----
  function setTheme(next: Theme) {
    theme = next;
    document.documentElement.dataset.theme = next;
    document.documentElement.style.colorScheme = next;
    localStorage.setItem("fwoosh-theme", next);
  }

  async function hidePopup() {
    settingsOpen = false;
    await getCurrentWindow().hide();
  }

  function startLogoDrag(e: MouseEvent) {
    if (e.button !== 0 || !/^Mac/.test(navigator.platform)) return;
    e.preventDefault();
    void getCurrentWindow().startDragging();
  }

  async function refreshRoom(collapseDevices = false) {
    try {
      const wasInRoom = inRoom;
      const rs = await invoke<{ in_room: boolean; member_count: number; topic: string }>(
        "room_state"
      );
      inRoom = rs.in_room;
      devices = inRoom ? await invoke<DeviceDto[]>("roster_devices") : [];
      if (!inRoom || collapseDevices || !wasInRoom) devicesExpanded = false;
    } catch {
      devices = [];
      devicesExpanded = false;
    }
  }

  async function send() {
    if (!text.trim() || sending) return;
    sending = true;
    status = "idle";
    try {
      await invoke("send_clip", { text, private: false });
      status = "ok";
      statusMsg = "Sent and saved to history";
      text = "";
      setTimeout(() => (status = "idle"), 2000);
    } catch (e) {
      status = "err";
      statusMsg = String(e);
    } finally {
      sending = false;
    }
  }

  async function search() {
    try {
      clips = await invoke<ClipDto[]>("search_clips", { query });
    } catch {
      /* ignore */
    }
  }

  async function copyClip(c: ClipDto) {
    await copyText(c.text, "Copied to clipboard");
  }

  async function copyText(value: string, preview = "Copied to clipboard") {
    try {
      await invoke("copy_to_clipboard", { text: value });
      showToast({ sender: "you", preview, text: value }, 1500);
    } catch {
      /* ignore */
    }
  }

  function showToast(next: ToastInfo, ttlMs?: number) {
    if (toastTimer) {
      clearTimeout(toastTimer);
      toastTimer = null;
    }
    toast = next;
    if (ttlMs) {
      toastTimer = setTimeout(() => {
        toast = null;
        toastTimer = null;
      }, ttlMs);
    }
  }

  function clearToast() {
    if (toastTimer) {
      clearTimeout(toastTimer);
      toastTimer = null;
    }
    toast = null;
  }

  async function delClip(id: number) {
    try {
      await invoke("delete_clip", { id });
      clips = clips.filter((c) => c.id !== id);
    } catch (e) {
      status = "err";
      statusMsg = String(e);
    }
  }

  async function deleteAllClips() {
    if (deletingAll) return;
    deletingAll = true;
    status = "idle";
    try {
      await invoke("delete_all_clips");
      clips = [];
      confirmDeleteAllOpen = false;
      status = "ok";
      statusMsg = "History cleared";
      setTimeout(() => (status = "idle"), 2000);
    } catch (e) {
      status = "err";
      statusMsg = String(e);
    } finally {
      deletingAll = false;
    }
  }

  async function createRoom() {
    try {
      pairingUri = await invoke<string>("create_room", { label: "My device" });
      inRoom = true;
      await refreshRoom(true);
      showPairing = true;
    } catch (e) {
      status = "err";
      statusMsg = String(e);
    }
  }

  async function handleIncomingClip(p: ToastInfo) {
    showToast(p);
    const attention = await windowAttentionState();
    if (attention.notify) {
      await notifyIncoming(p);
    }
    if (attention.revealForCopy) {
      await showMainWindow();
    }
  }

  async function windowAttentionState() {
    try {
      const win = getCurrentWindow();
      const [visible, minimized, focused] = await Promise.all([
        win.isVisible(),
        win.isMinimized(),
        win.isFocused(),
      ]);
      return {
        notify: !visible || minimized || !focused,
        revealForCopy: !visible || minimized,
      };
    } catch {
      return { notify: true, revealForCopy: true };
    }
  }

  async function showMainWindow() {
    try {
      await invoke("show_main_window");
    } catch {
      /* optional fallback */
    }
  }

  async function notifyIncoming(p: ToastInfo) {
    try {
      let granted = await isPermissionGranted();
      if (!granted) granted = (await requestPermission()) === "granted";
      if (!granted) return;

      await invoke("notify_incoming_clip", { sender: p.sender, preview: p.preview });
    } catch {
      /* notifications optional */
    }
  }

  async function copyToastText() {
    if (!toast) return;
    try {
      await invoke("copy_to_clipboard", { text: toast.text });
      clearToast();
    } catch {
      /* ignore */
    }
  }

  function onKeydown(e: KeyboardEvent) {
    if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) {
      e.preventDefault();
      send();
    }
    if (e.key === "Escape") {
      if (settingsOpen) {
        settingsOpen = false;
        return;
      }
      if (confirmDeleteAllOpen) {
        confirmDeleteAllOpen = false;
        return;
      }
      if (showPairing) {
        showPairing = false;
        return;
      }
      void hidePopup();
    }
  }

  function timeAgo(ts: number): string {
    const s = Math.floor(Date.now() / 1000 - ts);
    if (s < 60) return `${s}s`;
    if (s < 3600) return `${Math.floor(s / 60)}m`;
    if (s < 86400) return `${Math.floor(s / 3600)}h`;
    return `${Math.floor(s / 86400)}d`;
  }

  async function leaveRoom() {
    try {
      await invoke("leave_room");
      inRoom = false;
      devices = [];
      devicesExpanded = false;
      status = "idle";
    } catch (e) {
      status = "err";
      statusMsg = String(e);
    }
  }

  async function joinRoom() {
    if (!joinUri.trim()) return;
    try {
      await invoke("join_room", { uri: joinUri, label: "My device" });
      joinUri = "";
      status = "ok";
      statusMsg = "Joining room - waiting for admin to add you...";
      setTimeout(() => (status = "idle"), 4000);
    } catch (e) {
      status = "err";
      statusMsg = String(e);
    }
  }

  async function createPairingCode() {
    try {
      pairingUri = await invoke<string>("new_pairing_code");
      showPairing = true;
    } catch (e) {
      status = "err";
      statusMsg = String(e);
    }
  }

  async function revokeDevice(id: string) {
    if (!confirm("Revoke this device from the room?")) return;
    try {
      await invoke("revoke_device", { deviceId: id });
      await refreshRoom();
    } catch (e) {
      status = "err";
      statusMsg = String(e);
    }
  }
</script>

<svelte:window on:keydown={onKeydown} />

<div class="card" data-tauri-drag-region>
  <header class="header" data-tauri-drag-region>
    <div class="title" role="presentation" data-tauri-drag-region onmousedown={startLogoDrag}>
      <img
        class="brand-logo"
        src={logoSrc}
        alt="Fwoosh"
        draggable="false"
        data-tauri-drag-region
      />
    </div>
    <div class="tabs">
      <button
        class="tab"
        class:active={activeView === "compose"}
        onclick={() => (activeView = "compose")}>Send</button
      >
      <button
        class="tab"
        class:active={activeView === "history"}
        onclick={() => (activeView = "history")}>History</button
      >
    </div>
    <div class="window-actions" data-tauri-drag-region="false">
      <button
        class="icon-btn"
        aria-label="Settings"
        title="Settings"
        aria-expanded={settingsOpen}
        onclick={() => (settingsOpen = !settingsOpen)}
      >
        <svg class="icon-svg" viewBox="0 0 24 24" aria-hidden="true">
          <path d="M12 15.5a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7Z" />
          <path
            d="M19.4 15a1.8 1.8 0 0 0 .36 1.98l.04.04a2.1 2.1 0 0 1-2.98 2.98l-.04-.04A1.8 1.8 0 0 0 14.8 19.6a1.8 1.8 0 0 0-1.08 1.65V21.3a2.1 2.1 0 0 1-4.2 0v-.05A1.8 1.8 0 0 0 8.45 19.6a1.8 1.8 0 0 0-1.98.36l-.04.04a2.1 2.1 0 0 1-2.98-2.98l.04-.04A1.8 1.8 0 0 0 3.85 15a1.8 1.8 0 0 0-1.65-1.08H2.1a2.1 2.1 0 0 1 0-4.2h.1a1.8 1.8 0 0 0 1.65-1.08 1.8 1.8 0 0 0-.36-1.98l-.04-.04a2.1 2.1 0 0 1 2.98-2.98l.04.04a1.8 1.8 0 0 0 1.98.36A1.8 1.8 0 0 0 9.52 2.4V2.1a2.1 2.1 0 0 1 4.2 0v.3a1.8 1.8 0 0 0 1.08 1.65 1.8 1.8 0 0 0 1.98-.36l.04-.04a2.1 2.1 0 0 1 2.98 2.98l-.04.04A1.8 1.8 0 0 0 19.4 8.65a1.8 1.8 0 0 0 1.65 1.08h.25a2.1 2.1 0 0 1 0 4.2h-.25A1.8 1.8 0 0 0 19.4 15Z"
          />
        </svg>
      </button>
      <button class="icon-btn close-btn" aria-label="Hide Fwoosh" title="Hide Fwoosh" onclick={hidePopup}>
        <svg class="icon-svg" viewBox="0 0 24 24" aria-hidden="true">
          <path d="M6 6l12 12" />
          <path d="M18 6 6 18" />
        </svg>
      </button>
      {#if settingsOpen}
        <div class="settings-menu" data-tauri-drag-region="false">
          <div class="settings-title">Color scheme</div>
          <div class="scheme-toggle" role="radiogroup" aria-label="Color scheme">
            <button
              class:active={theme === "dark"}
              role="radio"
              aria-checked={theme === "dark"}
              onclick={() => {
                setTheme("dark");
                settingsOpen = false;
              }}>Dark</button
            >
            <button
              class:active={theme === "light"}
              role="radio"
              aria-checked={theme === "light"}
              onclick={() => {
                setTheme("light");
                settingsOpen = false;
              }}>Light</button
            >
          </div>
        </div>
      {/if}
    </div>
  </header>

  {#if activeView === "compose"}
    <div class="compose">
      <textarea
        bind:value={text}
        placeholder="Paste or type, then Cmd/Ctrl+Enter to send to all devices..."
        class="box"
        data-tauri-drag-region="false"></textarea>

      <div class="compose-controls">
        <button class="send-btn" onclick={send} disabled={sending || !text.trim()}>
          {sending ? "Sending..." : "Send"}
        </button>
      </div>

      {#if status !== "idle"}
        <div class="status" class:ok={status === "ok"} class:err={status === "err"}>
          {statusMsg}
        </div>
      {/if}

      {#if !inRoom}
        <div class="room-empty">
          <p class="muted">Not connected to any device yet.</p>
          <div class="room-actions">
            <button class="ghost" onclick={createRoom}>Create a room</button>
          </div>
          <div class="divider"><span>or</span></div>
          <input
            class="join-input"
            placeholder="Paste a pairing code..."
            bind:value={joinUri}
            onkeydown={(e) => e.key === "Enter" && joinRoom()} />
          <button class="ghost" onclick={joinRoom} disabled={!joinUri.trim()}>Join room</button>
        </div>
      {:else}
        <div class="devices-panel" class:expanded={devicesExpanded}>
          <div class="devices-compact">
            <button
              class="device-toggle"
              aria-label={devicesExpanded ? "Collapse devices" : "Expand devices"}
              aria-expanded={devicesExpanded}
              title={devicesExpanded ? "Collapse devices" : "Expand devices"}
              onclick={() => (devicesExpanded = !devicesExpanded)}
            >
              <svg class="icon-svg" viewBox="0 0 24 24" aria-hidden="true">
                {#if devicesExpanded}
                  <path d="M5 12h14" />
                {:else}
                  <path d="M12 5v14" />
                  <path d="M5 12h14" />
                {/if}
              </svg>
              <span>Devices</span>
            </button>
          </div>
          {#if devicesExpanded}
            <div class="roster">
              {#if devices.some((d) => d.is_self && d.is_admin)}
                <button class="pair-btn" onclick={createPairingCode}>Pair device</button>
              {/if}
              {#each devices as d (d.id)}
                <div class="device-row">
                  <div class="device-main">
                    <span class="device-label">{d.label}</span>
                    <span class="device-meta">
                      {d.is_self ? "this device" : d.id.slice(0, 8)}{d.is_admin ? " - admin" : ""}
                    </span>
                  </div>
                  {#if d.can_revoke}
                    <button class="revoke-btn" onclick={() => revokeDevice(d.id)}>Revoke</button>
                  {/if}
                </div>
              {/each}
            </div>
          {/if}
        </div>
        <button class="leave-link" onclick={leaveRoom}>Leave room</button>
      {/if}
    </div>
  {:else}
    <div class="history">
      <div class="history-toolbar">
        <input
          class="search"
          placeholder="Search history..."
          bind:value={query}
          oninput={search} />
        <button
          class="danger-icon-btn"
          aria-label="Delete all history"
          title="Delete all history"
          disabled={clips.length === 0}
          onclick={() => (confirmDeleteAllOpen = true)}
        >
          <svg class="icon-svg" viewBox="0 0 24 24" aria-hidden="true">
            <path d="M3 6h18" />
            <path d="M8 6V4h8v2" />
            <path d="M7 6l1 15h8l1-15" />
            <path d="M10 10v7" />
            <path d="M14 10v7" />
          </svg>
        </button>
      </div>
      {#if status !== "idle"}
        <div class="status" class:ok={status === "ok"} class:err={status === "err"}>
          {statusMsg}
        </div>
      {/if}
      {#if clips.length === 0}
        <div class="empty muted">No clips yet.</div>
      {:else}
        <ul class="clip-list">
          {#each clips as c (c.id)}
            <li class="clip">
              <button
                class="clip-del"
                onclick={() => delClip(c.id)}
                aria-label="Delete clip on all devices"
                title="Delete clip on all devices"
              >
                <svg class="icon-svg" viewBox="0 0 24 24" aria-hidden="true">
                  <path d="M6 6l12 12" />
                  <path d="M18 6 6 18" />
                </svg>
              </button>
              <button class="clip-body" onclick={() => copyClip(c)}>
                <span class="clip-text" class:searching={historySearching}>{c.text}</span>
                <span class="clip-meta">{timeAgo(c.ts)} - {c.sender}</span>
              </button>
            </li>
          {/each}
        </ul>
      {/if}
    </div>
  {/if}

  {#if showPairing && pairingUri}
    <div
      class="pairing-overlay"
      role="button"
      tabindex="0"
      onclick={() => (showPairing = false)}
      onkeydown={(e) => {
        if (e.key === "Escape" || e.key === "Enter") showPairing = false;
      }}
    >
      <div
        class="pairing-card"
        role="presentation"
        onclick={(e) => e.stopPropagation()}
        onkeydown={(e) => e.stopPropagation()}
      >
        <h3>Pair a device</h3>
        <p class="muted small"
          >Scan this on another device, or share the code. Single-use - keep it
          private.</p
        >
        <code class="pair-code">{pairingUri}</code>
        <button class="ghost" onclick={() => copyText(pairingUri, "Pairing code copied")}
          >Copy pairing code</button
        >
        <button class="send-btn" onclick={() => (showPairing = false)}>Done</button>
      </div>
    </div>
  {/if}

  {#if confirmDeleteAllOpen}
    <div
      class="modal-overlay"
      role="button"
      tabindex="0"
      onclick={() => (confirmDeleteAllOpen = false)}
      onkeydown={(e) => {
        if (e.key === "Escape" || e.key === "Enter") confirmDeleteAllOpen = false;
      }}
    >
      <div
        class="confirm-dialog"
        role="dialog"
        tabindex="-1"
        aria-modal="true"
        aria-labelledby="delete-all-title"
        onclick={(e) => e.stopPropagation()}
        onkeydown={(e) => e.stopPropagation()}
      >
        <h3 id="delete-all-title">Delete all history?</h3>
        <p class="muted small">
          This clears saved clips on this device and asks paired devices to remove matching synced clips.
        </p>
        <div class="dialog-actions">
          <button class="ghost" onclick={() => (confirmDeleteAllOpen = false)} disabled={deletingAll}>
            Cancel
          </button>
          <button class="danger-btn" onclick={deleteAllClips} disabled={deletingAll}>
            {deletingAll ? "Deleting..." : "Delete all"}
          </button>
        </div>
      </div>
    </div>
  {/if}

  {#if toast}
    <div class="toast" role="status">
      <button class="toast-copy" onclick={() => void copyToastText()}>
        <span class="toast-sender">{toast.sender}</span>
        <span class="toast-preview">{toast.preview}</span>
        <span class="toast-hint">click to copy</span>
      </button>
      <button
        class="toast-dismiss"
        aria-label="Dismiss notification"
        title="Dismiss"
        onclick={clearToast}
      >
        <svg class="icon-svg" viewBox="0 0 24 24" aria-hidden="true">
          <path d="M6 6l12 12" />
          <path d="M18 6 6 18" />
        </svg>
      </button>
    </div>
  {/if}

  <div
    class="connection-indicator"
    class:live={inRoom}
    aria-label={inRoom ? "Connected" : "Not connected"}
    title={inRoom ? "Connected" : "Not connected"}
  ></div>
</div>

<style>
  .card {
    --window-radius: 14px;
    --window-stroke: #2a2a32;
    --window-stroke-inset: 1px;
    position: relative;
    width: 100vw;
    height: 100vh;
    background: #1a1a1f;
    border-radius: var(--window-radius);
    display: flex;
    flex-direction: column;
    overflow: hidden;
    border: none;
    box-shadow: none;
    box-sizing: border-box;
  }
  .card::before {
    content: "";
    position: absolute;
    inset: var(--window-stroke-inset);
    z-index: 50;
    pointer-events: none;
    border: 1px solid var(--window-stroke);
    border-radius: calc(var(--window-radius) - var(--window-stroke-inset));
    box-sizing: border-box;
  }

  .header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 10px 14px;
    border-bottom: 1px solid #26262e;
    -webkit-app-region: drag;
  }
  .title {
    font-size: 13px;
    font-weight: 600;
    color: #e4e4e7;
    display: flex;
    align-items: center;
    gap: 7px;
    letter-spacing: 0.02em;
    min-width: 0;
    -webkit-app-region: drag;
  }
  .brand-logo {
    width: 112px;
    height: 32px;
    object-fit: contain;
    object-position: left center;
    -webkit-app-region: drag;
    user-select: none;
  }
  .window-actions {
    position: relative;
    display: flex;
    align-items: center;
    gap: 4px;
    -webkit-app-region: no-drag;
  }
  .icon-btn {
    width: 28px;
    height: 28px;
    display: grid;
    place-items: center;
    background: transparent;
    border: 1px solid transparent;
    color: #a1a1aa;
    border-radius: 7px;
    cursor: pointer;
    font-size: 15px;
    line-height: 1;
    -webkit-app-region: no-drag;
  }
  .icon-btn:hover,
  .icon-btn:focus-visible {
    background: #2a2a32;
    border-color: #3b3b46;
    color: #f4f4f5;
    outline: none;
  }
  .close-btn {
    color: #c4c4cc;
  }
  .icon-svg {
    width: 16px;
    height: 16px;
    fill: none;
    stroke: currentColor;
    stroke-width: 2;
    stroke-linecap: round;
    stroke-linejoin: round;
  }
  .settings-menu {
    position: absolute;
    top: 34px;
    right: 0;
    z-index: 20;
    width: 170px;
    padding: 10px;
    background: #1f1f27;
    border: 1px solid #343440;
    border-radius: 8px;
    box-shadow: 0 14px 28px rgba(0, 0, 0, 0.42);
  }
  .settings-title {
    color: #a1a1aa;
    font-size: 11px;
    font-weight: 600;
    margin-bottom: 8px;
  }
  .scheme-toggle {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 4px;
  }
  .scheme-toggle button {
    background: #14141a;
    border: 1px solid #30303a;
    color: #d4d4d8;
    border-radius: 6px;
    padding: 6px 8px;
    font-size: 12px;
    cursor: pointer;
  }
  .scheme-toggle button.active {
    background: #2563eb;
    border-color: #3b82f6;
    color: #ffffff;
  }
  .connection-indicator {
    position: absolute;
    right: 10px;
    bottom: 10px;
    z-index: 12;
    width: 10px;
    height: 10px;
    border-radius: 999px;
    background: #6b6b76;
    box-shadow: 0 0 0 2px #1a1a1f;
    pointer-events: none;
  }
  .connection-indicator.live {
    background: #34d399;
    box-shadow:
      0 0 0 2px #1a1a1f,
      0 0 9px rgba(52, 211, 153, 0.72);
  }
  .tabs {
    display: flex;
    gap: 2px;
  }
  .tab {
    background: transparent;
    border: none;
    color: #8b8b96;
    font-size: 12px;
    padding: 4px 10px;
    border-radius: 6px;
    cursor: pointer;
  }
  .tab.active {
    background: #2a2a32;
    color: #e4e4e7;
  }
  .leave-link {
    align-self: center;
    margin: 0 auto;
    margin-top: auto;
    background: transparent;
    border: none;
    color: #4a4a52;
    font-size: 11px;
    cursor: pointer;
    padding: 4px;
    text-decoration: underline;
    text-underline-offset: 2px;
  }
  .leave-link:hover {
    color: #f87171;
  }

  .devices-panel {
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    gap: 8px;
  }
  .devices-panel.expanded {
    align-items: stretch;
  }
  .devices-compact {
    display: flex;
    align-items: center;
    gap: 7px;
  }
  .device-toggle {
    min-width: 28px;
    height: 28px;
    display: inline-flex;
    align-items: center;
    gap: 6px;
    background: #23232b;
    border: 1px solid #343440;
    color: #d4d4d8;
    border-radius: 7px;
    cursor: pointer;
    padding: 0 9px;
    font-size: 12px;
    font-weight: 600;
  }
  .device-toggle:hover,
  .device-toggle:focus-visible {
    background: #2a2a32;
    border-color: #4b4b58;
    outline: none;
  }
  .roster {
    border: 1px solid #2a2a32;
    border-radius: 8px;
    overflow: hidden;
  }
  .pair-btn {
    width: 100%;
    background: #23232b;
    border: none;
    border-bottom: 1px solid #2a2a32;
    color: #d4d4d8;
    padding: 7px 9px;
    font-size: 12px;
    cursor: pointer;
    text-align: left;
  }
  .pair-btn:hover {
    background: #2a2a32;
  }
  .device-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    padding: 7px 9px;
    border-bottom: 1px solid #232329;
  }
  .device-row:last-child {
    border-bottom: none;
  }
  .device-main {
    min-width: 0;
    display: flex;
    flex-direction: column;
    gap: 1px;
  }
  .device-label {
    color: #d4d4d8;
    font-size: 12px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .device-meta {
    color: #6b6b76;
    font-size: 10px;
  }
  .revoke-btn {
    background: transparent;
    border: 1px solid #3b3b46;
    color: #f87171;
    border-radius: 6px;
    padding: 4px 8px;
    font-size: 11px;
    cursor: pointer;
  }
  .revoke-btn:hover {
    border-color: #f87171;
  }

  .compose {
    flex: 1;
    display: flex;
    flex-direction: column;
    padding: 12px;
    gap: 10px;
  }
  .box {
    flex: 1;
    resize: none;
    background: #121217;
    border: 1px solid #2a2a32;
    border-radius: 8px;
    color: #e4e4e7;
    padding: 12px;
    font-size: 14px;
    font-family: inherit;
    line-height: 1.45;
    outline: none;
    user-select: text;
  }
  .box:focus {
    border-color: #3b3b46;
  }
  .compose-controls {
    display: flex;
    align-items: center;
    justify-content: flex-end;
  }
  .send-btn {
    background: #6366f1;
    color: #fff;
    border: none;
    border-radius: 8px;
    padding: 7px 18px;
    font-size: 13px;
    font-weight: 600;
    cursor: pointer;
    transition: background 0.15s;
  }
  .send-btn:hover:not(:disabled) {
    background: #4f46e5;
  }
  .send-btn:disabled {
    opacity: 0.4;
    cursor: default;
  }
  .status {
    font-size: 12px;
    padding: 6px 10px;
    border-radius: 6px;
  }
  .status.ok {
    color: #34d399;
    background: #064e3b;
  }
  .status.err {
    color: #f87171;
    background: #7f1d1d;
  }

  .room-empty {
    text-align: center;
    padding: 8px 0;
  }
  .muted {
    color: #6b6b76;
    font-size: 13px;
  }
  .small {
    font-size: 11px;
  }
  .room-actions {
    margin-top: 8px;
  }
  .divider {
    display: flex;
    align-items: center;
    gap: 8px;
    margin: 12px 0 8px;
    color: #3f3f46;
    font-size: 11px;
  }
  .divider::before,
  .divider::after {
    content: "";
    flex: 1;
    height: 1px;
    background: #2a2a32;
  }
  .join-input {
    background: #121217;
    border: 1px solid #2a2a32;
    border-radius: 8px;
    color: #e4e4e7;
    padding: 7px 10px;
    font-size: 11px;
    outline: none;
    margin-bottom: 6px;
    width: 100%;
    box-sizing: border-box;
  }
  .ghost {
    background: transparent;
    border: 1px solid #3b3b46;
    color: #e4e4e7;
    border-radius: 8px;
    padding: 7px 14px;
    font-size: 13px;
    cursor: pointer;
  }
  .ghost:hover {
    border-color: #52525b;
  }

  .history {
    flex: 1;
    display: flex;
    flex-direction: column;
    padding: 10px 12px;
    gap: 8px;
    overflow: hidden;
  }
  .history-toolbar {
    display: grid;
    grid-template-columns: 1fr 32px;
    gap: 7px;
    align-items: center;
  }
  .search {
    background: #121217;
    border: 1px solid #2a2a32;
    border-radius: 8px;
    color: #e4e4e7;
    padding: 8px 12px;
    font-size: 13px;
    outline: none;
    min-width: 0;
  }
  .danger-icon-btn {
    width: 32px;
    height: 32px;
    display: grid;
    place-items: center;
    background: transparent;
    border: 1px solid #3b3b46;
    color: #f87171;
    border-radius: 7px;
    cursor: pointer;
  }
  .danger-icon-btn:hover:not(:disabled),
  .danger-icon-btn:focus-visible {
    background: #3a1f25;
    border-color: #f87171;
    outline: none;
  }
  .danger-icon-btn:disabled {
    opacity: 0.35;
    cursor: default;
  }
  .clip-list {
    list-style: none;
    margin: 0;
    padding: 0;
    overflow-y: auto;
    flex: 1;
    scrollbar-width: thin;
    scrollbar-color: #4b4b58 transparent;
  }
  .clip-list::-webkit-scrollbar,
  .box::-webkit-scrollbar,
  .pair-code::-webkit-scrollbar {
    width: 8px;
    height: 8px;
  }
  .clip-list::-webkit-scrollbar-track,
  .box::-webkit-scrollbar-track,
  .pair-code::-webkit-scrollbar-track {
    background: transparent;
  }
  .clip-list::-webkit-scrollbar-thumb,
  .box::-webkit-scrollbar-thumb,
  .pair-code::-webkit-scrollbar-thumb {
    background: #3b3b46;
    border: 2px solid transparent;
    border-radius: 999px;
    background-clip: padding-box;
  }
  .clip-list::-webkit-scrollbar-thumb:hover,
  .box::-webkit-scrollbar-thumb:hover,
  .pair-code::-webkit-scrollbar-thumb:hover {
    background: #555566;
    background-clip: padding-box;
  }
  .clip {
    display: flex;
    align-items: stretch;
    border-bottom: 1px solid #232329;
  }
  .clip-body {
    flex: 1;
    background: transparent;
    border: none;
    text-align: left;
    padding: 9px 4px;
    cursor: pointer;
    display: flex;
    flex-direction: column;
    gap: 2px;
    color: inherit;
  }
  .clip-text {
    color: #d4d4d8;
    font-size: 13px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .clip-text.searching {
    overflow: visible;
    text-overflow: clip;
    white-space: normal;
    word-break: break-word;
  }
  .clip-meta {
    color: #5c5c66;
    font-size: 10px;
  }
  .clip-del {
    width: 32px;
    min-width: 32px;
    display: grid;
    place-items: center;
    background: transparent;
    border: none;
    color: #5c5c66;
    cursor: pointer;
    padding: 0;
  }
  .clip-del:hover {
    color: #f87171;
  }

  .empty {
    text-align: center;
    padding: 30px 0;
  }

  .pairing-overlay {
    position: absolute;
    inset: 0;
    background: rgba(0, 0, 0, 0.7);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 10;
  }
  .modal-overlay {
    position: absolute;
    inset: 0;
    background: rgba(0, 0, 0, 0.7);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 25;
  }
  .pairing-card {
    background: #1a1a1f;
    border: 1px solid #2a2a32;
    border-radius: 12px;
    padding: 20px;
    width: 86%;
    display: flex;
    flex-direction: column;
    gap: 10px;
  }
  .pairing-card h3 {
    margin: 0;
    color: #e4e4e7;
    font-size: 15px;
  }
  .pair-code {
    background: #121217;
    border: 1px solid #2a2a32;
    border-radius: 6px;
    padding: 8px;
    font-size: 10px;
    color: #818cf8;
    word-break: break-all;
    user-select: text;
  }
  .confirm-dialog {
    width: 84%;
    background: #1a1a1f;
    border: 1px solid #343440;
    border-radius: 12px;
    padding: 18px;
    box-shadow: 0 18px 40px rgba(0, 0, 0, 0.48);
    display: flex;
    flex-direction: column;
    gap: 10px;
  }
  .confirm-dialog h3 {
    margin: 0;
    color: #f4f4f5;
    font-size: 15px;
  }
  .dialog-actions {
    display: flex;
    justify-content: flex-end;
    gap: 8px;
  }
  .danger-btn {
    background: #dc2626;
    border: none;
    color: #ffffff;
    border-radius: 8px;
    padding: 7px 12px;
    font-size: 13px;
    font-weight: 600;
    cursor: pointer;
  }
  .danger-btn:hover:not(:disabled) {
    background: #b91c1c;
  }
  .danger-btn:disabled,
  .ghost:disabled {
    opacity: 0.45;
    cursor: default;
  }

  .toast {
    position: absolute;
    bottom: 12px;
    left: 12px;
    right: 36px;
    z-index: 11;
    display: flex;
    align-items: stretch;
    background: #6366f1;
    color: #fff;
    border-radius: 10px;
    overflow: hidden;
    box-shadow: 0 6px 20px rgba(99, 102, 241, 0.4);
  }
  .toast-copy {
    flex: 1;
    min-width: 0;
    display: block;
    padding: 10px 10px 10px 14px;
    background: transparent;
    border: none;
    color: inherit;
    text-align: left;
    cursor: pointer;
  }
  .toast-copy:hover {
    background: rgba(255, 255, 255, 0.08);
  }
  .toast-copy:focus-visible,
  .toast-dismiss:focus-visible {
    outline: 2px solid rgba(255, 255, 255, 0.64);
    outline-offset: -2px;
  }
  .toast-dismiss {
    flex: 0 0 30px;
    width: 30px;
    margin: 6px 6px 6px 0;
    display: grid;
    place-items: center;
    background: rgba(255, 255, 255, 0.08);
    border: 1px solid rgba(255, 255, 255, 0.16);
    border-radius: 7px;
    color: rgba(255, 255, 255, 0.82);
    cursor: pointer;
  }
  .toast-dismiss:hover {
    background: rgba(255, 255, 255, 0.16);
    color: #fff;
  }
  .toast-sender {
    display: block;
    font-size: 11px;
    opacity: 0.8;
  }
  .toast-preview {
    display: block;
    font-size: 13px;
    margin-top: 2px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .toast-hint {
    display: block;
    font-size: 10px;
    opacity: 0.7;
    margin-top: 3px;
  }

  :global(html[data-theme="light"]) .card {
    --window-stroke: #c9d6e6;
    background: #f8fbff;
  }
  :global(html[data-theme="light"]) .header {
    border-bottom-color: #d8e2ef;
  }
  :global(html[data-theme="light"]) .title {
    color: #102033;
  }
  :global(html[data-theme="light"]) .connection-indicator {
    background: #94a3b8;
    box-shadow: 0 0 0 2px #f8fbff;
  }
  :global(html[data-theme="light"]) .connection-indicator.live {
    background: #059669;
    box-shadow:
      0 0 0 2px #f8fbff,
      0 0 9px rgba(5, 150, 105, 0.42);
  }
  :global(html[data-theme="light"]) .tab {
    color: #64748b;
  }
  :global(html[data-theme="light"]) .tab.active,
  :global(html[data-theme="light"]) .tab:hover {
    background: #e7eef7;
    color: #102033;
  }
  :global(html[data-theme="light"]) .icon-btn {
    color: #526172;
  }
  :global(html[data-theme="light"]) .icon-btn:hover,
  :global(html[data-theme="light"]) .icon-btn:focus-visible {
    background: #e7eef7;
    border-color: #bfd0e3;
    color: #102033;
  }
  :global(html[data-theme="light"]) .settings-menu,
  :global(html[data-theme="light"]) .pairing-card {
    background: #ffffff;
    border-color: #cbd8e8;
    box-shadow: 0 14px 28px rgba(30, 41, 59, 0.18);
  }
  :global(html[data-theme="light"]) .settings-title,
  :global(html[data-theme="light"]) .muted,
  :global(html[data-theme="light"]) .device-meta,
  :global(html[data-theme="light"]) .clip-meta {
    color: #607089;
  }
  :global(html[data-theme="light"]) .scheme-toggle button,
  :global(html[data-theme="light"]) .ghost,
  :global(html[data-theme="light"]) .revoke-btn {
    background: #ffffff;
    border-color: #c6d3e3;
    color: #102033;
  }
  :global(html[data-theme="light"]) .scheme-toggle button.active {
    background: #0757c7;
    border-color: #0757c7;
    color: #ffffff;
  }
  :global(html[data-theme="light"]) .box,
  :global(html[data-theme="light"]) .join-input,
  :global(html[data-theme="light"]) .search,
  :global(html[data-theme="light"]) .pair-code {
    background: #ffffff;
    border-color: #c9d6e6;
    color: #102033;
  }
  :global(html[data-theme="light"]) .box:focus,
  :global(html[data-theme="light"]) .join-input:focus,
  :global(html[data-theme="light"]) .search:focus {
    border-color: #0757c7;
    box-shadow: 0 0 0 2px rgba(7, 87, 199, 0.14);
  }
  :global(html[data-theme="light"]) .send-btn,
  :global(html[data-theme="light"]) .toast {
    background: #0757c7;
  }
  :global(html[data-theme="light"]) .send-btn:hover:not(:disabled) {
    background: #06469f;
  }
  :global(html[data-theme="light"]) .status.ok {
    color: #065f46;
    background: #d1fae5;
  }
  :global(html[data-theme="light"]) .status.err {
    color: #991b1b;
    background: #fee2e2;
  }
  :global(html[data-theme="light"]) .divider {
    color: #94a3b8;
  }
  :global(html[data-theme="light"]) .divider::before,
  :global(html[data-theme="light"]) .divider::after,
  :global(html[data-theme="light"]) .clip,
  :global(html[data-theme="light"]) .device-row {
    border-color: #dce6f1;
  }
  :global(html[data-theme="light"]) .roster {
    border-color: #c9d6e6;
  }
  :global(html[data-theme="light"]) .pair-btn {
    background: #edf4fb;
    border-bottom-color: #dce6f1;
    color: #102033;
  }
  :global(html[data-theme="light"]) .pair-btn:hover {
    background: #e2edf8;
  }
  :global(html[data-theme="light"]) .device-label,
  :global(html[data-theme="light"]) .clip-text,
  :global(html[data-theme="light"]) .pairing-card h3 {
    color: #102033;
  }
  :global(html[data-theme="light"]) .leave-link {
    color: #64748b;
  }
  :global(html[data-theme="light"]) .leave-link:hover,
  :global(html[data-theme="light"]) .revoke-btn {
    color: #b42318;
  }
  :global(html[data-theme="light"]) .revoke-btn:hover {
    border-color: #b42318;
  }
  :global(html[data-theme="light"]) .device-toggle {
    background: #edf4fb;
    border-color: #c6d3e3;
    color: #102033;
  }
  :global(html[data-theme="light"]) .device-toggle:hover,
  :global(html[data-theme="light"]) .device-toggle:focus-visible {
    background: #e2edf8;
    border-color: #9fb7d1;
  }
  :global(html[data-theme="light"]) .danger-icon-btn {
    border-color: #d7b9b8;
    color: #b42318;
  }
  :global(html[data-theme="light"]) .danger-icon-btn:hover:not(:disabled),
  :global(html[data-theme="light"]) .danger-icon-btn:focus-visible {
    background: #fee2e2;
    border-color: #b42318;
  }
  :global(html[data-theme="light"]) .clip-list {
    scrollbar-color: #aab8ca transparent;
  }
  :global(html[data-theme="light"]) .clip-list::-webkit-scrollbar-thumb,
  :global(html[data-theme="light"]) .box::-webkit-scrollbar-thumb,
  :global(html[data-theme="light"]) .pair-code::-webkit-scrollbar-thumb {
    background: #aab8ca;
    background-clip: padding-box;
  }
  :global(html[data-theme="light"]) .clip-list::-webkit-scrollbar-thumb:hover,
  :global(html[data-theme="light"]) .box::-webkit-scrollbar-thumb:hover,
  :global(html[data-theme="light"]) .pair-code::-webkit-scrollbar-thumb:hover {
    background: #8295ad;
    background-clip: padding-box;
  }
  :global(html[data-theme="light"]) .clip-del {
    color: #8492a6;
  }
  :global(html[data-theme="light"]) .clip-del:hover {
    color: #b42318;
  }
  :global(html[data-theme="light"]) .pairing-overlay {
    background: rgba(15, 23, 42, 0.34);
  }
  :global(html[data-theme="light"]) .modal-overlay {
    background: rgba(15, 23, 42, 0.34);
  }
  :global(html[data-theme="light"]) .confirm-dialog {
    background: #ffffff;
    border-color: #cbd8e8;
    box-shadow: 0 18px 40px rgba(30, 41, 59, 0.2);
  }
  :global(html[data-theme="light"]) .confirm-dialog h3 {
    color: #102033;
  }
  :global(html[data-theme="light"]) .danger-btn {
    background: #b42318;
  }
  :global(html[data-theme="light"]) .danger-btn:hover:not(:disabled) {
    background: #8f1d14;
  }
</style>
