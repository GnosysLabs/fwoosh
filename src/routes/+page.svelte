<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { listen, type UnlistenFn } from "@tauri-apps/api/event";
  import { getCurrentWindow } from "@tauri-apps/api/window";
  import { writeText } from "@tauri-apps/plugin-clipboard-manager";
  import {
    isPermissionGranted,
    requestPermission,
    sendNotification,
  } from "@tauri-apps/plugin-notification";

  // ---- State ----
  let text = $state("");
  let privateMode = $state(false);
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
  }

  // ---- Load recent clips on mount + listen for events ----
  let unlisteners: UnlistenFn[] = [];

  $effect(() => {
    (async () => {
      try {
        clips = await invoke<ClipDto[]>("recent_clips", { limit: 50 });
      } catch {
        /* store empty */
      }

      // Check if we're already in a room (e.g. after restart).
      try {
        const rs = await invoke<{ in_room: boolean; member_count: number; topic: string }>(
          "room_state"
        );
        inRoom = rs.in_room;
      } catch {
        /* ignore */
      }

      unlisteners.push(
        await listen("clip-received", (e) => {
          const p = e.payload as ToastInfo;
          toast = p;
          notifyIncoming(p.preview);
          setTimeout(() => (toast = null), 6000);
        })
      );
      unlisteners.push(
        await listen("clip-stored", async () => {
          clips = await invoke<ClipDto[]>("recent_clips", { limit: 50 });
        })
      );
      unlisteners.push(
        await listen("roster-updated", async () => {
          const rs = await invoke<{ in_room: boolean; member_count: number; topic: string }>(
            "room_state"
          );
          inRoom = rs.in_room;
        })
      );
    })();

    return () => unlisteners.forEach((u) => u());
  });

  // ---- Actions ----
  async function send() {
    if (!text.trim() || sending) return;
    sending = true;
    status = "idle";
    try {
      await invoke("send_clip", { text, private: privateMode });
      status = "ok";
      statusMsg = privateMode ? "Sent (private — not saved)" : "Sent + saved";
      if (!privateMode) text = "";
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
    try {
      await writeText(c.text);
      toast = { sender: "you", preview: "Copied to clipboard", text: c.text };
      setTimeout(() => (toast = null), 1500);
    } catch {
      /* ignore */
    }
  }

  async function delClip(id: number) {
    try {
      await invoke("delete_clip", { id });
      clips = clips.filter((c) => c.id !== id);
    } catch {
      /* ignore */
    }
  }

  async function createRoom() {
    try {
      pairingUri = await invoke<string>("create_room", { label: "My device" });
      inRoom = true;
      showPairing = true;
    } catch (e) {
      status = "err";
      statusMsg = String(e);
    }
  }

  async function notifyIncoming(preview: string) {
    try {
      let granted = await isPermissionGranted();
      if (!granted) granted = (await requestPermission()) === "granted";
      if (granted) sendNotification({ title: "Fwoosh", body: preview });
    } catch {
      /* notifications optional */
    }
  }

  function onKeydown(e: KeyboardEvent) {
    if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) {
      e.preventDefault();
      send();
    }
    if (e.key === "Escape") {
      getCurrentWindow().hide();
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
      statusMsg = "Joining room — waiting for admin to add you…";
      setTimeout(() => (status = "idle"), 4000);
    } catch (e) {
      status = "err";
      statusMsg = String(e);
    }
  }
</script>

<svelte:window on:keydown={onKeydown} />

<div class="card" data-tauri-drag-region>
  <header class="header" data-tauri-drag-region>
    <div class="title">
      <span class="dot" class:live={inRoom}></span>
      Fwoosh
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
  </header>

  {#if activeView === "compose"}
    <div class="compose">
      <textarea
        bind:value={text}
        placeholder="Paste or type, then ⌘/Ctrl+Enter to send to all devices…"
        class="box"
        data-tauri-drag-region="false"></textarea>

      <div class="compose-controls">
        <label class="private-toggle">
          <input type="checkbox" bind:checked={privateMode} />
          <span>Private</span>
        </label>
        <button class="send-btn" onclick={send} disabled={sending || !text.trim()}>
          {sending ? "Sending…" : "Send"}
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
            placeholder="Paste a pairing code…"
            bind:value={joinUri}
            onkeydown={(e) => e.key === "Enter" && joinRoom()} />
          <button class="ghost" onclick={joinRoom} disabled={!joinUri.trim()}>Join room</button>
        </div>
      {:else}
        <button class="leave-link" onclick={leaveRoom}>Leave room</button>
      {/if}
    </div>
  {:else}
    <div class="history">
      <input
        class="search"
        placeholder="Search history…"
        bind:value={query}
        oninput={search} />
      {#if clips.length === 0}
        <div class="empty muted">No clips yet.</div>
      {:else}
        <ul class="clip-list">
          {#each clips as c (c.id)}
            <li class="clip">
              <button class="clip-body" onclick={() => copyClip(c)}>
                <span class="clip-text">{c.text}</span>
                <span class="clip-meta">{timeAgo(c.ts)} · {c.sender}</span>
              </button>
              <button class="clip-del" onclick={() => delClip(c.id)} aria-label="Delete">✕</button>
            </li>
          {/each}
        </ul>
      {/if}
    </div>
  {/if}

  {#if showPairing && pairingUri}
    <div class="pairing-overlay" onclick={() => (showPairing = false)}>
      <div class="pairing-card" onclick={(e) => e.stopPropagation()}>
        <h3>Pair a device</h3>
        <p class="muted small"
          >Scan this on another device, or share the code. Single-use — keep it
          private.</p
        >
        <code class="pair-code">{pairingUri}</code>
        <button class="ghost" onclick={() => navigator.clipboard.writeText(pairingUri)}
          >Copy pairing code</button
        >
        <button class="send-btn" onclick={() => (showPairing = false)}>Done</button>
      </div>
    </div>
  {/if}

  {#if toast}
    <div
      class="toast"
      role="button"
      tabindex="0"
      onclick={() => {
        if (toast) {
          writeText(toast.text);
          toast = null;
        }
      }}
    >
      <div class="toast-sender">{toast.sender}</div>
      <div class="toast-preview">{toast.preview}</div>
      <div class="toast-hint">click to copy</div>
    </div>
  {/if}
</div>

<style>
  .card {
    width: 100vw;
    height: 100vh;
    background: #1a1a1f;
    border-radius: 14px;
    box-shadow: 0 12px 40px rgba(0, 0, 0, 0.5);
    display: flex;
    flex-direction: column;
    overflow: hidden;
    border: 1px solid #2a2a32;
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
  }
  .dot {
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background: #6b6b76;
  }
  .dot.live {
    background: #34d399;
    box-shadow: 0 0 6px #34d39980;
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
    justify-content: space-between;
  }
  .private-toggle {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: 12px;
    color: #8b8b96;
    cursor: pointer;
  }
  .private-toggle input {
    accent-color: #818cf8;
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
  .search {
    background: #121217;
    border: 1px solid #2a2a32;
    border-radius: 8px;
    color: #e4e4e7;
    padding: 8px 12px;
    font-size: 13px;
    outline: none;
  }
  .clip-list {
    list-style: none;
    margin: 0;
    padding: 0;
    overflow-y: auto;
    flex: 1;
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
  .clip-meta {
    color: #5c5c66;
    font-size: 10px;
  }
  .clip-del {
    background: transparent;
    border: none;
    color: #5c5c66;
    cursor: pointer;
    padding: 0 8px;
    font-size: 12px;
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

  .toast {
    position: absolute;
    bottom: 12px;
    left: 12px;
    right: 12px;
    background: #6366f1;
    color: #fff;
    border-radius: 10px;
    padding: 10px 14px;
    cursor: pointer;
    box-shadow: 0 6px 20px rgba(99, 102, 241, 0.4);
  }
  .toast-sender {
    font-size: 11px;
    opacity: 0.8;
  }
  .toast-preview {
    font-size: 13px;
    margin-top: 2px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .toast-hint {
    font-size: 10px;
    opacity: 0.7;
    margin-top: 3px;
  }
</style>
