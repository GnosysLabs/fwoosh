<script lang="ts">
  import { onMount } from "svelte";
  import { invoke } from "@tauri-apps/api/core";
  import { listen, type UnlistenFn } from "@tauri-apps/api/event";
  import { getCurrentWindow } from "@tauri-apps/api/window";
  import { save } from "@tauri-apps/plugin-dialog";
  import { isPermissionGranted, requestPermission } from "@tauri-apps/plugin-notification";

  type Theme = "hacker" | "light" | "onyx";

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
  let activeView = $state<"compose" | "history" | "files">("compose");
  let devices = $state<DeviceDto[]>([]);
  let theme = $state<Theme>("hacker");
  let settingsOpen = $state(false);
  let devicesExpanded = $state(false);
  let confirmDeleteAllOpen = $state(false);
  let deletingAll = $state(false);
  let deviceLabel = $state("");
  let deviceLabelDraft = $state("");
  let savingDeviceLabel = $state(false);
  let stunServersText = $state("");
  let savingNetwork = $state(false);
  let fileHover = $state(false);
  let pendingFile = $state<DroppedFile | null>(null);
  let sendingFile = $state(false);
  let incomingFileOffer = $state<FileOfferDto | null>(null);
  let acceptingFile = $state(false);
  let transfers = $state<Record<string, TransferView>>({});
  let logoSrc = $derived(
    theme === "light"
      ? "/fwoosh_dark.webp"
      : theme === "onyx"
        ? "/fwoosh_onyx.webp"
        : "/fwoosh_light.webp"
  );
  let historySearching = $derived(query.trim().length > 0);
  let peerDevices = $derived(devices.filter((d) => !d.is_self));
  let transferList = $derived(Object.values(transfers));
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
  interface DroppedFile {
    path: string;
    name: string;
  }
  interface TransferDto {
    session_id: string;
    file_name: string;
    size: number;
    peer_label: string;
    direction: string;
    status: string;
  }
  interface FileOfferDto {
    session_id: string;
    sender_id: string;
    sender_label: string;
    file_name: string;
    size: number;
  }
  interface FileTransferProgressDto {
    session_id: string;
    transferred: number;
    total: number;
    status: string;
    message: string;
  }
  interface TransferView {
    session_id: string;
    file_name: string;
    peer_label: string;
    direction: string;
    transferred: number;
    total: number;
    status: string;
    message: string;
  }

  // ---- Load recent clips on mount + listen for events ----
  let unlisteners: Array<() => void | Promise<void>> = [];

  onMount(() => {
    const savedTheme = localStorage.getItem("fwoosh-theme");
    const preferredTheme =
      savedTheme === "dark"
        ? "hacker"
        : savedTheme === "light" || savedTheme === "hacker" || savedTheme === "onyx"
          ? savedTheme
        : window.matchMedia?.("(prefers-color-scheme: light)").matches
          ? "light"
          : "hacker";
    setTheme(preferredTheme);

    (async () => {
      try {
        deviceLabel = await invoke<string>("suggest_device_label");
        deviceLabelDraft = deviceLabel;
      } catch {
        deviceLabel = "This device";
        deviceLabelDraft = deviceLabel;
      }
      try {
        const network = await invoke<{ stun_servers: string[] }>("network_settings");
        stunServersText = network.stun_servers.join(", ");
      } catch {
        stunServersText = "stun:stun.cloudflare.com:3478";
      }
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
        await getCurrentWindow().onDragDropEvent((event) => {
          const payload = event.payload as
            | { type: "over"; position: { x: number; y: number } }
            | { type: "drop"; paths: string[]; position: { x: number; y: number } }
            | { type: "cancel" };
          if (payload.type === "over") {
            fileHover = true;
          } else if (payload.type === "drop") {
            fileHover = false;
            void handleDroppedPaths(payload.paths);
          } else {
            fileHover = false;
          }
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
      unlisteners.push(
        await listen("file-offer-received", (e) => {
          incomingFileOffer = e.payload as FileOfferDto;
        })
      );
      unlisteners.push(
        await listen("file-transfer-progress", (e) => {
          upsertTransferProgress(e.payload as FileTransferProgressDto);
        })
      );
      unlisteners.push(
        await listen("file-transfer-complete", (e) => {
          completeTransfer(e.payload as Record<string, unknown>);
        })
      );
      unlisteners.push(
        await listen("file-transfer-failed", (e) => {
          failTransfer(e.payload as FileTransferProgressDto);
        })
      );
      unlisteners.push(
        await listen("file-transfer-cancelled", (e) => {
          failTransfer(e.payload as FileTransferProgressDto);
        })
      );
    })();

    return () => unlisteners.forEach((u) => void u());
  });

  // ---- Actions ----
  function setTheme(next: Theme) {
    theme = next;
    document.documentElement.dataset.theme = next;
    document.documentElement.style.colorScheme = next === "light" ? "light" : "dark";
    localStorage.setItem("fwoosh-theme", next);
  }

  async function saveDeviceLabel() {
    if (savingDeviceLabel || !deviceLabelDraft.trim()) return;
    savingDeviceLabel = true;
    try {
      await invoke("rename_device", { label: deviceLabelDraft });
      deviceLabel = deviceLabelDraft.trim();
      status = "ok";
      statusMsg = "Device name updated";
      await refreshRoom();
      setTimeout(() => (status = "idle"), 2000);
    } catch (e) {
      status = "err";
      statusMsg = String(e);
    } finally {
      savingDeviceLabel = false;
    }
  }

  async function saveNetworkSettings() {
    if (savingNetwork) return;
    savingNetwork = true;
    try {
      const stunServers = stunServersText
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);
      await invoke("set_stun_servers", { stunServers });
      status = "ok";
      statusMsg = "Network settings updated";
      setTimeout(() => (status = "idle"), 2000);
    } catch (e) {
      status = "err";
      statusMsg = String(e);
    } finally {
      savingNetwork = false;
    }
  }

  function fileNameFromPath(path: string) {
    return path.split(/[\\/]/).filter(Boolean).pop() ?? "Dropped file";
  }

  async function handleDroppedPaths(paths: string[]) {
    if (!inRoom) {
      status = "err";
      statusMsg = "Pair another device before sending files";
      return;
    }
    if (paths.length !== 1) {
      status = "err";
      statusMsg = "Drop one file at a time";
      return;
    }
    const file = { path: paths[0], name: fileNameFromPath(paths[0]) };
    if (peerDevices.length === 0) {
      status = "err";
      statusMsg = "No paired device is available";
      return;
    }
    if (peerDevices.length === 1) {
      await sendFileTo(file, peerDevices[0].id);
      return;
    }
    pendingFile = file;
  }

  async function sendFileTo(file: DroppedFile, recipientId: string) {
    if (sendingFile) return;
    sendingFile = true;
    pendingFile = null;
    status = "ok";
    statusMsg = "Preparing file transfer";
    try {
      const transfer = await invoke<TransferDto>("start_file_send", {
        path: file.path,
        recipientId,
      });
      status = "idle";
      transfers = {
        ...transfers,
        [transfer.session_id]: {
          session_id: transfer.session_id,
          file_name: transfer.file_name,
          peer_label: transfer.peer_label,
          direction: transfer.direction,
          transferred: 0,
          total: transfer.size,
          status: transfer.status,
          message: "Waiting for recipient",
        },
      };
      activeView = "files";
    } catch (e) {
      status = "err";
      statusMsg = String(e);
    } finally {
      sendingFile = false;
    }
  }

  async function acceptIncomingFile() {
    if (!incomingFileOffer || acceptingFile) return;
    acceptingFile = true;
    try {
      const savePath = await save({ defaultPath: incomingFileOffer.file_name });
      if (!savePath) return;
      const offer = incomingFileOffer;
      incomingFileOffer = null;
      transfers = {
        ...transfers,
        [offer.session_id]: {
          session_id: offer.session_id,
          file_name: offer.file_name,
          peer_label: offer.sender_label,
          direction: "incoming",
          transferred: 0,
          total: offer.size,
          status: "connecting",
          message: "Preparing direct connection",
        },
      };
      activeView = "files";
      await invoke("accept_file_transfer", {
        sessionId: offer.session_id,
        savePath,
      });
    } catch (e) {
      status = "err";
      statusMsg = String(e);
    } finally {
      acceptingFile = false;
    }
  }

  async function rejectIncomingFile() {
    if (!incomingFileOffer) return;
    const offer = incomingFileOffer;
    incomingFileOffer = null;
    try {
      await invoke("reject_file_transfer", { sessionId: offer.session_id });
    } catch {
      /* best effort */
    }
  }

  async function cancelTransfer(sessionId: string) {
    try {
      await invoke("cancel_file_transfer", { sessionId });
    } catch {
      /* best effort */
    }
    const next = { ...transfers };
    delete next[sessionId];
    transfers = next;
  }

  function upsertTransferProgress(p: FileTransferProgressDto) {
    const existing = transfers[p.session_id];
    transfers = {
      ...transfers,
      [p.session_id]: {
        session_id: p.session_id,
        file_name: existing?.file_name ?? p.message,
        peer_label: existing?.peer_label ?? "",
        direction: existing?.direction ?? "transfer",
        transferred: p.transferred || existing?.transferred || 0,
        total: p.total || existing?.total || 0,
        status: p.status,
        message: p.message,
      },
    };
  }

  function completeTransfer(payload: Record<string, unknown>) {
    const sessionId = String(payload.session_id ?? "");
    if (!sessionId) return;
    const existing = transfers[sessionId];
    transfers = {
      ...transfers,
      [sessionId]: {
        session_id: sessionId,
        file_name: String(payload.file_name ?? existing?.file_name ?? "File"),
        peer_label: existing?.peer_label ?? "",
        direction: String(payload.direction ?? existing?.direction ?? "transfer"),
        transferred: Number(payload.size ?? existing?.total ?? 0),
        total: Number(payload.size ?? existing?.total ?? 0),
        status: "complete",
        message: "Complete",
      },
    };
  }

  function failTransfer(p: FileTransferProgressDto) {
    const existing = transfers[p.session_id];
    transfers = {
      ...transfers,
      [p.session_id]: {
        session_id: p.session_id,
        file_name: existing?.file_name ?? "File",
        peer_label: existing?.peer_label ?? "",
        direction: existing?.direction ?? "transfer",
        transferred: existing?.transferred ?? 0,
        total: existing?.total ?? 0,
        status: p.status,
        message: p.message,
      },
    };
  }

  function formatBytes(bytes: number) {
    if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
    const units = ["B", "KB", "MB", "GB", "TB"];
    let value = bytes;
    let unit = 0;
    while (value >= 1024 && unit < units.length - 1) {
      value /= 1024;
      unit += 1;
    }
    return `${value >= 10 || unit === 0 ? value.toFixed(0) : value.toFixed(1)} ${units[unit]}`;
  }

  function progressPct(t: TransferView) {
    if (!t.total) return 0;
    return Math.min(100, Math.round((t.transferred / t.total) * 100));
  }

  function clipPreview(value: string, maxLength = 180) {
    const compact = value.replace(/\s+/g, " ").trim();
    if (!compact) return "(blank clip)";
    if (compact.length <= maxLength) return compact;
    const boundary = compact.lastIndexOf(" ", maxLength);
    const cutAt = boundary >= Math.floor(maxLength * 0.55) ? boundary : maxLength;
    return `${compact.slice(0, cutAt).trimEnd()}...`;
  }

  function preferredDeviceLabel() {
    return deviceLabelDraft.trim() || deviceLabel.trim() || "This device";
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
      pairingUri = await invoke<string>("create_room", { label: preferredDeviceLabel() });
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
      if (pendingFile) {
        pendingFile = null;
        return;
      }
      if (incomingFileOffer) {
        void rejectIncomingFile();
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
      await invoke("join_room", { uri: joinUri, label: preferredDeviceLabel() });
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

<div class="card" class:file-hover={fileHover} data-tauri-drag-region>
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
      <button
        class="tab"
        class:active={activeView === "files"}
        onclick={() => (activeView = "files")}>Files</button
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
          <div class="settings-section">
            <label class="settings-title" for="device-name">Device name</label>
            <div class="settings-row">
              <input
                id="device-name"
                class="settings-input"
                maxlength="48"
                bind:value={deviceLabelDraft}
                onkeydown={(e) => {
                  e.stopPropagation();
                  if (e.key === "Enter") void saveDeviceLabel();
                }}
              />
              <button
                class="mini-action"
                onclick={saveDeviceLabel}
                disabled={savingDeviceLabel || !deviceLabelDraft.trim()}
              >
                {savingDeviceLabel ? "..." : "Save"}
              </button>
            </div>
          </div>
          <div class="settings-section">
            <div class="settings-title">Color scheme</div>
            <div class="scheme-toggle" role="radiogroup" aria-label="Color scheme">
              <button
                class:active={theme === "hacker"}
                role="radio"
                aria-checked={theme === "hacker"}
                onclick={() => setTheme("hacker")}>Hacker</button
              >
              <button
                class:active={theme === "light"}
                role="radio"
                aria-checked={theme === "light"}
                onclick={() => setTheme("light")}>Light</button
              >
              <button
                class:active={theme === "onyx"}
                role="radio"
                aria-checked={theme === "onyx"}
                onclick={() => setTheme("onyx")}>Onyx</button
              >
            </div>
          </div>
          <div class="settings-section">
            <label class="settings-title" for="stun-servers">STUN servers</label>
            <textarea
              id="stun-servers"
              class="settings-textarea"
              rows="2"
              bind:value={stunServersText}
              onkeydown={(e) => e.stopPropagation()}
            ></textarea>
            <button class="mini-action full" onclick={saveNetworkSettings} disabled={savingNetwork}>
              {savingNetwork ? "Saving..." : "Save network"}
            </button>
          </div>
        </div>
      {/if}
    </div>
  </header>

  {#if activeView === "compose"}
    <div class="compose" class:devices-open={inRoom && devicesExpanded}>
      <textarea
        bind:value={text}
        placeholder="Paste or type a message, or drag and drop a file to securely transfer it."
        class="box"
        data-tauri-drag-region="false"></textarea>

      <div class="compose-controls">
        {#if inRoom}
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
          </div>
        {:else}
          <span class="compose-control-spacer" aria-hidden="true"></span>
        {/if}
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
            <button class="unpair-btn" onclick={leaveRoom}>Unpair Device</button>
          </div>
        {/if}
      {/if}
    </div>
  {:else if activeView === "files"}
    <div class="files">
      {#if status !== "idle"}
        <div class="status" class:ok={status === "ok"} class:err={status === "err"}>
          {statusMsg}
        </div>
      {/if}
      {#if transferList.length > 0}
        <div class="transfer-list">
          {#each transferList as t (t.session_id)}
            <div class="transfer-item" class:complete={t.status === "complete"} class:failed={t.status === "failed" || t.status === "cancelled"}>
              <div class="transfer-head">
                <span class="transfer-file">{t.file_name}</span>
                <span class="transfer-progress">
                  {formatBytes(t.transferred)} / {formatBytes(t.total)}
                  {#if t.status === "complete"}
                    <svg class="transfer-check" viewBox="0 0 24 24" aria-label="Complete" role="img">
                      <path d="M20 6 9 17l-5-5" />
                    </svg>
                  {/if}
                </span>
                {#if t.status !== "complete" && t.status !== "failed" && t.status !== "cancelled"}
                  <button
                    class="transfer-cancel"
                    aria-label="Cancel transfer"
                    title="Cancel transfer"
                    onclick={() => cancelTransfer(t.session_id)}
                  >
                    <svg class="icon-svg" viewBox="0 0 24 24" aria-hidden="true">
                      <path d="M6 6l12 12" />
                      <path d="M18 6 6 18" />
                    </svg>
                  </button>
                {/if}
              </div>
              <div class="transfer-track" aria-hidden="true">
                <div class="transfer-fill" style={`width: ${progressPct(t)}%`}></div>
              </div>
              {#if t.status !== "complete"}
                <div class="transfer-message">
                  {t.direction === "incoming" ? "from" : "to"} {t.peer_label || "peer"}{t.message ? ` - ${t.message}` : ""}
                </div>
              {/if}
            </div>
          {/each}
        </div>
      {:else}
        <div class="files-empty muted">No files yet.</div>
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
        <div class="clip-list" role="list" aria-label="Clipboard history">
          {#each clips as c (c.id)}
            <div class="clip" role="listitem">
              <button
                class="clip-body"
                onclick={() => copyClip(c)}
                aria-label={`Copy clip: ${clipPreview(c.text)}`}
                title="Copy to clipboard"
              >
                <span class="clip-action">Copy clip</span>
                <span class="clip-text" class:searching={historySearching}>{clipPreview(c.text)}</span>
                <span class="clip-meta">{timeAgo(c.ts)} - {c.sender}</span>
              </button>
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
            </div>
          {/each}
        </div>
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

  {#if pendingFile}
    <div
      class="modal-overlay"
      role="button"
      tabindex="0"
      onclick={() => (pendingFile = null)}
      onkeydown={(e) => {
        if (e.key === "Escape" || e.key === "Enter") pendingFile = null;
      }}
    >
      <div
        class="transfer-dialog"
        role="dialog"
        tabindex="-1"
        aria-modal="true"
        aria-labelledby="send-file-title"
        onclick={(e) => e.stopPropagation()}
        onkeydown={(e) => e.stopPropagation()}
      >
        <h3 id="send-file-title">Send file</h3>
        <div class="transfer-file-card">
          <span class="transfer-file">{pendingFile.name}</span>
        </div>
        <div class="recipient-list">
          {#each peerDevices as d (d.id)}
            <button
              class="recipient-button"
              onclick={() => pendingFile && sendFileTo(pendingFile, d.id)}
              disabled={sendingFile}
            >
              <span class="recipient-name">{d.label}</span>
              <span class="recipient-meta">{d.id.slice(0, 8)}</span>
            </button>
          {/each}
        </div>
        <div class="dialog-actions">
          <button class="ghost" onclick={() => (pendingFile = null)} disabled={sendingFile}>
            Cancel
          </button>
        </div>
      </div>
    </div>
  {/if}

  {#if incomingFileOffer}
    <div
      class="modal-overlay"
      role="button"
      tabindex="0"
      onclick={rejectIncomingFile}
      onkeydown={(e) => {
        if (e.key === "Escape" || e.key === "Enter") void rejectIncomingFile();
      }}
    >
      <div
        class="transfer-dialog"
        role="dialog"
        tabindex="-1"
        aria-modal="true"
        aria-labelledby="incoming-file-title"
        onclick={(e) => e.stopPropagation()}
        onkeydown={(e) => e.stopPropagation()}
      >
        <h3 id="incoming-file-title">Incoming file</h3>
        <div class="transfer-file-card">
          <span class="transfer-file">{incomingFileOffer.file_name}</span>
          <span class="transfer-meta">
            {incomingFileOffer.sender_label} - {formatBytes(incomingFileOffer.size)}
          </span>
        </div>
        <div class="dialog-actions">
          <button class="ghost" onclick={rejectIncomingFile} disabled={acceptingFile}>
            Decline
          </button>
          <button class="send-btn" onclick={acceptIncomingFile} disabled={acceptingFile}>
            {acceptingFile ? "Opening..." : "Save"}
          </button>
        </div>
      </div>
    </div>
  {/if}

  {#if fileHover}
    <div class="drop-overlay" aria-hidden="true">
      <div class="drop-target">Drop file</div>
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

  <div class="footer-security" aria-label="End-to-end encrypted connection status">
    <span class="security-fragment" title="End-to-end encrypted">
      <svg class="icon-svg" viewBox="0 0 24 24" aria-hidden="true">
        <rect x="5" y="11" width="14" height="10" rx="2" />
        <path d="M8 11V8a4 4 0 0 1 8 0v3" />
      </svg>
      E2E
    </span>
    <span
      class="connection-indicator"
      class:live={inRoom}
      aria-label={inRoom ? "Connected" : "Not connected"}
      title={inRoom ? "Connected" : "Not connected"}
    ></span>
  </div>
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
    z-index: 30;
    width: 292px;
    max-width: calc(100vw - 24px);
    padding: 10px;
    background: #1f1f27;
    border: 1px solid #343440;
    border-radius: 8px;
    box-shadow: 0 14px 28px rgba(0, 0, 0, 0.42);
  }
  .settings-section {
    display: flex;
    flex-direction: column;
    gap: 7px;
    padding-bottom: 10px;
    margin-bottom: 10px;
    border-bottom: 1px solid #30303a;
  }
  .settings-section:last-child {
    padding-bottom: 0;
    margin-bottom: 0;
    border-bottom: none;
  }
  .settings-title {
    color: #a1a1aa;
    font-size: 11px;
    font-weight: 600;
  }
  .settings-row {
    display: grid;
    grid-template-columns: 1fr auto;
    gap: 6px;
    align-items: center;
  }
  .settings-input,
  .settings-textarea {
    min-width: 0;
    width: 100%;
    box-sizing: border-box;
    background: #14141a;
    border: 1px solid #30303a;
    color: #e4e4e7;
    border-radius: 7px;
    padding: 7px 8px;
    font: inherit;
    font-size: 12px;
    outline: none;
  }
  .settings-textarea {
    resize: vertical;
    min-height: 52px;
    line-height: 1.35;
  }
  .settings-input:focus,
  .settings-textarea:focus {
    border-color: #6366f1;
    box-shadow: 0 0 0 2px rgba(99, 102, 241, 0.16);
  }
  .mini-action {
    background: #2f3240;
    border: 1px solid #454858;
    color: #f4f4f5;
    border-radius: 7px;
    padding: 7px 9px;
    font-size: 12px;
    font-weight: 600;
    cursor: pointer;
    white-space: nowrap;
  }
  .mini-action.full {
    width: 100%;
  }
  .mini-action:hover:not(:disabled) {
    background: #3a3d4c;
  }
  .mini-action:disabled {
    opacity: 0.45;
    cursor: default;
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
  .transfer-list {
    display: flex;
    flex-direction: column;
    gap: 7px;
    max-height: 156px;
    overflow-y: auto;
    scrollbar-width: thin;
    scrollbar-color: #4b4b58 transparent;
  }
  .transfer-item {
    border: 1px solid #2f2f3a;
    border-radius: 8px;
    padding: 8px;
    background: #15151b;
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  .transfer-item.complete {
    border-color: rgba(52, 211, 153, 0.34);
  }
  .transfer-item.failed {
    border-color: rgba(248, 113, 113, 0.38);
  }
  .transfer-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
  }
  .transfer-file {
    color: #e4e4e7;
    font-size: 12px;
    font-weight: 600;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .transfer-meta,
  .transfer-message {
    color: #858590;
    font-size: 10px;
  }
  .transfer-track {
    height: 5px;
    overflow: hidden;
    border-radius: 999px;
    background: #292934;
  }
  .transfer-fill {
    height: 100%;
    background: #22c55e;
    border-radius: inherit;
    transition: width 0.18s ease;
  }
  .transfer-item.failed .transfer-fill {
    background: #ef4444;
  }
  .transfer-cancel {
    width: 26px;
    height: 26px;
    flex: 0 0 26px;
    display: grid;
    place-items: center;
    background: transparent;
    border: 1px solid #393945;
    color: #9ca3af;
    border-radius: 7px;
    cursor: pointer;
  }
  .transfer-cancel:hover,
  .transfer-cancel:focus-visible {
    border-color: #f87171;
    color: #f87171;
    outline: none;
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

  .history,
  .files {
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
  .files-empty {
    flex: 1;
    display: grid;
    place-items: center;
    text-align: center;
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
  .transfer-list::-webkit-scrollbar,
  .box::-webkit-scrollbar,
  .pair-code::-webkit-scrollbar {
    width: 8px;
    height: 8px;
  }
  .clip-list::-webkit-scrollbar-track,
  .transfer-list::-webkit-scrollbar-track,
  .box::-webkit-scrollbar-track,
  .pair-code::-webkit-scrollbar-track {
    background: transparent;
  }
  .clip-list::-webkit-scrollbar-thumb,
  .transfer-list::-webkit-scrollbar-thumb,
  .box::-webkit-scrollbar-thumb,
  .pair-code::-webkit-scrollbar-thumb {
    background: #3b3b46;
    border: 2px solid transparent;
    border-radius: 999px;
    background-clip: padding-box;
  }
  .clip-list::-webkit-scrollbar-thumb:hover,
  .transfer-list::-webkit-scrollbar-thumb:hover,
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
  .transfer-dialog {
    width: 86%;
    max-height: 86vh;
    overflow: hidden;
    background: #1a1a1f;
    border: 1px solid #343440;
    border-radius: 12px;
    padding: 18px;
    box-shadow: 0 18px 40px rgba(0, 0, 0, 0.48);
    display: flex;
    flex-direction: column;
    gap: 12px;
  }
  .confirm-dialog h3 {
    margin: 0;
    color: #f4f4f5;
    font-size: 15px;
  }
  .transfer-dialog h3 {
    margin: 0;
    color: #f4f4f5;
    font-size: 15px;
  }
  .transfer-file-card {
    min-width: 0;
    border: 1px solid #2f2f3a;
    border-radius: 8px;
    background: #14141a;
    padding: 9px;
    display: flex;
    flex-direction: column;
    gap: 3px;
  }
  .recipient-list {
    display: flex;
    flex-direction: column;
    gap: 7px;
    max-height: 190px;
    overflow-y: auto;
    scrollbar-width: thin;
    scrollbar-color: #4b4b58 transparent;
  }
  .recipient-button {
    width: 100%;
    border: 1px solid #343440;
    border-radius: 8px;
    background: #202028;
    color: #e4e4e7;
    padding: 9px 10px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
    cursor: pointer;
    text-align: left;
  }
  .recipient-button:hover:not(:disabled),
  .recipient-button:focus-visible {
    border-color: #6366f1;
    background: #262637;
    outline: none;
  }
  .recipient-button:disabled {
    opacity: 0.45;
    cursor: default;
  }
  .recipient-name {
    min-width: 0;
    color: #f4f4f5;
    font-size: 13px;
    font-weight: 600;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .recipient-meta {
    color: #858590;
    font-size: 10px;
    font-variant-numeric: tabular-nums;
  }
  .dialog-actions {
    display: flex;
    justify-content: flex-end;
    gap: 8px;
  }
  .drop-overlay {
    position: absolute;
    inset: 0;
    z-index: 24;
    display: grid;
    place-items: center;
    pointer-events: none;
    background: rgba(6, 8, 16, 0.58);
  }
  .drop-target {
    width: calc(100% - 44px);
    height: calc(100% - 88px);
    border: 2px dashed rgba(129, 140, 248, 0.8);
    border-radius: 12px;
    display: grid;
    place-items: center;
    color: #f4f4f5;
    background: rgba(20, 20, 26, 0.74);
    font-size: 15px;
    font-weight: 700;
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
  :global(html[data-theme="light"]) .transfer-meta,
  :global(html[data-theme="light"]) .transfer-message,
  :global(html[data-theme="light"]) .recipient-meta,
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
  :global(html[data-theme="light"]) .settings-section {
    border-bottom-color: #d8e2ef;
  }
  :global(html[data-theme="light"]) .settings-input,
  :global(html[data-theme="light"]) .settings-textarea,
  :global(html[data-theme="light"]) .mini-action,
  :global(html[data-theme="light"]) .transfer-item,
  :global(html[data-theme="light"]) .transfer-file-card,
  :global(html[data-theme="light"]) .recipient-button {
    background: #ffffff;
    border-color: #c6d3e3;
    color: #102033;
  }
  :global(html[data-theme="light"]) .mini-action:hover:not(:disabled),
  :global(html[data-theme="light"]) .recipient-button:hover:not(:disabled),
  :global(html[data-theme="light"]) .recipient-button:focus-visible {
    background: #edf4fb;
    border-color: #0757c7;
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
  :global(html[data-theme="light"]) .search:focus,
  :global(html[data-theme="light"]) .settings-input:focus,
  :global(html[data-theme="light"]) .settings-textarea:focus {
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
  :global(html[data-theme="light"]) .transfer-track {
    background: #d8e2ef;
  }
  :global(html[data-theme="light"]) .transfer-cancel {
    border-color: #c6d3e3;
    color: #607089;
  }
  :global(html[data-theme="light"]) .transfer-cancel:hover,
  :global(html[data-theme="light"]) .transfer-cancel:focus-visible {
    border-color: #b42318;
    color: #b42318;
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
  :global(html[data-theme="light"]) .transfer-file,
  :global(html[data-theme="light"]) .recipient-name,
  :global(html[data-theme="light"]) .pairing-card h3 {
    color: #102033;
  }
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
  :global(html[data-theme="light"]) .transfer-list::-webkit-scrollbar-thumb,
  :global(html[data-theme="light"]) .box::-webkit-scrollbar-thumb,
  :global(html[data-theme="light"]) .pair-code::-webkit-scrollbar-thumb {
    background: #aab8ca;
    background-clip: padding-box;
  }
  :global(html[data-theme="light"]) .clip-list::-webkit-scrollbar-thumb:hover,
  :global(html[data-theme="light"]) .transfer-list::-webkit-scrollbar-thumb:hover,
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
  :global(html[data-theme="light"]) .transfer-dialog {
    background: #ffffff;
    border-color: #cbd8e8;
    box-shadow: 0 18px 40px rgba(30, 41, 59, 0.2);
  }
  :global(html[data-theme="light"]) .confirm-dialog h3,
  :global(html[data-theme="light"]) .transfer-dialog h3 {
    color: #102033;
  }
  :global(html[data-theme="light"]) .drop-overlay {
    background: rgba(15, 23, 42, 0.32);
  }
  :global(html[data-theme="light"]) .drop-target {
    background: rgba(255, 255, 255, 0.82);
    border-color: rgba(7, 87, 199, 0.68);
    color: #102033;
  }
  :global(html[data-theme="light"]) .danger-btn {
    background: #b42318;
  }
  :global(html[data-theme="light"]) .danger-btn:hover:not(:disabled) {
    background: #8f1d14;
  }

  /* Reference-style shell skin. Kept last so it restyles the existing flows
     without disturbing the current component logic. */
  .card {
    --window-radius: 30px;
    --footer-safe: 30px;
    --window-stroke: rgba(74, 101, 54, 0.78);
    --shell-bg: #020702;
    --shell-top: #071109;
    --panel: #050b06;
    --panel-raised: #0a1309;
    --field: #020703;
    --field-strong: #0d160c;
    --line: rgba(72, 94, 53, 0.68);
    --line-soft: rgba(68, 88, 51, 0.46);
    --line-strong: rgba(139, 197, 72, 0.62);
    --text: #d9ded2;
    --text-strong: #f4f7eb;
    --muted: #aeb5aa;
    --muted-soft: #757d72;
    --accent: #c7ff00;
    --accent-hover: #d9ff43;
    --accent-text: #071003;
    --mint: #75efad;
    --mint-panel: rgba(48, 130, 83, 0.28);
    --danger: #ff7d7d;
    --danger-panel: rgba(91, 30, 29, 0.62);
    --danger-line: rgba(255, 125, 125, 0.46);
    --focus: rgba(199, 255, 0, 0.2);
    background:
      linear-gradient(180deg, var(--shell-top) 0%, var(--shell-bg) 58%),
      var(--shell-bg);
    border-radius: var(--window-radius);
    background-clip: padding-box;
    clip-path: inset(0 round var(--window-radius));
    color: var(--text);
    font-family: "Aptos Display", "Segoe UI Variable", "Segoe UI", system-ui, sans-serif;
    box-shadow:
      inset 0 0 0 1px rgba(207, 255, 114, 0.08),
      inset 0 0 38px rgba(145, 191, 80, 0.045);
  }
  .card::before {
    inset: 4px;
    border-color: var(--window-stroke);
    border-radius: calc(var(--window-radius) - 4px);
    box-shadow: inset 0 0 26px rgba(145, 191, 80, 0.08);
  }

  :global(html[data-theme="light"]) .card {
    --window-stroke: rgba(73, 128, 129, 0.28);
    --shell-bg: #f8f1df;
    --shell-top: #fffaf0;
    --panel: rgba(255, 251, 239, 0.92);
    --panel-raised: rgba(236, 251, 242, 0.82);
    --field: rgba(255, 253, 246, 0.78);
    --field-strong: rgba(237, 249, 240, 0.78);
    --line: rgba(49, 103, 101, 0.22);
    --line-soft: rgba(49, 103, 101, 0.13);
    --line-strong: rgba(0, 174, 184, 0.46);
    --text: #264252;
    --text-strong: #0d2d38;
    --muted: #65746f;
    --muted-soft: #8b958d;
    --accent: #00aeb8;
    --accent-hover: #16cbd0;
    --accent-text: #062d31;
    --mint: #00aeb8;
    --mint-panel: rgba(0, 174, 184, 0.13);
    --danger: #b42318;
    --danger-panel: rgba(254, 226, 226, 0.92);
    --danger-line: rgba(180, 35, 24, 0.3);
    --focus: rgba(0, 174, 184, 0.16);
    background:
      radial-gradient(circle at 18% 6%, rgba(122, 246, 255, 0.32), transparent 30%),
      radial-gradient(circle at 88% 18%, rgba(255, 214, 232, 0.34), transparent 34%),
      radial-gradient(circle at 38% 100%, rgba(255, 238, 172, 0.42), transparent 42%),
      linear-gradient(145deg, var(--shell-top) 0%, #f3f9eb 48%, var(--shell-bg) 100%),
      var(--shell-bg);
    box-shadow:
      inset 0 0 0 1px rgba(255, 255, 255, 0.72),
      inset 0 0 40px rgba(255, 255, 255, 0.42);
  }

  :global(html[data-theme="onyx"]) .card {
    --window-stroke: rgba(255, 255, 255, 0.18);
    --shell-bg: #000000;
    --shell-top: #050505;
    --panel: #040404;
    --panel-raised: #090909;
    --field: #010101;
    --field-strong: #070707;
    --line: rgba(255, 255, 255, 0.13);
    --line-soft: rgba(255, 255, 255, 0.08);
    --line-strong: rgba(255, 255, 255, 0.56);
    --text: #dedede;
    --text-strong: #ffffff;
    --muted: #a0a0a0;
    --muted-soft: #6e6e6e;
    --accent: #ffffff;
    --accent-hover: #ffffff;
    --accent-text: #ffffff;
    --mint: #ffffff;
    --mint-panel: rgba(255, 255, 255, 0.075);
    --danger: #ffffff;
    --danger-panel: rgba(255, 255, 255, 0.055);
    --danger-line: rgba(255, 255, 255, 0.2);
    --focus: rgba(255, 255, 255, 0.18);
    background:
      radial-gradient(circle at 50% -16%, rgba(255, 255, 255, 0.12), transparent 38%),
      radial-gradient(circle at 92% 8%, rgba(255, 255, 255, 0.06), transparent 30%),
      linear-gradient(180deg, var(--shell-top) 0%, #010101 42%, var(--shell-bg) 100%),
      var(--shell-bg);
    box-shadow:
      inset 0 1px 0 rgba(255, 255, 255, 0.12),
      inset 0 -42px 80px rgba(255, 255, 255, 0.02);
  }

  .header {
    display: grid;
    grid-template-columns: minmax(132px, 1fr) auto auto;
    gap: 12px;
    min-height: 70px;
    padding: 13px 20px;
    border-bottom-color: var(--line-soft);
    background: rgba(0, 0, 0, 0.02);
    box-sizing: border-box;
  }
  :global(html[data-theme="onyx"]) .header {
    background:
      linear-gradient(180deg, rgba(0, 0, 0, 0.94), rgba(0, 0, 0, 0.64)),
      var(--shell-top);
    border-bottom-color: rgba(255, 255, 255, 0.09);
  }
  .title {
    color: var(--text-strong);
    letter-spacing: 0;
  }
  .brand-logo {
    width: 126px;
    height: 38px;
  }
  .tabs {
    align-items: center;
    align-self: center;
    gap: 3px;
    padding: 3px;
    border: 1px solid var(--line-soft);
    border-radius: 999px;
    background: var(--field);
  }
  .tab {
    height: 30px;
    padding: 0 13px;
    border-radius: 999px;
    color: var(--muted);
    font-size: 12px;
    font-weight: 800;
    letter-spacing: 0;
  }
  .tab.active,
  .tab:hover {
    background: var(--field-strong);
    color: var(--accent);
  }
  :global(html[data-theme="light"]) .tab.active,
  :global(html[data-theme="light"]) .tab:hover {
    color: var(--text-strong);
  }
  .window-actions {
    align-self: center;
    gap: 10px;
  }
  .icon-btn {
    width: 40px;
    height: 40px;
    border: 1px solid var(--line);
    border-radius: 15px;
    background: var(--field-strong);
    color: var(--muted);
    transition:
      background 0.15s ease,
      border-color 0.15s ease,
      color 0.15s ease,
      transform 0.15s ease;
  }
  .icon-btn .icon-svg {
    width: 20px;
    height: 20px;
    stroke-width: 2.4;
  }
  .icon-btn:hover,
  .icon-btn:focus-visible {
    background: var(--panel-raised);
    border-color: var(--line-strong);
    color: var(--text-strong);
    outline: none;
    transform: translateY(-1px);
  }
  .close-btn {
    background: var(--danger-panel);
    border-color: var(--danger-line);
    color: var(--danger);
  }
  .close-btn:hover,
  .close-btn:focus-visible {
    border-color: var(--danger);
    color: var(--danger);
  }

  .settings-menu {
    top: 54px;
    right: 0;
    width: min(326px, calc(100vw - 34px));
    padding: 14px;
    border: 1px solid var(--line);
    border-radius: 22px;
    background: var(--panel);
    box-shadow: 0 22px 48px rgba(0, 0, 0, 0.5);
  }
  .settings-section {
    gap: 9px;
    border-bottom-color: var(--line-soft);
  }
  .settings-title {
    color: var(--muted);
    font-size: 12px;
    letter-spacing: 0;
  }
  .settings-input,
  .settings-textarea,
  .join-input,
  .search,
  .pair-code {
    border: 1px solid var(--line);
    border-radius: 15px;
    background: var(--field);
    color: var(--text);
  }
  .settings-input,
  .settings-textarea {
    padding: 9px 11px;
  }
  .settings-input:focus,
  .settings-textarea:focus,
  .join-input:focus,
  .search:focus,
  .box:focus {
    border-color: var(--line-strong);
    box-shadow: 0 0 0 3px var(--focus);
  }
  .scheme-toggle {
    gap: 6px;
  }
  .scheme-toggle button,
  .mini-action,
  .ghost,
  .unpair-btn {
    border: 1px solid var(--line);
    border-radius: 999px;
    background: var(--field-strong);
    color: var(--text);
    font-weight: 800;
  }
  .scheme-toggle button {
    flex: 1 1 0;
    padding: 8px 10px;
  }
  .scheme-toggle button.active,
  .mini-action:hover:not(:disabled),
  .ghost:hover,
  .unpair-btn:hover {
    border-color: var(--line-strong);
    background: var(--mint-panel);
    color: var(--accent);
  }
  :global(html[data-theme="light"]) .scheme-toggle button.active,
  :global(html[data-theme="light"]) .mini-action:hover:not(:disabled),
  :global(html[data-theme="light"]) .ghost:hover {
    color: var(--text-strong);
  }
  :global(html[data-theme="light"]) .scheme-toggle button.active {
    background: linear-gradient(135deg, #a6f7fa 0%, #46d7de 54%, #c8fff0 100%);
    border-color: rgba(0, 174, 184, 0.58);
    color: #063238;
    box-shadow:
      inset 0 1px 0 rgba(255, 255, 255, 0.72),
      0 0 0 1px rgba(255, 255, 255, 0.3);
  }
  :global(html[data-theme="light"]) .settings-menu,
  :global(html[data-theme="light"]) .pairing-card,
  :global(html[data-theme="light"]) .confirm-dialog,
  :global(html[data-theme="light"]) .transfer-dialog {
    background:
      radial-gradient(circle at 10% 0%, rgba(147, 247, 255, 0.2), transparent 42%),
      linear-gradient(145deg, rgba(255, 253, 246, 0.97), rgba(245, 252, 238, 0.92));
    backdrop-filter: blur(16px);
  }
  :global(html[data-theme="light"]) .box,
  :global(html[data-theme="light"]) .join-input,
  :global(html[data-theme="light"]) .search,
  :global(html[data-theme="light"]) .settings-input,
  :global(html[data-theme="light"]) .settings-textarea {
    background:
      linear-gradient(135deg, rgba(255, 255, 250, 0.92), rgba(248, 254, 240, 0.8)),
      var(--field);
  }
  :global(html[data-theme="light"]) .send-btn,
  :global(html[data-theme="light"]) .toast {
    background: var(--accent);
    color: var(--accent-text);
  }
  :global(html[data-theme="light"]) .send-btn:hover:not(:disabled) {
    background: var(--accent-hover);
  }
  :global(html[data-theme="onyx"]) .scheme-toggle button,
  :global(html[data-theme="onyx"]) .mini-action,
  :global(html[data-theme="onyx"]) .ghost,
  :global(html[data-theme="onyx"]) .send-btn,
  :global(html[data-theme="onyx"]) .device-toggle,
  :global(html[data-theme="onyx"]) .pair-btn,
  :global(html[data-theme="onyx"]) .icon-btn,
  :global(html[data-theme="onyx"]) .tab.active,
  :global(html[data-theme="onyx"]) .tab:hover,
  :global(html[data-theme="onyx"]) .danger-btn,
  :global(html[data-theme="onyx"]) .danger-icon-btn,
  :global(html[data-theme="onyx"]) .transfer-cancel,
  :global(html[data-theme="onyx"]) .recipient-button,
  :global(html[data-theme="onyx"]) .toast-dismiss {
    background:
      linear-gradient(180deg, rgba(255, 255, 255, 0.075), rgba(255, 255, 255, 0.018)),
      #020202;
    border-color: rgba(255, 255, 255, 0.18);
    color: #ffffff;
    box-shadow:
      inset 0 1px 0 rgba(255, 255, 255, 0.12),
      inset 0 -1px 0 rgba(255, 255, 255, 0.035);
  }
  :global(html[data-theme="onyx"]) .scheme-toggle button.active,
  :global(html[data-theme="onyx"]) .mini-action:hover:not(:disabled),
  :global(html[data-theme="onyx"]) .ghost:hover,
  :global(html[data-theme="onyx"]) .send-btn:hover:not(:disabled),
  :global(html[data-theme="onyx"]) .device-toggle:hover,
  :global(html[data-theme="onyx"]) .device-toggle:focus-visible,
  :global(html[data-theme="onyx"]) .pair-btn:hover,
  :global(html[data-theme="onyx"]) .icon-btn:hover,
  :global(html[data-theme="onyx"]) .icon-btn:focus-visible,
  :global(html[data-theme="onyx"]) .tab.active,
  :global(html[data-theme="onyx"]) .tab:hover,
  :global(html[data-theme="onyx"]) .danger-btn:hover:not(:disabled),
  :global(html[data-theme="onyx"]) .danger-icon-btn:hover:not(:disabled),
  :global(html[data-theme="onyx"]) .danger-icon-btn:focus-visible,
  :global(html[data-theme="onyx"]) .transfer-cancel:hover,
  :global(html[data-theme="onyx"]) .transfer-cancel:focus-visible,
  :global(html[data-theme="onyx"]) .recipient-button:hover:not(:disabled),
  :global(html[data-theme="onyx"]) .recipient-button:focus-visible,
  :global(html[data-theme="onyx"]) .toast-dismiss:hover {
    background:
      linear-gradient(180deg, rgba(255, 255, 255, 0.12), rgba(255, 255, 255, 0.035)),
      #040404;
    border-color: rgba(255, 255, 255, 0.44);
    color: #ffffff;
  }
  :global(html[data-theme="onyx"]) .send-btn,
  :global(html[data-theme="onyx"]) .toast {
    color: #ffffff;
  }
  :global(html[data-theme="onyx"]) .send-btn {
    border: 1px solid rgba(255, 255, 255, 0.34);
    text-shadow: 0 0 14px rgba(255, 255, 255, 0.32);
  }
  :global(html[data-theme="onyx"]) .toast {
    background:
      linear-gradient(180deg, rgba(255, 255, 255, 0.08), rgba(255, 255, 255, 0.025)),
      #020202;
    border-color: rgba(255, 255, 255, 0.32);
  }

  .compose {
    padding: 18px 20px;
    gap: 10px;
  }
  .box {
    flex: 1 1 126px;
    min-height: 120px;
    padding: 22px;
    border: 1px solid var(--line);
    border-radius: 24px;
    background: var(--field);
    color: var(--text);
    font-size: 18px;
    font-weight: 600;
    line-height: 1.45;
  }
  .box::placeholder,
  .join-input::placeholder,
  .search::placeholder {
    color: var(--muted);
    opacity: 1;
  }
  .compose-controls {
    justify-content: flex-end;
    min-height: 46px;
  }
  .send-btn {
    min-width: 116px;
    height: 46px;
    padding: 0 26px;
    border-radius: 999px;
    background: var(--accent);
    color: var(--accent-text);
    font-size: 18px;
    font-weight: 900;
    box-shadow: none;
    transition:
      background 0.15s ease,
      transform 0.15s ease,
      opacity 0.15s ease;
  }
  .send-btn:hover:not(:disabled) {
    background: var(--accent-hover);
    transform: translateY(-1px);
  }
  .send-btn:disabled {
    opacity: 0.64;
  }
  .dialog-actions .send-btn,
  .pairing-card .send-btn {
    min-width: 92px;
    height: 40px;
    padding: 0 18px;
    font-size: 14px;
  }

  .devices-panel {
    gap: 10px;
  }
  .device-toggle {
    height: 48px;
    min-width: 126px;
    padding: 0 20px;
    gap: 9px;
    border: 1px solid rgba(199, 255, 0, 0.48);
    border-radius: 999px;
    background: rgba(199, 255, 0, 0.1);
    color: var(--accent);
    font-size: 17px;
    font-weight: 900;
  }
  .device-toggle .icon-svg {
    width: 18px;
    height: 18px;
    stroke-width: 3;
  }
  .device-toggle:hover,
  .device-toggle:focus-visible {
    background: rgba(199, 255, 0, 0.16);
    border-color: var(--accent);
    color: var(--accent);
  }
  :global(html[data-theme="light"]) .device-toggle {
    border-color: rgba(11, 95, 211, 0.32);
    background: rgba(11, 95, 211, 0.08);
    color: var(--accent);
  }
  :global(html[data-theme="onyx"]) .device-toggle {
    border-color: rgba(255, 255, 255, 0.32);
    color: #ffffff;
  }
  :global(html[data-theme="onyx"]) .device-toggle:hover,
  :global(html[data-theme="onyx"]) .device-toggle:focus-visible {
    border-color: rgba(255, 255, 255, 0.56);
    color: #ffffff;
  }
  .roster {
    display: flex;
    flex-direction: column;
    gap: 9px;
    border: none;
    border-radius: 0;
    overflow: visible;
  }
  .pair-btn,
  .device-row,
  .transfer-item,
  .transfer-file-card,
  .recipient-button {
    border: 1px solid var(--line-soft);
    border-radius: 18px;
    background: var(--field-strong);
    color: var(--text);
  }
  .pair-btn {
    padding: 12px 16px;
    border-bottom: 1px solid var(--line-soft);
    color: var(--accent);
    font-weight: 900;
  }
  .pair-btn:hover {
    background: var(--mint-panel);
  }
  .device-row {
    padding: 12px 16px;
    border-bottom: 1px solid var(--line-soft);
  }
  .device-label,
  .clip-text,
  .transfer-file,
  .recipient-name,
  .pairing-card h3,
  .confirm-dialog h3,
  .transfer-dialog h3 {
    color: var(--text-strong);
  }
  .device-label {
    font-size: 15px;
    font-weight: 900;
  }
  .device-meta,
  .transfer-meta,
  .transfer-message,
  .recipient-meta,
  .clip-meta,
  .muted {
    color: var(--muted);
  }
  .revoke-btn,
  .danger-icon-btn,
  .transfer-cancel,
  .clip-del,
  .unpair-btn {
    color: var(--danger);
  }
  .revoke-btn,
  .danger-icon-btn,
  .transfer-cancel {
    border-color: var(--danger-line);
    border-radius: 14px;
    background: var(--danger-panel);
  }
  .status {
    border: 1px solid var(--line-soft);
    border-radius: 16px;
    padding: 9px 12px;
    font-weight: 800;
  }
  .status.ok {
    background: var(--mint-panel);
    color: var(--mint);
  }
  .status.err {
    background: var(--danger-panel);
    color: var(--danger);
  }
  .transfer-list,
  .recipient-list,
  .clip-list {
    scrollbar-color: var(--line-strong) transparent;
  }
  .transfer-track {
    background: rgba(117, 125, 114, 0.22);
  }
  .transfer-fill {
    background: var(--mint);
  }
  .transfer-check {
    width: 13px;
    height: 13px;
    color: var(--mint);
    fill: none;
    stroke: currentColor;
    stroke-linecap: round;
    stroke-linejoin: round;
    stroke-width: 3;
  }

  .room-empty {
    padding: 2px 4px 0;
  }
  .room-empty .muted {
    margin: 0 0 8px;
  }
  .room-actions {
    margin-top: 8px;
  }
  .join-input {
    height: 38px;
    padding: 0 14px;
    font-size: 13px;
  }
  .divider {
    color: var(--muted-soft);
    margin: 8px 0 6px;
  }
  .room-empty .ghost {
    min-height: 38px;
    padding: 0 16px;
  }
  .divider::before,
  .divider::after {
    background: var(--line-soft);
  }

  .history,
  .files {
    padding: 20px 22px 22px;
    gap: 12px;
  }
  .history-toolbar {
    grid-template-columns: 1fr 44px;
    gap: 10px;
  }
  .files .transfer-list {
    flex: 1;
    max-height: none;
    min-height: 0;
  }
  .files-empty {
    border: 1px solid var(--line-soft);
    border-radius: 18px;
    background: var(--field);
    font-size: 13px;
  }
  .search {
    height: 44px;
    padding: 0 16px;
    font-size: 14px;
  }
  .danger-icon-btn {
    width: 44px;
    height: 44px;
  }
  .clip-list {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }
  .clip {
    border-bottom: none;
    border: 1px solid var(--line-soft);
    border-radius: 18px;
    background: var(--field-strong);
    overflow: hidden;
  }
  .clip-body {
    padding: 12px 14px 12px 2px;
  }
  .clip-text {
    font-size: 14px;
    font-weight: 800;
  }
  .clip-del {
    min-width: 42px;
    width: 42px;
  }

  .pairing-overlay,
  .modal-overlay {
    background: rgba(0, 0, 0, 0.68);
    backdrop-filter: blur(10px);
  }
  :global(html[data-theme="light"]) .pairing-overlay,
  :global(html[data-theme="light"]) .modal-overlay {
    background: rgba(13, 31, 50, 0.24);
  }
  .pairing-card,
  .confirm-dialog,
  .transfer-dialog {
    border: 1px solid var(--line);
    border-radius: 24px;
    background: var(--panel);
    box-shadow: 0 24px 54px rgba(0, 0, 0, 0.46);
  }
  .pair-code {
    padding: 10px;
    color: var(--accent);
  }
  .recipient-button:hover:not(:disabled),
  .recipient-button:focus-visible {
    border-color: var(--line-strong);
    background: var(--mint-panel);
  }
  .danger-btn {
    height: 40px;
    padding: 0 16px;
    border-radius: 999px;
    background: var(--danger);
    color: #ffffff;
    font-weight: 900;
  }
  .danger-btn:hover:not(:disabled) {
    background: #d63a32;
  }

  .drop-overlay {
    background: rgba(0, 0, 0, 0.62);
    backdrop-filter: blur(8px);
  }
  .drop-target {
    width: calc(100% - 52px);
    height: calc(100% - 112px);
    border: 2px dashed var(--accent);
    border-radius: 26px;
    background: rgba(5, 11, 6, 0.82);
    color: var(--accent);
    font-size: 22px;
    font-weight: 900;
  }
  :global(html[data-theme="light"]) .drop-target {
    background: rgba(255, 255, 255, 0.84);
    color: var(--accent);
  }

  .toast {
    left: 22px;
    right: 52px;
    bottom: 18px;
    border: 1px solid var(--line-strong);
    border-radius: 20px;
    background: var(--accent);
    color: var(--accent-text);
    box-shadow: 0 18px 34px rgba(0, 0, 0, 0.32);
  }
  .toast-copy {
    padding: 12px 12px 12px 16px;
  }
  .toast-dismiss {
    border-radius: 14px;
  }
  .connection-indicator {
    right: 16px;
    bottom: 16px;
    width: 12px;
    height: 12px;
    background: var(--muted-soft);
    box-shadow: 0 0 0 3px var(--shell-bg);
  }
  .connection-indicator.live {
    background: var(--mint);
    box-shadow:
      0 0 0 3px var(--shell-bg),
      0 0 15px rgba(117, 239, 173, 0.8);
  }
  :global(html[data-theme="onyx"]) .connection-indicator.live {
    box-shadow:
      0 0 0 3px var(--shell-bg),
      0 0 15px rgba(255, 255, 255, 0.74);
  }

  .card {
    font-family: "Geist", "Segoe UI", system-ui, sans-serif;
  }
  .card button,
  .card input,
  .card textarea {
    font-family: inherit;
  }
  .tab,
  .send-btn,
  .device-toggle,
  .pair-btn,
  .unpair-btn,
  .mini-action,
  .ghost,
  .danger-btn,
  .status,
  .settings-title,
  .security-fragment {
    font-weight: 500;
  }
  .box,
  .device-label,
  .clip-text,
  .transfer-file,
  .recipient-name,
  .muted,
  .device-meta,
  .transfer-meta,
  .transfer-message,
  .recipient-meta,
  .clip-meta {
    font-weight: 400;
  }

  .header {
    min-height: 62px;
    padding: 10px 16px;
    gap: 10px;
  }
  .brand-logo {
    width: 118px;
    height: 34px;
  }
  .tabs {
    padding: 2px;
  }
  .tab {
    height: 28px;
    padding: 0 11px;
    font-size: 11px;
  }
  .window-actions {
    gap: 8px;
  }
  .icon-btn {
    width: 36px;
    height: 36px;
    border-radius: 13px;
  }
  .icon-btn .icon-svg {
    width: 18px;
    height: 18px;
    stroke-width: 2.2;
  }

  .settings-menu {
    top: 48px;
    width: min(302px, calc(100vw - 30px));
    padding: 12px;
    border-radius: 18px;
  }
  .settings-section {
    gap: 7px;
    padding-bottom: 8px;
    margin-bottom: 8px;
  }
  .settings-title {
    font-size: 11px;
  }
  .settings-input,
  .settings-textarea {
    padding: 8px 10px;
    font-size: 12px;
  }
  .scheme-toggle button,
  .mini-action {
    padding: 7px 9px;
    font-size: 12px;
  }
  .scheme-toggle button {
    min-width: 0;
    padding-inline: 7px;
  }

  .compose {
    padding: 14px 18px calc(12px + var(--footer-safe));
    gap: 8px;
  }
  .compose.devices-open {
    gap: 7px;
  }
  .box {
    flex: 1 1 112px;
    min-height: 104px;
    padding: 16px 18px;
    border-radius: 20px;
    font-size: 15px;
    line-height: 1.42;
  }
  .compose.devices-open .box {
    flex: 0 1 84px;
    min-height: 84px;
    padding-block: 12px;
  }
  .compose-controls {
    justify-content: space-between;
    min-height: 40px;
    gap: 12px;
  }
  .compose-control-spacer {
    flex: 1;
    min-width: 1px;
    height: 1px;
  }
  .send-btn {
    min-width: 96px;
    height: 40px;
    padding: 0 20px;
    font-size: 14px;
  }
  .dialog-actions .send-btn,
  .pairing-card .send-btn {
    min-width: 82px;
    height: 36px;
    padding: 0 16px;
    font-size: 13px;
  }

  .devices-panel {
    margin: 0;
    align-self: center;
  }
  .devices-compact {
    display: flex;
  }
  .device-toggle {
    height: 40px;
    min-width: 108px;
    padding: 0 16px;
    gap: 7px;
    font-size: 14px;
  }
  .device-toggle .icon-svg {
    width: 16px;
    height: 16px;
    stroke-width: 2.5;
  }
  .roster {
    max-height: 122px;
    overflow-y: auto;
    gap: 0;
    padding: 2px 4px 2px 0;
    border-top: 1px solid var(--line-soft);
    border-bottom: 1px solid var(--line-soft);
    scrollbar-width: thin;
    scrollbar-color: var(--line-strong) transparent;
  }
  .compose.devices-open .roster {
    max-height: 178px;
  }
  .roster::-webkit-scrollbar {
    width: 8px;
  }
  .roster::-webkit-scrollbar-track {
    background: transparent;
  }
  .roster::-webkit-scrollbar-thumb {
    background: var(--line-strong);
    border: 2px solid transparent;
    border-radius: 999px;
    background-clip: padding-box;
  }
  .pair-btn {
    width: auto;
    align-self: flex-start;
    margin: 4px 0;
    padding: 7px 13px;
    border-radius: 999px;
    font-size: 13px;
  }
  .device-row {
    padding: 7px 2px;
    border: 0;
    border-bottom: 1px solid var(--line-soft);
    border-radius: 0;
    background: transparent;
  }
  .device-row:last-child {
    border-bottom: 0;
  }
  .device-label {
    font-size: 13px;
  }
  .device-meta {
    font-size: 9.5px;
  }
  .revoke-btn {
    padding: 3px 4px;
    border: 0;
    background: transparent;
    font-size: 10px;
    font-weight: 400;
  }
  .unpair-btn {
    width: 100%;
    margin: 2px 0 0;
    padding: 7px 2px 5px;
    border: 0;
    border-top: 1px solid var(--line-soft);
    border-radius: 0;
    background: transparent;
    color: var(--danger);
    font-size: 11px;
    font-weight: 400;
    text-align: left;
    cursor: pointer;
  }
  .unpair-btn:hover,
  .unpair-btn:focus-visible {
    background: transparent;
    border-color: var(--line-soft);
    color: var(--danger);
    outline: none;
  }
  .room-empty {
    padding-top: 0;
  }
  .room-empty .muted {
    margin-bottom: 7px;
    font-size: 12px;
  }
  .room-actions {
    margin-top: 6px;
  }
  .room-empty .ghost {
    min-height: 34px;
    padding: 0 14px;
    font-size: 12px;
  }
  .divider {
    margin: 7px 0 5px;
  }
  .join-input {
    height: 34px;
    padding: 0 12px;
    font-size: 12px;
  }

  .history,
  .files {
    padding: 16px 18px calc(18px + var(--footer-safe));
    gap: 10px;
  }
  .history-toolbar {
    grid-template-columns: 1fr 38px;
    gap: 8px;
  }
  .files .transfer-list {
    max-height: none;
    min-height: 0;
    flex: 1;
    padding-right: 2px;
  }
  .files-empty {
    min-height: 0;
    border-radius: 14px;
    font-size: 12px;
  }
  .search {
    height: 38px;
    padding: 0 13px;
    font-size: 12px;
  }
  .danger-icon-btn {
    width: 38px;
    height: 38px;
    border-radius: 13px;
  }
  .clip-list {
    gap: 6px;
    list-style: none;
    counter-reset: none;
  }
  .clip {
    border-radius: 14px;
    min-height: 58px;
  }
  .clip::marker {
    content: "";
  }
  .clip-body {
    min-width: 0;
    padding: 9px 10px 9px 12px;
    gap: 3px;
  }
  .clip-action {
    color: var(--accent);
    font-size: 10px;
    line-height: 1;
  }
  .clip-text {
    display: block;
    overflow: visible;
    text-overflow: clip;
    font-size: 12.5px;
    line-height: 1.3;
    white-space: normal;
    word-break: break-word;
  }
  .clip-text.searching {
    display: block;
  }
  .clip-meta {
    font-size: 10px;
    line-height: 1.1;
  }
  .clip-del {
    min-width: 38px;
    width: 38px;
    border-left: 1px solid var(--line-soft);
  }

  .pairing-card,
  .confirm-dialog,
  .transfer-dialog {
    border-radius: 20px;
    padding: 16px;
  }
  .pairing-card h3,
  .confirm-dialog h3,
  .transfer-dialog h3 {
    font-size: 14px;
    font-weight: 500;
  }
  .transfer-item,
  .transfer-file-card,
  .recipient-button {
    border-radius: 14px;
    padding: 7px 9px;
  }
  .transfer-list {
    gap: 5px;
  }
  .transfer-item {
    gap: 5px;
    padding: 6px 8px;
  }
  .transfer-head {
    display: grid;
    grid-template-columns: minmax(0, 1fr) auto auto;
    align-items: center;
    gap: 7px;
  }
  .transfer-file {
    min-width: 0;
    font-size: 11.5px;
    line-height: 1.1;
  }
  .transfer-progress {
    display: inline-flex;
    align-items: center;
    justify-content: flex-end;
    gap: 4px;
    color: var(--muted);
    font-size: 10.5px;
    line-height: 1;
    white-space: nowrap;
  }
  .transfer-track {
    height: 4px;
  }
  .transfer-message {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    font-size: 9.5px;
    line-height: 1.05;
  }
  .transfer-cancel {
    width: 22px;
    height: 22px;
    flex-basis: 22px;
    border-radius: 9px;
  }
  .transfer-cancel .icon-svg {
    width: 13px;
    height: 13px;
  }
  .status {
    padding: 7px 10px;
    border-radius: 13px;
    font-size: 11px;
  }
  .drop-target {
    width: calc(100% - 44px);
    height: calc(100% - 96px);
    border-radius: 22px;
    font-size: 18px;
  }
  .toast {
    left: 18px;
    right: 44px;
    bottom: calc(14px + var(--footer-safe));
    border-radius: 16px;
  }

  .footer-security {
    position: absolute;
    right: 18px;
    bottom: 16px;
    z-index: 12;
    display: inline-flex;
    align-items: center;
    gap: 8px;
    pointer-events: none;
  }
  .security-fragment {
    height: auto;
    padding: 0;
    display: inline-flex;
    align-items: center;
    gap: 4px;
    border: 0;
    background: transparent;
    color: var(--mint);
    font-size: 10px;
    line-height: 1;
  }
  .security-fragment .icon-svg {
    width: 12px;
    height: 12px;
    stroke-width: 2.3;
  }
  .footer-security .connection-indicator {
    position: static;
    right: auto;
    bottom: auto;
    width: 10px;
    height: 10px;
    box-shadow: 0 0 0 2px var(--shell-bg);
  }
  .footer-security .connection-indicator.live {
    box-shadow:
      0 0 0 2px var(--shell-bg),
      0 0 12px rgba(117, 239, 173, 0.78);
  }
  :global(html[data-theme="onyx"]) .footer-security .connection-indicator.live {
    box-shadow:
      0 0 0 2px var(--shell-bg),
      0 0 12px rgba(255, 255, 255, 0.72);
  }

  @media (max-width: 410px) {
    .header {
      grid-template-columns: 1fr auto;
    }
    .tabs {
      display: none;
    }
  }
</style>
