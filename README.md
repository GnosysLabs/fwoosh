# Fwoosh

A free, open-source, **end-to-end-encrypted clipboard sync** app for Windows &
macOS. Pop a small text box out of the tray/dock with `Ctrl/Cmd+Shift+V`, paste,
and it becomes available on all your paired devices — instantly, with **zero
servers to run**.

- **Transport:** the public [ntfy.sh](https://ntfy.sh) relay by default
  (self-hostable). It sees only ciphertext.
- **Crypto:** signed envelope encryption — XChaCha20-Poly1305 + HPKE recipient
  wrapping (RFC 9180) + Ed25519 signatures + an append-only, signed roster log
  with epochs and revocation.
- **Cost:** $0 to run. No accounts, no central database.

## How it works

```
┌─────────────┐  E2E-encrypted  ┌───────────┐  E2E-encrypted  ┌─────────────┐
│  Device A   │ ──────────────▶ │  ntfy.sh  │ ──────────────▶ │  Device B   │
│  (Tauri app)│   HTTPS publish │  (relay)  │  WSS push       │  (Tauri app)│
└─────────────┘                 └───────────┘                 └─────────────┘
       └────────────── paired via QR (proof-of-knowledge) ───────────────┘
```

1. **Pair** — the first device creates a room and shows a single-use pairing
   code. Other devices paste it; the join is authenticated with an HMAC
   proof-of-knowledge so eavesdroppers can't inject bogus devices.
2. **Send** — press `Ctrl/Cmd+Shift+V`, paste into the popup, hit Enter. The
   clip is encrypted (one fresh content key per clip, wrapped per recipient
   via HPKE) and published to the relay.
3. **Receive** — other devices get it within ~1s, verify the sender's Ed25519
   signature, decrypt, and show a toast + **click-to-copy** (never auto-copy).

## Status

**Working & tested:** crypto core, roster epochs, HMAC-authenticated pairing,
encrypted history, keychain storage, ntfy transport, replay cache, tray/hotkey,
manual send UI, and admin revocation with encrypted topic-rotation notice.

**Still before public MVP:** QR scanning, custom relay settings UI, pause sync,
full room-repair UX, installer packaging via Tauri bundling, and cargo/npm audit
automation in CI.

| Area | State |
|---|---|
| Signed envelope crypto (`crypto.rs`) | 12 tests |
| Roster log (`roster.rs`) | ✅ 9 tests |
| Encrypted history (`store.rs`) | 6 tests |
| OS keychain (`keychain.rs`) | OS keychain by default; file fallback only by explicit dev opt-in |
| ntfy transport (`ntfy.rs`) | ✅ 7 tests |
| Pairing (`pairing.rs`) | ✅ 8 tests |
| Desktop shell (tray, hotkey, popup UI) | ✅ builds |
| CI / release pipeline | Tests plus cargo/npm audit in CI; release workflow written |

## Threat model (honest)

- ✅ **Content is E2E encrypted.** The relay sees only ciphertext.
- ✅ **Sender authenticity** (Ed25519 signatures over canonical bytes).
- ✅ **Replay/roster-tamper resistance** (signed epochs, strict current-epoch
  checks, and a local seen-message cache).
- ✅ **Revocation** (admin drops pubkey, rotates the ntfy topic, and sends the
  new roster to remaining devices through an encrypted move message).
- ❌ **Not protected:** relay metadata (unguessable topic, timing, size, IPs);
  topic leaks via HTTPS URLs/logs; ~12h ntfy cache window for offline catch-up.
- ❌ **No forward secrecy** (deferred — ratcheting is fragile on a lossy relay).
- ❌ Same-user malware defeats the OS keychain (standard limitation).

## Building

### Prerequisites
- Rust (stable), Node.js 20+, npm
- Windows: a complete VS 2022/2026 C++ workload (or use CI)
- macOS: Xcode command-line tools

### Run in dev
```bash
cd fwoosh
npm install
npm run tauri dev
```

### Build a release binary
```bash
npm run build
cd src-tauri && cargo build --release
```

### Run the test suite
```bash
cd src-tauri && cargo test --lib
```

## Versioning

Fwoosh uses SemVer and release tags like `v0.1.0`.

The app version is stored in `package.json`, `package-lock.json`,
`src-tauri/Cargo.toml`, `src-tauri/Cargo.lock`, and
`src-tauri/tauri.conf.json`. Keep them in sync with:

```bash
npm run version:check
npm run version:bump -- patch   # or minor, major, 0.2.0
```

Before tagging a release, move the relevant `CHANGELOG.md` entries from
`Unreleased` to the target version and create a matching `vX.Y.Z` tag.

> **Windows + Git Bash:** because Git Bash's `/usr/bin/link` (GNU coreutils)
> shadows MSVC's `link.exe` in PATH, builds from Git Bash use
> `src-tauri/cargo-dev.cmd` (which loads `vcvars64.bat`) and a linker pin in
> `.cargo/config.toml`. This is purely a shell-PATH issue, not a project
> workaround — PowerShell, cmd, and CI all build normally.

## Project layout

```
src-tauri/src/
  crypto.rs    X25519+Ed25519+HPKE+XChaCha20Poly1305 signed envelopes
  roster.rs    admin-signed, hash-chained membership log (epochs, revoke)
  store.rs     encrypted local history (SQLite, separate DB key)
  keychain.rs  OS credential storage (device keys + history key)
  ntfy.rs      TLS-enforced publish + WSS subscribe + reconnect
  pairing.rs   URI/QR encode + HMAC proof-of-knowledge
  commands.rs  Tauri IPC: send_clip, recent_clips, create/join_room, ...
  lib.rs       tray icon, global hotkey, popup window, plugin setup
src/routes/+page.svelte   the popup UI (Svelte + Tailwind)
.github/workflows/        Release build/checksum workflow
```

## License

MIT.
