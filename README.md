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

✅ **Working & tested (41/41 unit tests):** crypto core, roster (membership +
revocation + topic rotation), encrypted history, keychain, ntfy transport,
pairing. The app builds to a runnable desktop binary with tray + hotkey + UI.

🚧 **MVP-complete; in polish:** the join handshake completes the proof-of-
knowledge round-trip over the wire, the revocation UI button, and a first
tagged release via CI.

| Area | State |
|---|---|
| Signed envelope crypto (`crypto.rs`) | ✅ 11 tests |
| Roster log (`roster.rs`) | ✅ 9 tests |
| Encrypted history (`store.rs`) | ✅ 5 tests |
| OS keychain (`keychain.rs`) | ✅ |
| ntfy transport (`ntfy.rs`) | ✅ 7 tests |
| Pairing (`pairing.rs`) | ✅ 8 tests |
| Desktop shell (tray, hotkey, popup UI) | ✅ builds |
| CI / release pipeline | ✅ written |

## Threat model (honest)

- ✅ **Content is E2E encrypted.** The relay sees only ciphertext.
- ✅ **Sender authenticity** (Ed25519 signatures over canonical bytes).
- ✅ **Replay/roster-tamper resistance** (signed, hash-chained epoch log).
- ✅ **Revocation** (drop pubkey + rotate the ntfy topic).
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
.github/workflows/        CI (test+audit) and release (build+checksum)
```

## License

MIT.
