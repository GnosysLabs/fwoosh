# Fwoosh

A free, open-source, **end-to-end-encrypted clipboard sync and P2P file
sharing** app for Windows, macOS, and Linux (planned). Pop a small text box
out of the tray/dock with `Ctrl/Cmd+Shift+V`, paste, and it becomes available
on all your paired devices, instantly, using the free public
[ntfy.sh](https://ntfy.sh) relay. **No servers to set up.**

- **Transport:** the public [ntfy.sh](https://ntfy.sh) relay by default
  (self-hostable) for encrypted clips and file-transfer signaling; P2P file
  transfers use WebRTC data channels.
- **Crypto:** signed envelope encryption — XChaCha20-Poly1305 + HPKE recipient
  wrapping (RFC 9180) + Ed25519 signatures + an append-only, signed roster log
  with epochs and revocation. File transfers use their own encrypted chunk
  stream plus checksum verification.
- **Cost:** $0 to run. Uses the free public [ntfy.sh](https://ntfy.sh) relay by
  default. No accounts, no central database or file storage.

## How it works

```
┌─────────────┐  E2E-encrypted  ┌───────────┐  E2E-encrypted  ┌─────────────┐
│  Device A   │ ──────────────▶ │  ntfy.sh  │ ──────────────▶ │  Device B   │
│  (Tauri app)│   HTTPS publish │  (relay)  │  WSS push       │  (Tauri app)│
└─────────────┘                 └───────────┘                 └─────────────┘
       └────────────── paired via QR (proof-of-knowledge) ───────────────┘
```

1. **Pair** — the first device creates a Sync Group and shows a single-use QR
   code plus a copyable pairing URI. Other devices scan or paste it; the join is authenticated with an HMAC
   proof-of-knowledge so eavesdroppers can't inject bogus devices.
2. **Send** — press `Ctrl/Cmd+Shift+V`, paste into the popup, hit Enter. The
   clip is encrypted (one fresh content key per clip, wrapped per recipient
   via HPKE) and published to the relay.
3. **Receive** — other devices get it within ~1s, verify the sender's Ed25519
   signature, decrypt, and show a toast + **click-to-copy** (never auto-copy).
4. **Send files** — drag in a file or choose one from the Files tab. Fwoosh sends
   encrypted WebRTC signaling over ntfy, then streams the file directly to the
   selected paired device over a WebRTC data channel.

## Status

**Working:** crypto core, roster epochs, HMAC-authenticated pairing, encrypted
history, keychain storage, ntfy transport, replay cache, tray/hotkey, manual
send UI, P2P file transfers, and admin revocation with encrypted topic-rotation
notice. Multiple named Sync Groups keep membership, relay topics, and history
separate, with an active-group switcher for deliberate sends.

**Planned for release:** mobile companion app, Linux support, QR scanning,
custom relay settings UI, pause sync, full room-repair UX, signed and notarized
installer releases, and a cross-device installed-app smoke test.

| Area | State |
|---|---|
| Signed envelope crypto (`crypto.rs`) | 12 tests |
| Roster log (`roster.rs`) | ✅ 9 tests |
| Encrypted history (`store.rs`) | 6 tests |
| OS keychain (`keychain.rs`) | OS keychain by default; file fallback only by explicit dev opt-in |
| ntfy transport (`ntfy.rs`) | ✅ 7 tests |
| Pairing (`pairing.rs`) | ✅ 8 tests plus scannable QR generation |
| Sync Groups | Named groups, isolated roster files/history, legacy-room migration, active-group switching |
| P2P file transfer (`commands.rs`) | WebRTC data channels; streamed encrypted chunks; configurable timeout |
| Desktop shell (tray, hotkey, popup UI) | ✅ builds |
| CI / release pipeline | Tests plus cargo/npm audit in CI; installer publishing and signing remain before public release |

## Threat model (honest)

- ✅ **Content is E2E encrypted.** The relay sees ciphertext for clips and file
  signaling; file bytes stream over WebRTC and are encrypted in chunks.
- ✅ **Sender authenticity** (Ed25519 signatures over canonical bytes).
- ✅ **Replay/roster-tamper resistance** (signed epochs, strict current-epoch
  checks, and a local seen-message cache).
- ✅ **Revocation** (admin drops pubkey, rotates the ntfy topic, and sends the
  new roster to remaining devices through an encrypted move message).
- **Known limit: relay metadata.** The relay can observe topic URLs, timing,
  message sizes, and IPs. The default public relay keeps ordinary encrypted
  messages briefly for offline catch-up; Private sends request no relay cache.
- **Known limit: no forward secrecy.** Fwoosh uses stable device keys for v1
  because lossy networks, offline catch-up, and portable devices make ratcheting
  hard to do reliably.
- **Known limit: endpoint compromise.** Malware running as the same logged-in
  user can access OS-keychain-backed secrets; this is a standard OS credential
  storage boundary.

## Building

### Prerequisites
- Rust (stable), Node.js 20+, npm
- Windows: a complete VS 2022/2026 C++ workload (or use CI)
- macOS: Xcode command-line tools
- Linux: GCC, pkg-config, and development headers for DBus/Secret Service

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
> `src-tauri/cargo-dev.cmd`, which discovers Visual Studio locally, loads
> `vcvars64.bat`, and sets a wrapper-scoped Cargo linker override. CI and
> normal PowerShell/cmd builds should use Cargo's default MSVC discovery.

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

## Legal documents

- [Privacy Policy](docs/privacy-policy.md)
- [Terms of Use](docs/terms-of-use.md)
