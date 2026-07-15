# Fwoosh

A free, open-source, **end-to-end-encrypted clipboard sync and P2P file
sharing** app for Windows, macOS, Android, and iOS (Linux planned). Pop a small text box
out of the tray/dock with `Ctrl/Cmd+Shift+V`, paste, and it becomes available
on all your paired devices, instantly, using the free public
[ntfy.sh](https://ntfy.sh) relay. **No servers to set up.**

- **Transport:** the public [ntfy.sh](https://ntfy.sh) relay by default
  (self-hostable) for compressed encrypted clips and file-transfer signaling.
  Larger clips use encrypted ntfy attachments; P2P file transfers use WebRTC
  data channels.
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

1. **Pair** — the first device creates a Sync Group and becomes its admin. Its
   reusable invitation survives restarts and remains valid until revoked;
   optional temporary invitations expire at a chosen time. QR and copyable URI
   carry the same invitation. Every join uses an encrypted proof-of-knowledge
   request and requires explicit admin approval.
2. **Send** — press `Ctrl/Cmd+Shift+V`, paste into the popup, hit Enter. The
   clip is encrypted (one fresh content key per clip, wrapped per recipient
   via HPKE) and published to the relay.
3. **Receive** — other devices get it within ~1s, verify the sender's Ed25519
   signature, decrypt, and show a toast + **click-to-copy** (never auto-copy).
4. **Send files** — drag in a file or choose one from the Files tab. Fwoosh sends
   encrypted WebRTC signaling over ntfy, then streams the file directly to the
   selected paired device over a WebRTC data channel.

## Status

**Working:** crypto core, roster epochs, durable admin-approved pairing,
encrypted history, keychain storage, ntfy transport, replay cache, tray/hotkey,
manual send UI, explicit-recipient P2P file transfers, and admin revocation
with encrypted topic-rotation notice. Multiple named Sync Groups keep
membership, relay topics, and history separate, with an active-group switcher
for deliberate sends.

**Planned for release:** Linux support, custom relay settings UI, pause sync,
full room-repair UX, signed and notarized installer releases, mobile device
validation, and a cross-device installed-app smoke test.

| Area | State |
|---|---|
| Signed envelope crypto (`crypto.rs`) | 15 tests |
| Roster log (`roster.rs`) | ✅ 10 tests |
| Encrypted history (`store.rs`) | 11 tests |
| OS keychain (`keychain.rs`) | OS keychain by default; file fallback only by explicit dev opt-in |
| ntfy transport (`ntfy.rs`) | ✅ 12 tests |
| Pairing (`pairing.rs`) | ✅ 6 tests plus scannable QR generation |
| Sync Groups | Named groups, isolated roster files/history, legacy-room migration, active-group switching |
| P2P file transfer (`commands/transfer/`) | WebRTC data channels; streamed encrypted chunks; configurable timeout |
| Desktop shell (tray, hotkey, popup UI) | ✅ builds |
| Mobile shell (Android / iOS) | Shared protocol core; responsive shell, QR scan, secure storage, file picker streaming, and target CI are wired |
| CI / release pipeline | Tests plus cargo/npm audit in CI; Windows NSIS/MSI and unsigned macOS app/DMG publishing are wired, signing remains before public release |

## Threat model (honest)

- ✅ **Content is E2E encrypted.** The relay sees ciphertext for clips,
  encrypted large-clip attachments, and file signaling; file bytes stream over
  WebRTC and are encrypted in chunks.
- ✅ **Sender authenticity** (Ed25519 signatures over canonical bytes).
- ✅ **Replay/roster-tamper resistance** (signed epochs, strict current-epoch
  checks, and a local seen-message cache).
- ✅ **Revocation** (admin drops pubkey, rotates the ntfy topic, and sends the
  new roster to remaining devices through an encrypted move message).
- **Known limit: relay metadata.** The relay can observe topic URLs, timing,
  message sizes, and IPs. The default public relay keeps ordinary encrypted
  messages briefly for offline catch-up and large encrypted clip attachments
  for its attachment lifetime; Private sends request no relay caching and never
  use attachments.
- **Known limit: no forward secrecy.** Fwoosh uses stable device keys
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

### Build Windows installers

On a Windows machine with the Visual Studio C++ workload installed:

```cmd
npm ci
npm run build:windows
```

The NSIS setup executable and MSI installer are written to
`src-tauri/target/x86_64-pc-windows-msvc/release/bundle/`.

### Build macOS testing artifacts

On macOS, with Xcode command-line tools installed:

```bash
npm ci
npm run build:macos
```

This creates an ad-hoc-signed `.app` bundle and `.dmg` installer under
`src-tauri/target/<your-target>/release/bundle/`. Ad-hoc signing makes the app
structurally runnable on Apple Silicon, but it is not notarization: a Mac that
downloads the app must still approve its first launch in Privacy & Security.

### Build Android and iOS

See [mobile development](docs/mobile.md) for the Android and iOS prerequisites,
development commands, and lifecycle behavior. Android builds can run on
Windows, macOS, or Linux after the SDK/NDK is installed; iOS builds require
macOS with full Xcode and CocoaPods.

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

Every frontend and installer build checks that these version values agree. The
current version is also shown in the app's Settings menu.

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
  pairing.rs   durable invitation URI + reusable HMAC proof-of-knowledge
  network.rs   Network, invitation, People/contact, and recipient domain types
  commands.rs  thin shared command facade and clipboard-send orchestration
  commands/
    state.rs             shared AppState, settings, wire types, and IPC DTOs
    sync_groups.rs       Sync Group lifecycle, roster persistence, membership
    pairing_commands.rs  durable invitations and admin-approved pairing
    relay.rs             relay subscriptions, publishing, and wire dispatch
    history_commands.rs  clipboard-history IPC commands and DTOs
    transfer/
      mod.rs             file-transfer commands and signaling state machine
      webrtc.rs          WebRTC channels, framing, finalization, and cleanup
    tests.rs             cross-module command regression tests
  lib.rs       tray icon, global hotkey, popup window, plugin setup
src/routes/+page.svelte   the popup UI (Svelte + Tailwind)
.github/workflows/        Release build/checksum workflow
```

## License

MIT.

## Legal documents

- [Privacy Policy](docs/privacy-policy.md)
- [Terms of Use](docs/terms-of-use.md)
