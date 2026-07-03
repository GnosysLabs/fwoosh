# ClipVault

A free, open-source, **end-to-end-encrypted clipboard sync** app for Windows &
macOS. Pop a small text box out of the tray/dock, paste, and it becomes
available on all your paired devices — instantly, with zero servers to run.

- **Transport:** the public [ntfy.sh](https://ntfy.sh) relay by default (self-
  hostable). It sees only ciphertext.
- **Crypto:** signed envelope encryption — XChaCha20-Poly1305 + HPKE recipient
  wrapping + Ed25519 signatures + an append-only, signed roster log with epochs.
- **Cost:** $0 to run. No accounts, no central database.

## Status

🚧 **In active development.** Current state:

| Phase | Status |
|---|---|
| Scaffold (Tauri v2 + Svelte/Tailwind) | ✅ |
| Crypto core (`crypto.rs`) — 11/11 tests pass | ✅ |
| OS keychain + encrypted history store | ⏳ |
| Local-only loop (hotkey → encrypt → decrypt → clipboard) | ⏳ |
| Roster log + pairing + ntfy transport | ⏳ |
| UI + integration + polish | ⏳ |

## Threat model (honest)

- ✅ **Content is E2E encrypted.** The relay sees only ciphertext.
- ✅ **Sender authenticity** (Ed25519 signatures).
- ✅ **Replay/roster-tamper resistance** (signed epoch log).
- ✅ **Revocation** (drop pubkey + rotate the ntfy topic).
- ❌ **Not protected:** relay metadata (unguessable topic, timing, size, IPs);
  topic leaks via HTTPS URLs/logs; ~12h ntfy cache window for offline catch-up.
- ❌ **No forward secrecy** (deferred — ratcheting is fragile on a lossy relay).

## Building on Windows (this machine)

The VS 2026 C++ workload here is missing the MSVC headers, so the build uses a
no-op `tauri-winres` replacement (cosmetic only — no embedded icon). Use the
wrapper that sets up the MSVC environment:

```bash
cd src-tauri
cmd.exe //c cargo-dev.cmd test --lib crypto
```

(`cargo-dev.cmd` sets `LIB`/`INCLUDE`/`PATH` and pins the MSVC linker so Git
Bash's `/usr/bin/link.exe` doesn't shadow it.)

## License

MIT.
