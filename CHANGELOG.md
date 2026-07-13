# Changelog

All notable changes to Fwoosh are tracked here.

This project uses SemVer. Release tags should use the form `vX.Y.Z`.

## Unreleased

- Add scannable QR codes to the pairing flow.
- Add multiple named Sync Groups with isolated rosters and clip history,
  active-group switching, create/join/rename/remove controls, and automatic
  migration of the legacy single-room state.
- Add coordinated version tooling for npm, Cargo, Tauri, and lockfiles.
- Harden pairing, replay rejection, revocation, startup restore, relay sizing,
  key storage fallback, and desktop permissions.

## 0.1.0

- Initial local development version.
- Add Tauri desktop shell, Svelte popup UI, signed encrypted text clips,
  roster epochs, ntfy transport, encrypted local history, and keychain storage.
