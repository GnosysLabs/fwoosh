# Changelog

All notable changes to Fwoosh are tracked here.

This project uses SemVer. Release tags should use the form `vX.Y.Z`.

## Unreleased

- Split the oversized Tauri command implementation into focused state, Sync
  Group, pairing, relay, history, and file-transfer modules without changing
  the IPC contract.
- Add scannable QR codes to the pairing flow.
- Add multiple named Sync Groups with isolated rosters and clip history,
  active-group switching, create/join/rename/remove controls, and automatic
  migration of the legacy single-room state.
- Replace short-lived single-use pairing with reusable, revocable Network
  invitations stored in the OS keychain, plus optional expiring invitations.
- Encrypt pairing bootstrap requests and grants with HPKE and require explicit
  admin approval before a device is added to the signed roster.
- Add stable Network identity/default-target scaffolding and make clipboard
  routing fail closed when the requested Network is unavailable.
- Always show the file recipient picker and separate My Devices from the
  reserved People/direct-share section.
- Add coordinated version tooling for npm, Cargo, Tauri, and lockfiles.
- Harden pairing, replay rejection, revocation, startup restore, relay sizing,
  key storage fallback, and desktop permissions.
- Roll back failed Sync Group creation/join attempts, remove group-scoped local
  history on leave, and stop expired invitation or pending-join subscribers.
- Remove the prelaunch legacy pairing decoder, unused placeholder IPC commands,
  unscoped history APIs, and duplicate image assets.
- Consolidate relay pumping, admin authorization, opaque ID handling, and
  authenticated history-deletion publishing into narrowly scoped helpers.
- Compress text clips before encryption, route larger clips through bounded
  encrypted ntfy attachments, expire incomplete assemblies, and direct text
  over 1 MiB to the file-transfer flow.

## 0.1.0

- Initial local development version.
- Add Tauri desktop shell, Svelte popup UI, signed encrypted text clips,
  roster epochs, ntfy transport, encrypted local history, and keychain storage.
