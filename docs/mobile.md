# Mobile development

Fwoosh uses the same Rust protocol, crypto, relay, history, pairing, and
file-transfer implementation on desktop, Android, and iOS. Mobile-specific
code is limited to the window lifecycle, secure storage, QR camera access,
and system file-picker adapters.

## What mobile supports

- Clipboard sends and encrypted history.
- Pairing by pasted invitation or a scanned QR code.
- Admin approval, roster management, and all Sync Group behavior.
- Encrypted WebRTC file transfers. A selected source is streamed directly from
  the system-picked URI, and received files are verified before they are copied
  to a system-selected destination.
- Relay catch-up when the app is opened or resumed. No APNs, FCM, or other
  push service is required; an active file transfer must remain open.

The mobile shell preserves Fwoosh's theme tokens and feature screens while
using touch-sized controls, safe-area padding, full-screen sheets, and bottom
navigation.

## Local setup

Android requires Java 17+, the Android SDK, Platform Tools, Build Tools, a
side-by-side NDK, and Rust's Android targets. Set `ANDROID_HOME` and
`NDK_HOME` before running:

```bash
npm ci
npm run mobile:android:init
npm run mobile:android:dev
# or: npm run mobile:android:build
```

iOS development and signing require macOS, full Xcode, CocoaPods, and Rust's
iOS targets:

```bash
npm ci
npm run mobile:ios:init
npm run mobile:ios:dev
# or: npm run mobile:ios:build
```

The generated native projects live under `src-tauri/gen/`. They are generated
by the Tauri CLI after the platform prerequisites are present. The mobile CI
workflow performs this initialization before each target build; signing and
store submission remain release-environment responsibilities.
