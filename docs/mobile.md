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
rustup target add aarch64-apple-ios aarch64-apple-ios-sim
brew install cocoapods
npm ci
npm run mobile:ios:init
```

### Install on a physical iPhone via Xcode (macOS)

1. Connect your iPhone to your Mac via USB (and trust the computer on the iPhone).
2. On the iPhone, enable **Settings -> Privacy & Security -> Developer Mode** (restart if prompted).
3. Open the generated Xcode project (or launch it via Tauri):
   ```bash
   open src-tauri/gen/apple/fwoosh.xcodeproj
   # or build & run directly from the CLI:
   # npm run mobile:ios:dev
   ```
4. In Xcode, select the **fwoosh_iOS** target -> **Signing & Capabilities**:
   - Check **Automatically manage signing** and pick your **Team** (a free Apple ID personal team works for 7-day dev installs; a paid Apple Developer account signs for 1 year).
   - If Xcode says `com.aramo.fwoosh` is unavailable for your team, change the **Bundle Identifier** to a unique value (e.g. `com.<yourname>.fwoosh`).
   - If keychain storage reports `-34018` (`errSecMissingEntitlement`), click **+ Capability** and add **Keychain Sharing**.
5. Pick your connected iPhone from Xcode's device selector at the top and press **Run** (`Cmd+R`).
6. First launch with a free Apple ID: on the iPhone, open **Settings -> General -> VPN & Device Management**, tap your developer certificate, and tap **Trust**, then open Fwoosh.

To build from the CLI instead of Xcode's Run button:

```bash
npm run mobile:ios:dev
# or release archive:
npm run mobile:ios:build
```

The generated native projects live under `src-tauri/gen/`. They are generated
by the Tauri CLI after the platform prerequisites are present. The mobile CI
workflow performs this initialization before each target build; signing and
store submission remain release-environment responsibilities.
