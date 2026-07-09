# Fwoosh — Mac setup (one page)

This builds the same app that runs on Windows, so the two can sync clips. No
Mac-specific code — just the toolchain. **~15 minutes one-time setup.**

## 1. One-time prerequisites (Terminal)

```bash
# Xcode command-line tools (provides clang, needed to compile C deps like SQLite)
xcode-select --install

# Rust (provides cargo + rustc)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"

# Node.js (if you don't already have it — check with `node --version`)
curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh | bash
brew install node
```

## 2. Get the source onto the Mac

Copy `fwoosh-source.zip` over (AirDrop, USB, etc.), then:

```bash
cd ~/Downloads        # or wherever you saved it
unzip fwoosh-source.zip -d fwoosh
cd fwoosh
```

## 3. Build + run

```bash
npm install           # fetches JS deps (~1 min)
npm run tauri dev     # builds + launches the native Mac app
```

The first build compiles the Rust core (~3-5 min). A native window appears and
a **Fwoosh icon shows in the menu bar** (top-right). Hit
**`Cmd+Shift+V`** anywhere to pop the text box.

> **No `dev.cmd` on Mac** — that file is Windows-only (it loads the MSVC build
> env). On Mac, just `npm run tauri dev` directly.

## 4. Pair with your Windows machine

On **Windows**: launch the app (`dev.cmd`), click **Create a room**, copy the
pairing code shown.

On **Mac**: the popup should show "Not connected to any device yet". Click
**Join a room**, paste the code from Windows.

Wait a few seconds — the green dot next to "Fwoosh" lights up when paired.
Now paste something into either popup and hit `Cmd/Ctrl+Enter`; it appears on
the other machine within ~1 second as a toast (click to copy).

## Troubleshooting

**`npm run tauri dev` fails with a Rust error** — run `rustup update` and retry.
The `Cargo.lock` pins exact versions, so it should resolve cleanly.

**"No such command: tauri"** — run `npm install` again; the Tauri CLI is a
dev dependency.

**Build is slow** — that's normal for the first build (compiling ~300 crates).
Subsequent builds are incremental (~10s).

**Nothing happens when I press Cmd+Shift+V** — macOS may prompt for
Accessibility permissions (System Settings → Privacy & Security → Accessibility,
enable Terminal/iTerm). Global shortcuts need it.

**App crashes / no tray icon** — check the Terminal output. Fwoosh expects
macOS Keychain to be available. A raw file fallback is only for development or
tests with `FWOOSH_ALLOW_FILE_KEY_FALLBACK=1`.

## To make a distributable `.dmg`

```bash
npm run tauri build
# Output: src-tauri/target/release/bundle/dmg/fwoosh_0.1.0_*.dmg
```

For throwaway local testing, an unsigned DMG can be opened with right-click ->
Open. Do not use unsigned or ad-hoc-signed builds as the normal update path:
macOS Keychain authorization is tracked against the app's code-signing
requirement, so every rebuilt unsigned app can look like a different app and
trigger repeated "Fwoosh wants to use your confidential information" prompts.

For builds you keep updating, sign with the same Apple code-signing identity
every time. On the Mac that builds the app:

```bash
security find-identity -v -p codesigning
export APPLE_SIGNING_IDENTITY="Developer ID Application: Your Name (TEAMID)"
npm run tauri build
```

For sharing outside your own Mac, use a paid Apple Developer account and
notarize the build too:

```bash
export APPLE_ID="you@example.com"
export APPLE_PASSWORD="app-specific-password"
export APPLE_TEAM_ID="TEAMID"
export APPLE_SIGNING_IDENTITY="Developer ID Application: Your Name (TEAMID)"
npm run tauri build
```

After moving from an unsigned build to a consistently signed build, macOS may
ask for Keychain access once more. Choose **Always Allow** for the signed app.
Future updates signed with the same identity should not re-prompt for the same
Keychain item.

---

For reference, the full architecture, threat model, and project layout are in
`README.md`. Source is identical on both platforms — nothing is Mac-specific.
