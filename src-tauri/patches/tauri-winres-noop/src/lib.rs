//! No-op stand-in for `tauri-winres`.
//!
//! The real crate compiles a Windows resource (.rc) file via `embed-resource`
//! -> `vswhom-sys`, which needs the MSVC C++ headers (vcruntime.h, excpt.h).
//! On machines where the VS "MSVC headers" component is not installed, that
//! native C compile fails. This replacement implements the exact API surface
//! that `tauri-build` calls (`WindowsResource` builder + `VersionInfo` enum)
//! but does nothing at `compile()` time, so no native build tools are needed.
//!
//! Trade-off: the resulting .exe will not have an embedded app icon, version
//! resource, or manifest. That is purely cosmetic/UX; the app runs normally.
//! On a machine with a complete VS C++ install, remove the [patch] in
//! Cargo.toml to restore real resource embedding.

/// Version-info field selector. Values mirror the real crate's enum so call
/// sites compile unchanged.
#[derive(Copy, Clone, Debug)]
pub enum VersionInfo {
    FILEVERSION,
    PRODUCTVERSION,
}

/// Builder that mirrors `tauri_winres::WindowsResource`. All setters are
/// no-ops; `compile()` succeeds without invoking any native toolchain.
#[derive(Default)]
pub struct WindowsResource;

impl WindowsResource {
    pub fn new() -> Self {
        Self
    }

    pub fn set_manifest(&mut self, _manifest: &str) {}
    pub fn append_rc_content(&mut self, _content: &str) {}
    pub fn set_version_info(&mut self, _field: VersionInfo, _value: u64) {}
    pub fn set(&mut self, _name: &str, _value: &str) {}
    pub fn set_icon_with_id(&mut self, _path: &str, _id: &str) {}

    /// No-op compile. Returns Ok; nothing is written and no toolchain runs.
    /// Matches the real crate's `io::Result<()>` return type so `tauri-build`'s
    /// `.with_context()` call type-checks.
    pub fn compile(&self) -> std::io::Result<()> {
        Ok(())
    }
}
