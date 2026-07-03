// Minimal excpt.h shim. The real header declares the SEH helpers used by
// vswhom.cpp. We only need the type EXCEPTION_POINTERS, which lives in
// winnt.h. This shim forwards via the standard windows headers so the
// embed-resource (tauri-winres) C helper compiles on this VS install whose
// UCRT shared headers are partially missing. Not a runtime dependency.
#ifndef _CLIPVAULT_EXCPT_SHIM_H
#define _CLIPVAULT_EXCPT_SHIM_H
#include <winnt.h>
#endif
