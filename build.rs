//! Detect optional external tools used by the integration tests.
//!
//! The built-in test harness has no runtime "skip", so a test that bails out when its tool is
//! missing still counts as passed -- which is indistinguishable from having actually run. By
//! probing here and emitting a `cfg`, those tests can carry `#[ignore]` instead and show up in
//! the summary as ignored.

use std::env;
use std::path::Path;

/// External binaries the integration tests shell out to
const OPTIONAL_TOOLS: [&str; 3] = ["openssl", "gpg", "sq"];

/// Look up a binary in `PATH`
fn has_tool(name: &str) -> bool {
    env::var_os("PATH")
        .map(|path| {
            env::split_paths(&path).any(|dir| {
                let candidate = dir.join(name);
                candidate.is_file() && is_executable(&candidate)
            })
        })
        .unwrap_or(false)
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    path.metadata()
        .map(|meta| meta.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable(_path: &Path) -> bool {
    true
}

fn main() {
    // Re-probe when PATH changes, so entering a dev shell that provides the tools takes effect
    println!("cargo::rerun-if-env-changed=PATH");
    println!("cargo::rerun-if-changed=build.rs");

    for tool in OPTIONAL_TOOLS {
        let cfg = format!("has_{tool}");
        println!("cargo::rustc-check-cfg=cfg({cfg})");

        if has_tool(tool) {
            println!("cargo::rustc-cfg={cfg}");
        } else {
            println!("cargo::warning=`{tool}` not found in PATH, related tests will be ignored");
        }
    }
}
