//! Records the README's interface animation. Dev-only tooling: it is behind
//! the `record` feature and is not part of the installed `knife` command.
//!
//! ```text
//! cargo run --features record --bin knife-record -- TARGET SCRIPT OUTDIR
//! ```
//!
//! It writes one JSON frame per scripted step; `scripts/rasterize-frames.py`
//! turns those into images and `scripts/record-demo.sh` drives the whole run.

use anyhow::{bail, Result};
use std::path::Path;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [target, script, out] = args.as_slice() else {
        bail!("usage: knife-record TARGET SCRIPT OUTDIR");
    };
    reknife::tui::record::record(target, Path::new(script), Path::new(out))
}
