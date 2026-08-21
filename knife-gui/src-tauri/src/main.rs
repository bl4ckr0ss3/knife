// The desktop window has no console; on Windows this stops one from flashing
// up behind it in a release build.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! knife-gui: a desktop reverse-engineering workbench.
//!
//! The whole analysis lives in the `reknife` library — this binary is only the
//! window and the command surface that connects the web frontend to it. See
//! `commands.rs` for the IPC handlers and `state.rs` for the cached session.

mod commands;
mod console;
mod dto;
mod state;
mod symbols;

use state::AppState;

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            commands::open_target,
            commands::list_functions,
            commands::disassemble,
            commands::decompile,
            commands::xrefs,
            commands::cfg,
            commands::strings_list,
            console::console_exec,
            symbols::imports,
            symbols::exports,
            commands::attack_surface,
            commands::binary_detail,
            commands::set_name,
            commands::set_note,
        ])
        .run(tauri::generate_context!())
        .expect("knife-gui failed to start");
}
