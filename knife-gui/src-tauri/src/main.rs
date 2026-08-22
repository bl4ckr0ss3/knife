// The desktop window has no console; on Windows this stops one from flashing
// up behind it in a release build.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! knife-gui: a desktop reverse-engineering workbench.
//!
//! The whole analysis lives in the `reknife` library — this binary is only the
//! window and the command surface that connects the web frontend to it. See
//! `commands.rs` for the IPC handlers and `state.rs` for the cached session.

mod agent;
mod commands;
mod console;
mod driver_cmds;
mod dto;
mod idents;
mod state;
mod symbols;
#[cfg(windows)]
mod winicon;
mod workspace_cmds;

use state::AppState;

fn main() {
    tauri::Builder::default()
        .setup(|app| {
            // Windows asks the window for its icon and stretches a 16x16 one to
            // fill the taskbar; hand it frames that fit instead.
            #[cfg(windows)]
            {
                use tauri::Manager;
                if let Some(w) = app.get_webview_window("main") {
                    if let Ok(hwnd) = w.hwnd() {
                        winicon::apply(hwnd.0 as isize);
                    }
                }
            }
            let _ = app;
            Ok(())
        })
        .plugin(tauri_plugin_dialog::init())
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            commands::open_target,
            commands::list_targets,
            commands::select_target,
            commands::close_target,
            commands::list_functions,
            commands::disassemble,
            commands::decompile,
            commands::xrefs,
            commands::paths_to,
            commands::set_yara_rules,
            commands::yara_matches,
            agent::agent_set_key,
            agent::agent_has_key,
            agent::agent_ask,
            agent::agent_cancel,
            commands::cfg,
            commands::strings_list,
            console::console_exec,
            symbols::imports,
            symbols::exports,
            commands::attack_surface,
            commands::binary_detail,
            commands::set_name,
            commands::set_note,
            workspace_cmds::clear_name,
            workspace_cmds::clear_note,
            workspace_cmds::set_prototype,
            workspace_cmds::clear_prototype,
            workspace_cmds::bind_type,
            workspace_cmds::clear_binding,
            workspace_cmds::set_field,
            workspace_cmds::clear_field,
            workspace_cmds::set_variable,
            workspace_cmds::clear_variable,
            workspace_cmds::stage_patch,
            workspace_cmds::clear_patch,
            workspace_cmds::patch_runs,
            workspace_cmds::export_patched,
            workspace_cmds::analyst_facts,
            workspace_cmds::line_actions,
            driver_cmds::driver_report,
            workspace_cmds::import_typelib,
            workspace_cmds::export_typelib,
        ])
        .run(tauri::generate_context!())
        .expect("knife-gui failed to start");
}
