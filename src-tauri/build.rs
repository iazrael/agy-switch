const COMMANDS: &[&str] = &[
    "get_app_experiments",
    "set_app_translation",
    "get_auto_switch_config",
    "set_auto_switch_config",
    "get_auto_switch_status",
    "check_auto_switch_now",
    "cancel_auto_switch",
    "get_desktop_settings",
    "get_menu_bar_appearance",
    "set_desktop_preferences",
    "open_app_page",
    "main_window_ready",
    "present_main_window",
    "hide_menu_bar_dashboard",
    "quit_app",
    "list_accounts",
    "get_account_dashboard_snapshot",
    "get_menu_bar_snapshot",
    "set_menu_bar_preferences",
    "set_dashboard_cards",
    "add_account",
    "delete_account",
    "delete_accounts",
    "reorder_accounts",
    "switch_account",
    "save_account_export",
    "import_account_transfer",
    "get_current_account",
    "fetch_account_quota",
    "refresh_all_quotas",
    "load_config",
    "save_config",
    "set_client_executable",
    "prepare_oauth_url",
    "start_oauth_login",
    "complete_oauth_login",
    "cancel_oauth_login",
    "submit_oauth_code",
    "list_oauth_clients",
    "get_active_oauth_client",
    "set_active_oauth_client",
    "import_from_db",
    "import_local_accounts_report",
    "import_custom_db",
    "sync_account_from_db",
    "open_data_folder",
    "get_data_dir_path",
    "show_main_window",
    "open_project_page",
    "set_window_theme",
    "update_account_label",
    "get_local_token_usage",
    "get_menu_bar_usage",
    "get_api_pricing",
    "get_exchange_rate",
    "get_account_quota_valuations",
    "get_quota_cycle_history",
    "check_for_updates",
    "download_and_install_update",
    "get_running_version",
];

fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        println!("cargo:rerun-if-changed=src/modules/macos_keychain.c");
        cc::Build::new()
            .file("src/modules/macos_keychain.c")
            .flag_if_supported("-Wno-deprecated-declarations")
            .compile("agy_macos_keychain");
        println!("cargo:rustc-link-lib=framework=Security");
        println!("cargo:rustc-link-lib=framework=CoreFoundation");
    }

    let attributes = tauri_build::Attributes::new()
        .app_manifest(tauri_build::AppManifest::new().commands(COMMANDS));
    // Unit-test executables also import Common Controls v6 through Tauri's menu
    // stack. Own the manifest at the linker boundary for binaries/tests/examples;
    // Tauri continues to supply the icon and VERSION resource, without a second
    // manifest resource. See tauri-apps/tauri#13948 and its official API example.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows")
        && std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc")
    {
        tauri_build::try_build(attributes.windows_attributes(
            tauri_build::WindowsAttributes::new_without_app_manifest(),
        )).expect("failed to build Tauri resources");
        let manifest = std::path::PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap())
            .join("../scripts/fixtures/windows-desktop.manifest");
        println!("cargo:rerun-if-changed={}", manifest.display());
        println!("cargo:rustc-link-arg=/MANIFEST:EMBED");
        println!("cargo:rustc-link-arg=/MANIFESTINPUT:{}", manifest.display());
    } else {
        tauri_build::try_build(attributes).expect("failed to build Tauri resources");
    }
}
