//! In-process access to Antigravity's shared macOS credential item.
use crate::modules::{integration::parse_keyring_payload, migration::ImportedOAuthState};
use base64::{engine::general_purpose::STANDARD, Engine};
use std::{ffi::{c_char, c_void, CString}, os::unix::ffi::OsStrExt, ptr};

extern "C" {
    fn agy_macos_keychain_read(length: *mut u32, bytes: *mut *mut c_void) -> i32;
    fn agy_macos_account_key(candidate: *const c_void, key: *mut c_void, length: u32, peer: *const c_char) -> i32;
    fn agy_macos_keychain_free(bytes: *mut c_void);
    fn agy_macos_keychain_write(bytes: *const c_void, length: u32, peer: *const c_char) -> i32;
}

pub(crate) fn read() -> Result<ImportedOAuthState, String> {
    let mut length = 0u32;
    let mut raw = ptr::null_mut();
    let status = unsafe { agy_macos_keychain_read(&mut length, &mut raw) };
    if status != 0 || raw.is_null() {
        return Err(format!("Cannot read the Antigravity macOS keychain item ({status})."));
    }
    let bytes = unsafe { std::slice::from_raw_parts(raw.cast::<u8>(), length as usize) };
    let result = (|| {
        let payload = std::str::from_utf8(bytes).map_err(|_| "Invalid macOS keychain item.")?;
        if let Some(encoded) = payload.strip_prefix("go-keyring-base64:") {
            let decoded = STANDARD.decode(encoded).map_err(|_| "Invalid macOS keychain item.")?;
            parse_keyring_payload(std::str::from_utf8(&decoded).map_err(|_| "Invalid macOS keychain item.")?)
        } else {
            parse_keyring_payload(payload)
        }
    })();
    unsafe { agy_macos_keychain_free(raw); }
    result
}

pub(crate) fn write(payload: &str) -> Result<(), String> {
    let value = format!("go-keyring-base64:{}", STANDARD.encode(payload));
    let length = value.len().try_into().map_err(|_| "Antigravity credential is too large.")?;
    let peer = peer_executable();
    let peer_path = peer.as_ref().map_or(ptr::null(), |path| path.as_ptr());
    let status = unsafe { agy_macos_keychain_write(value.as_ptr().cast(), length, peer_path) };
    if status != 0 {
        return Err(format!("Cannot update the Antigravity macOS keychain item ({status})."));
    }
    Ok(())
}


pub(crate) fn account_key(candidate: Option<&[u8; 32]>, key: &mut [u8; 32]) -> Result<(), String> {
    let peer = peer_executable();
    let peer_path = peer.as_ref().map_or(ptr::null(), |path| path.as_ptr());
    let candidate = candidate.map_or(ptr::null(), |value| value.as_ptr().cast());
    let status = unsafe { agy_macos_account_key(candidate, key.as_mut_ptr().cast(), key.len() as u32, peer_path) };
    if status != 0 {
        return Err(format!("Cannot access the AntiGravity Switch account key in Keychain ({status})."));
    }
    Ok(())
}

fn peer_executable() -> Option<CString> {
    // Both Switch entry points can use the same item when packaged in the same bundle.
    std::env::current_exe().ok()
        .and_then(|path| {
            let directory = path.parent()?;
            if directory.file_name()?.to_str()? != "MacOS"
                || directory.parent()?.file_name()?.to_str()? != "Contents" { return None; }
            let name = match path.file_name()?.to_str()? {
                "agy-switch" => "agy-switch-desktop",
                "agy-switch-desktop" => "agy-switch",
                _ => return None,
            };
            let peer = directory.join(name);
            if !peer.is_file() { return None; }
            CString::new(peer.as_os_str().as_bytes()).ok()
        })
}
