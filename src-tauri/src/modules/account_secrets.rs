//! Managed account files contain a versioned encrypted credential field.
//! Account metadata remains available to dashboard and CLI reads without a vault unlock.
use crate::models::TokenData;
use base64::{engine::general_purpose::STANDARD, Engine};
use std::path::Path;
use zeroize::Zeroizing;

const PREFIX: &str = "v1:";

pub(crate) fn seal(token: &TokenData, id: &str, file: &Path) -> Result<String, String> {
    let json = Zeroizing::new(serde_json::to_vec(token).map_err(|_| "Cannot encode account credentials.")?);
    let bytes = platform::seal(&json, id, file)?;
    Ok(format!("{PREFIX}{}", STANDARD.encode(bytes)))
}

pub(crate) fn open(sealed: &str, id: &str, file: &Path) -> Result<TokenData, String> {
    let sealed = sealed.strip_prefix(PREFIX).ok_or("Unsupported account credential format.")?;
    let bytes = STANDARD.decode(sealed).map_err(|_| "Invalid encrypted account credentials.")?;
    let json = platform::open(bytes, id, file)?;
    serde_json::from_slice(&json).map_err(|_| "Invalid account credentials.".into())
}

#[cfg(unix)]
mod platform {
    use ring::{
        aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN},
        rand::{SecureRandom, SystemRandom},
    };
    use std::{io::{Read, Write}, path::{Path, PathBuf}};
    use zeroize::Zeroizing;

    const KEY_SIZE: usize = 32;

    pub(super) fn seal(input: &[u8], id: &str, file: &Path) -> Result<Vec<u8>, String> {
        let key = cipher(file, true)?;
        let mut nonce = [0u8; NONCE_LEN];
        SystemRandom::new().fill(&mut nonce).map_err(|_| "Cannot generate account encryption nonce.")?;
        let mut ciphertext = Zeroizing::new(input.to_vec());
        key.seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce), Aad::from(id.as_bytes()), &mut *ciphertext,
        ).map_err(|_| "Cannot encrypt account credentials.")?;
        let mut output = nonce.to_vec();
        output.extend_from_slice(&ciphertext);
        Ok(output)
    }

    pub(super) fn open(input: Vec<u8>, id: &str, file: &Path) -> Result<Zeroizing<Vec<u8>>, String> {
        let key = cipher(file, false)?;
        let mut plaintext = Zeroizing::new(input);
        if plaintext.len() <= NONCE_LEN {
            return Err("Invalid encrypted account credentials.".into());
        }
        let (nonce, ciphertext) = plaintext.split_at_mut(NONCE_LEN);
        let nonce = Nonce::try_assume_unique_for_key(nonce).map_err(|_| "Invalid account encryption nonce.")?;
        let decoded = key.open_in_place(nonce, Aad::from(id.as_bytes()), ciphertext)
            .map_err(|_| "Cannot decrypt account credentials.")?;
        Ok(Zeroizing::new(decoded.to_vec()))
    }

    fn cipher(file: &Path, create: bool) -> Result<LessSafeKey, String> {
        let root = file.parent().and_then(Path::parent).ok_or("Invalid account data directory.")?;
        let key = key_for_store(root, create)?;
        let key = UnboundKey::new(&AES_256_GCM, &*key).map_err(|_| "Invalid account encryption key.")?;
        Ok(LessSafeKey::new(key))
    }

    fn key_for_store(root: &Path, create: bool) -> Result<Zeroizing<[u8; KEY_SIZE]>, String> {
        #[cfg(target_os = "macos")]
        if dirs::home_dir().is_some_and(|home| home.join(".antigravity_tools") == root) {
            return keychain_key(create);
        }
        // A separate file keeps the key out of backups that contain only the data directory.
        // Explicit test stores remain isolated from the user's default keychain.
        let root = root.canonicalize().map_err(|_| "Cannot resolve the account data directory.")?;
        let key_path = sibling_key_path(&root)?;
        if !create || key_path.symlink_metadata().is_ok() {
            return read_key(&key_path);
        }

        let candidate = random_key()?;
        let parent = key_path.parent().ok_or("Invalid account key path.")?;
        let mut temporary = tempfile::NamedTempFile::new_in(parent)
            .map_err(|_| "Cannot create a private account key file.")?;
        temporary.write_all(&*candidate).and_then(|_| temporary.as_file().sync_all())
            .map_err(|_| "Cannot save the account encryption key.")?;
        match temporary.persist_noclobber(&key_path) {
            Ok(_) => {
                std::fs::File::open(parent).and_then(|directory| directory.sync_all())
                    .map_err(|_| "Cannot synchronize the account key directory.")?;
                Ok(candidate)
            }
            Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => read_key(&key_path),
            Err(_) => Err("Cannot save the account encryption key.".into()),
        }
    }

    fn sibling_key_path(root: &Path) -> Result<PathBuf, String> {
        let mut name = root.file_name().ok_or("Invalid account data directory.")?.to_os_string();
        name.push(".agy-switch-key");
        Ok(root.with_file_name(name))
    }

    fn random_key() -> Result<Zeroizing<[u8; KEY_SIZE]>, String> {
        let mut key = Zeroizing::new([0u8; KEY_SIZE]);
        SystemRandom::new().fill(&mut *key).map_err(|_| "Cannot generate an account encryption key.")?;
        Ok(key)
    }

    fn read_key(path: &Path) -> Result<Zeroizing<[u8; KEY_SIZE]>, String> {
        let mut file = crate::utils::fs::open_private_file(path).map_err(|_| "Cannot open the account encryption key.")?;
        let mut key = Zeroizing::new([0u8; KEY_SIZE]);
        file.read_exact(&mut *key).map_err(|_| "Invalid account encryption key.")?;
        if file.read(&mut [0]).map_err(|_| "Cannot read the account encryption key.")? != 0 {
            return Err("Invalid account encryption key.".into());
        }
        Ok(key)
    }

    #[cfg(target_os = "macos")]
    fn keychain_key(create: bool) -> Result<Zeroizing<[u8; KEY_SIZE]>, String> {
        use std::sync::Mutex;
        static KEY: Mutex<Option<Zeroizing<[u8; KEY_SIZE]>>> = Mutex::new(None);
        let mut cached = KEY.lock().map_err(|_| "Cannot lock the account encryption key.")?;
        if let Some(key) = cached.as_ref() { return Ok(key.clone()); }
        let candidate = create.then(random_key).transpose()?;
        let mut key = Zeroizing::new([0u8; KEY_SIZE]);
        crate::modules::macos_keychain::account_key(candidate.as_deref(), &mut key)?;
        *cached = Some(key.clone());
        Ok(key)
    }
}

#[cfg(windows)]
mod platform {
    use std::{ffi::c_void, path::Path, ptr};
    use zeroize::{Zeroize, Zeroizing};

    #[repr(C)]
    struct DataBlob {
        size: u32,
        bytes: *mut u8,
    }

    #[link(name = "crypt32")]
    extern "system" {
        fn CryptProtectData(
            input: *const DataBlob, description: *const u16, entropy: *const DataBlob,
            reserved: *mut c_void, prompt: *mut c_void, flags: u32, output: *mut DataBlob,
        ) -> i32;
        fn CryptUnprotectData(
            input: *const DataBlob, description: *mut *mut u16, entropy: *const DataBlob,
            reserved: *mut c_void, prompt: *mut c_void, flags: u32, output: *mut DataBlob,
        ) -> i32;
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn LocalFree(memory: *mut c_void) -> *mut c_void;
    }

    pub(super) fn seal(input: &[u8], id: &str, _: &Path) -> Result<Vec<u8>, String> {
        protect(input, id, true).map(|bytes| bytes.to_vec())
    }

    pub(super) fn open(input: Vec<u8>, id: &str, _: &Path) -> Result<Zeroizing<Vec<u8>>, String> {
        protect(&input, id, false)
    }

    fn protect(input: &[u8], id: &str, encrypt: bool) -> Result<Zeroizing<Vec<u8>>, String> {
        const UI_FORBIDDEN: u32 = 1;
        let input = blob(input)?;
        let entropy = blob(id.as_bytes())?;
        let mut output = DataBlob { size: 0, bytes: ptr::null_mut() };
        // Default DPAPI scope binds the credentials to the current Windows user.
        let status = unsafe {
            if encrypt {
                CryptProtectData(&input, ptr::null(), &entropy, ptr::null_mut(), ptr::null_mut(), UI_FORBIDDEN, &mut output)
            } else {
                CryptUnprotectData(&input, ptr::null_mut(), &entropy, ptr::null_mut(), ptr::null_mut(), UI_FORBIDDEN, &mut output)
            }
        };
        if status == 0 || output.bytes.is_null() {
            return Err("Cannot protect or open account credentials with Windows DPAPI.".into());
        }
        let bytes = unsafe { std::slice::from_raw_parts_mut(output.bytes, output.size as usize) };
        let result = Zeroizing::new(bytes.to_vec());
        bytes.zeroize();
        unsafe { LocalFree(output.bytes.cast()); }
        Ok(result)
    }

    fn blob(bytes: &[u8]) -> Result<DataBlob, String> {
        Ok(DataBlob {
            size: bytes.len().try_into().map_err(|_| "Account credentials are too large.")?,
            bytes: bytes.as_ptr().cast_mut(),
        })
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sealed_tokens_roundtrip_and_stay_bound_to_their_account() {
        let temp = tempfile::tempdir().unwrap();
        let directory = temp.path().join("data").join("accounts");
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("account-1.json");
        let token = TokenData::new(
            "fixture-access".into(), "fixture-refresh".into(), 3600, None, None, None, true, None,
        );

        let sealed = seal(&token, "account-1", &path).unwrap();
        assert!(!sealed.contains("fixture-refresh"));
        assert_eq!(open(&sealed, "account-1", &path).unwrap().refresh_token, "fixture-refresh");
        assert!(open(&sealed, "account-2", &path).is_err());
        assert!(open("v1:broken", "account-1", &path).is_err());
    }
}
