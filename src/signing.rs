//! This module provides the signing functionality used by the stellar network

/// Sign the message with the given secrey key
pub fn sign(data: &[u8], secret_key: &[u8]) -> [u8; 64] {
    signing_impl::sign(data, secret_key)
}
/// Verify the signature
///
/// Returns `false` (rather than reading out of bounds) when `signature` is not
/// 64 bytes or `public_key` is not 32 bytes, since both are commonly supplied by
/// untrusted callers.
pub fn verify(data: &[u8], signature: &[u8], public_key: &[u8]) -> bool {
    if signature.len() != 64 || public_key.len() != 32 {
        return false;
    }
    signing_impl::verify(data, signature, public_key)
}

/// Generate Keypair
pub fn generate(secret_key: &[u8]) -> [u8; 32] {
    signing_impl::generate(secret_key)
}

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
mod signing_impl {
    pub fn generate(secret_key: &[u8]) -> [u8; 32] {
        let secret_key_u8: &[u8; 32] = secret_key.try_into().unwrap();
        let nacl_keys = nacl::sign::generate_keypair(secret_key_u8);
        nacl_keys.pkey
    }

    pub fn sign(data: &[u8], secret_key: &[u8]) -> [u8; 64] {
        let mut data_u8 = data;
        let mut secret_key_u8 = secret_key;
        let signed_msg = nacl::sign::signature(&mut data_u8, &mut secret_key_u8).unwrap();
        let mut signature = [0u8; 64];

        for i in 0..signed_msg.len() {
            signature[i] = signed_msg[i];
        }
        signature
    }

    pub fn verify(data: &[u8], signature: &[u8], public_key: &[u8]) -> bool {
        let data_u8 = data;
        let signature_u8 = signature;
        let public_key_u8 = public_key;
        nacl::sign::verify(data_u8, signature_u8, public_key_u8).unwrap()
    }
}

#[cfg(not(target_arch = "wasm32"))]
mod signing_impl {
    use libsodium_sys::crypto_sign_detached;
    use libsodium_sys::crypto_sign_seed_keypair;

    macro_rules! raw_ptr_char {
        ($name: ident) => {
            $name.as_mut_ptr() as *mut libc::c_uchar
        };
    }

    /// make invoking ffi functions more readable
    macro_rules! raw_ptr_char_immut {
        ($name: ident) => {
            $name.as_ptr() as *const libc::c_uchar
        };
    }

    pub fn generate(secret_key: &[u8]) -> [u8; 32] {
        unsafe {
            libsodium_sys::sodium_init();
        };

        unsafe {
            let mut pk = [0u8; libsodium_sys::crypto_sign_PUBLICKEYBYTES as usize];
            let mut sk = [0u8; libsodium_sys::crypto_sign_SECRETKEYBYTES as usize];

            libsodium_sys::crypto_sign_seed_keypair(
                raw_ptr_char!(pk),
                raw_ptr_char!(sk),
                raw_ptr_char_immut!(secret_key),
            );

            pk
        }
    }

    pub fn sign(data: &[u8], secret_key: &[u8]) -> [u8; 64] {
        unsafe {
            unsafe {
                let mut signature = [0u8; libsodium_sys::crypto_sign_BYTES as usize];

                libsodium_sys::crypto_sign_detached(
                    raw_ptr_char!(signature),
                    std::ptr::null_mut(),
                    raw_ptr_char_immut!(data),
                    data.len() as libc::c_ulonglong,
                    secret_key.as_ptr(),
                );

                signature
            }
        }
    }

    pub fn verify(data: &[u8], signature: &[u8], public_key: &[u8]) -> bool {
        unsafe {
            let val = libsodium_sys::crypto_sign_verify_detached(
                raw_ptr_char_immut!(signature),
                raw_ptr_char_immut!(data),
                data.len() as libc::c_ulonglong,
                raw_ptr_char_immut!(public_key),
            );

            val == 0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_hash_string() {
        let data = b"hello world";
        let expected_sig = hex!(
            "587d4b472eeef7d07aafcd0b049640b0bb3f39784118c2e2b73a04fa2f64c9c538b4b2d0f5335e968a480021fdc23e98c0ddf424cb15d8131df8cb6c4bb58309"
        );
        let actual_sig = sign(data, &hex!(
            "1123740522f11bfef6b3671f51e159ccf589ccf8965262dd5f97d1721d383dd4ffbdd7ef9933fe7249dc5ca1e7120b6d7b7b99a7a367e1a2fc6cb062fe420437"
        ));
        assert_eq!(expected_sig, actual_sig);
    }
    #[test]
    fn test_verify_string() {
        let data = "hello world".as_bytes();
        let sig = hex!(
            "587d4b472eeef7d07aafcd0b049640b0bb3f39784118c2e2b73a04fa2f64c9c538b4b2d0f5335e968a480021fdc23e98c0ddf424cb15d8131df8cb6c4bb58309"
        );
        let bad_sig = hex!(
            "687d4b472eeef7d07aafcd0b049640b0bb3f39784118c2e2b73a04fa2f64c9c538b4b2d0f5335e968a480021fdc23e98c0ddf424cb15d8131df8cb6c4bb58309"
        );
        let public_key = hex!("ffbdd7ef9933fe7249dc5ca1e7120b6d7b7b99a7a367e1a2fc6cb062fe420437");

        assert!(verify(data, &sig, &public_key));
        assert!(!verify(b"corrupted", &sig, &public_key));
        assert!(!verify(data, &bad_sig, &public_key));
    }
}
