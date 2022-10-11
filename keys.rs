/*
 * Copyright (C) 2022 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
//! Trusty implementation of RetrieveKeyMaterial.

use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::{array::TryFromSliceError, mem};
use hwkey::{Hwkey, KdfVersion, OsRollbackVersion, RollbackVersionSource};
use kmr_common::{
    crypto, keyblob::legacy::AuthEncryptedBlobFormat, km_err, vec_try_with_capacity, Error,
};
use trusty_std::ffi::CStr;

const TRUSTY_KM_KAK_SIZE: usize = 32;
const TRUSTY_KM_WRAPPING_KEY_SIZE: usize = 16;
const KM_KAK_SLOT_ID: &'static [u8] = b"com.android.trusty.keymint.kak\0";

const KM_KEY_DERIVATION_DATA: &'static [u8] = b"KeymasterMaster\0";

const U32_SIZE: usize = mem::size_of::<u32>();

fn deserialize_u32(bytes: &[u8], error_message: &str) -> Result<u32, Error> {
    let u32_bytes: [u8; U32_SIZE] = match bytes.try_into() {
        Ok(byte_array) => byte_array,
        Err(_) => return Err(km_err!(InvalidArgument, "{}", error_message)),
    };
    Ok(u32::from_le_bytes(u32_bytes))
}

fn os_rollback_version_to_u32(os_rollback_version: OsRollbackVersion) -> Result<u32, Error> {
    match os_rollback_version {
        // If we get a "Current" version, we want to convert it to the specific version, so
        // the context remains accurate if it is saved and used at a later time.
        OsRollbackVersion::Current => {
            let hwkey_session = match Hwkey::open() {
                Ok(connection) => connection,
                Err(_) => {
                    return Err(km_err!(SecureHwCommunicationFailed, "HwKey connection error"))
                }
            };
            match hwkey_session.query_current_os_version(RollbackVersionSource::CommittedVersion) {
                Ok(OsRollbackVersion::Version(n)) => Ok(n),
                _ => Err(km_err!(
                    SecureHwCommunicationFailed,
                    "Couldn't get current os rollback version"
                )),
            }
        }
        OsRollbackVersion::Version(n) => Ok(n),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct NonLegacyKeyContext {
    kdf_version: KdfVersion,
    os_rollback_version: OsRollbackVersion,
}

// KEK context provide information to derive the same Key Encryption Key used to encrypt a given
// key. To be able to do that we need to know if the key is a legacy one or not; and if it is not a
// legacy key; we need to know the KDF method used (although currently there is only 1 method) and
// the Os Rollback version (more info on this parameters can be found on the trusty hwkey crate).
#[derive(Clone, Debug, PartialEq, Eq)]
enum TrustyKekContext {
    LegacyKey,
    NonLegacyKey(NonLegacyKeyContext),
}

// TrustyKekContext is serialized as 3 consecutive little endian U32 values:
// [Context Version: u32]
// [KDF Version: u32]
// [OS Rollback Version: u32]
impl TrustyKekContext {
    // CONTEXT_VERSION will be serialized on the first 4 bytes of the raw context representation and
    // it reperesents the version of the TrustyKekContext structure. If the structure is changed
    // this number needs to be bumped and the serialize/deserialize functions updated
    const CONTEXT_VERSION: u32 = 1;
    const CONTEXT_VER_OFFSET: usize = 0;
    // Reserving 4 bytes for non_legacy_key in case we want to
    // replace it with the enum that represents the specific key format.
    // For kek derivation we don't really use it; it is either a legacy
    // key or not.
    const NON_LEGACY_KEY_OFFSET: usize = Self::CONTEXT_VER_OFFSET + U32_SIZE;
    const KDF_VER_OFFSET: usize = Self::NON_LEGACY_KEY_OFFSET + U32_SIZE;
    const OS_ROLLBACK_VER_OFFSET: usize = Self::KDF_VER_OFFSET + U32_SIZE;
    const SERIALIZED_SIZE: usize = Self::OS_ROLLBACK_VER_OFFSET + U32_SIZE;

    fn new(
        non_legacy_key: bool,
        kdf_version: Option<KdfVersion>,
        os_rollback_version: Option<OsRollbackVersion>,
    ) -> Result<Self, Error> {
        if non_legacy_key {
            if kdf_version.is_none() {
                return Err(km_err!(InvalidArgument, "Non legacy keys require a KDF version"));
            }
            if os_rollback_version.is_none() {
                return Err(km_err!(
                    InvalidArgument,
                    "Non legacy keys require an OS Rollback version"
                ));
            }
            // Directly unwrapping values because we checked that they were not None
            let kdf_version = kdf_version.unwrap();
            let os_rollback_version = os_rollback_version.unwrap();
            Ok(TrustyKekContext::NonLegacyKey(NonLegacyKeyContext {
                kdf_version,
                os_rollback_version,
            }))
        } else {
            if kdf_version.is_some() {
                return Err(km_err!(InvalidArgument, "Legacy keys do not use a KDF version"));
            }
            if os_rollback_version.is_some() {
                return Err(km_err!(
                    InvalidArgument,
                    "Legacy keys do nto use a OS Rollback version"
                ));
            }
            Ok(TrustyKekContext::LegacyKey)
        }
    }

    fn from_raw(raw_context: &[u8]) -> Result<Self, Error> {
        if raw_context.len() != Self::SERIALIZED_SIZE {
            return Err(km_err!(
                InvalidArgument,
                "Provided kek context had wrong size. Received {} bytes, expected {} bytes",
                raw_context.len(),
                Self::SERIALIZED_SIZE
            ));
        }
        let context_version = deserialize_u32(
            &raw_context[..Self::NON_LEGACY_KEY_OFFSET],
            "Couldn't deserialize context version",
        )?;
        if context_version != Self::CONTEXT_VERSION {
            return Err(km_err!(InvalidArgument, "Received invalid context version"));
        }
        let non_legacy_key = deserialize_u32(
            &raw_context[Self::NON_LEGACY_KEY_OFFSET..Self::KDF_VER_OFFSET],
            "Couldn't deserialize kdf version",
        )?;
        match non_legacy_key {
            0 => Ok(TrustyKekContext::LegacyKey),
            1 => {
                let kdf_version = deserialize_u32(
                    &raw_context[Self::KDF_VER_OFFSET..Self::OS_ROLLBACK_VER_OFFSET],
                    "Couldn't deserialize kdf version",
                )?;
                let kdf_version = KdfVersion::from(kdf_version);
                let os_rollback_version = deserialize_u32(
                    &raw_context[Self::OS_ROLLBACK_VER_OFFSET..],
                    "Couldn't deserialize os rolback version",
                )?;
                let os_rollback_version = OsRollbackVersion::Version(os_rollback_version);
                Ok(TrustyKekContext::NonLegacyKey(NonLegacyKeyContext {
                    kdf_version,
                    os_rollback_version,
                }))
            }
            _ => Err(km_err!(InvalidArgument, "Received invalid non legacy key value")),
        }
    }

    fn to_raw(&self) -> Result<Vec<u8>, Error> {
        // For legacy keys giving 0 values for OS and KDF version. These values will be ignored on
        // deserialization.
        let (os_version, kdf_version, non_legacy_key) = match self {
            TrustyKekContext::LegacyKey => (0, 0, 0u32),
            TrustyKekContext::NonLegacyKey(ctx) => {
                let os_version = os_rollback_version_to_u32(ctx.os_rollback_version)?;
                let kdf_version: u32 = ctx.kdf_version.into();
                (os_version, kdf_version, 1u32)
            }
        };
        let mut raw_vec = vec_try_with_capacity!(Self::SERIALIZED_SIZE)?;
        raw_vec.extend_from_slice(&Self::CONTEXT_VERSION.to_le_bytes());
        raw_vec.extend_from_slice(&non_legacy_key.to_le_bytes());
        raw_vec.extend_from_slice(&kdf_version.to_le_bytes());
        raw_vec.extend_from_slice(&os_version.to_le_bytes());
        Ok(raw_vec)
    }
}

pub struct TrustyKeys;

//TODO: Change traits definitions to support kek and kak keys stored on hardware if needed.
//      RawKeyMaterial assume that the key will be passed in the clear, which won't be the case
//      if the IP block never releases the key. KeyMaterial type fixes that issue by including
//      Opaque keys, but RawKeys are not included on KeyMaterial.
impl kmr_ta::device::RetrieveKeyMaterial for TrustyKeys {
    fn root_kek(&self, context: &[u8]) -> Result<crypto::RawKeyMaterial, Error> {
        let context = TrustyKekContext::from_raw(context)?;
        let hwkey_session = Hwkey::open()
            .map_err(|_| km_err!(SecureHwCommunicationFailed, "Failed to connect to HwKey"))?;

        let mut key_buffer = [0; TRUSTY_KM_WRAPPING_KEY_SIZE];

        match context {
            TrustyKekContext::NonLegacyKey(context) => {
                let _ = hwkey_session
                    .derive_key_req()
                    .unique_key()
                    .kdf(context.kdf_version)
                    .os_rollback_version(context.os_rollback_version)
                    .rollback_version_source(RollbackVersionSource::CommittedVersion)
                    .derive(KM_KEY_DERIVATION_DATA, &mut key_buffer)
                    .map_err(|_| km_err!(SecureHwCommunicationFailed, "Couldn't derive key"))?;
            }
            TrustyKekContext::LegacyKey => {
                let _ = hwkey_session
                    .derive_key_req()
                    .kdf(KdfVersion::Version(1))
                    .derive(KM_KEY_DERIVATION_DATA, &mut key_buffer)
                    .map_err(|_| {
                        km_err!(SecureHwCommunicationFailed, "Couldn't derive legacy key")
                    })?;
            }
        }
        Ok(crypto::RawKeyMaterial(key_buffer.to_vec()))
    }

    fn kek_context(&self) -> Result<Vec<u8>, Error> {
        TrustyKekContext::new(true, Some(KdfVersion::Best), Some(OsRollbackVersion::Current))?
            .to_raw()
    }

    fn kak(&self) -> Result<crypto::aes::Key, Error> {
        let hwkey_session = Hwkey::open()
            .map_err(|_| km_err!(SecureHwCommunicationFailed, "Failed to connect to HwKey"))?;
        let mut key_buffer = [0; TRUSTY_KM_KAK_SIZE];
        let keyslot = CStr::from_bytes_with_nul(KM_KAK_SLOT_ID)
            .expect("should never happen, KM_KAK_SLOT_ID follows from_bytes_with_nul rules");
        let kak = hwkey_session
            .get_keyslot_data(keyslot, &mut key_buffer)
            .map_err(|_| km_err!(SecureHwCommunicationFailed, "Couldn't retrieve kak"))?;
        Ok(crypto::aes::Key::Aes256(key_buffer))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kmr_ta::device::RetrieveKeyMaterial;
    use test::{expect, expect_eq, expect_ne};

    #[test]
    fn kak_call_returns_key() {
        let trusty_keys = TrustyKeys;
        let kak = trusty_keys.kak().expect("Couldn't retrieve kak");

        expect!(matches!(kak, crypto::aes::Key::Aes256(_)), "Should have received an AES 256 key");

        let key = match kak {
            crypto::aes::Key::Aes256(key) => key,
            _ => panic!("Wrong type of key received"),
        };
        // Getting an all 0 key agreement key by chance is not likely if we got a
        // connection to HWKey
        expect_ne!(key, [0; TRUSTY_KM_KAK_SIZE], "key agreement key should not be 0s");
    }

    #[test]
    fn kak_two_calls_returns_same_key() {
        let trusty_keys = TrustyKeys;

        let kak1 = match trusty_keys.kak().expect("Couldn't retrieve kak") {
            crypto::aes::Key::Aes256(key) => key,
            _ => panic!("Wrong type of key received"),
        };
        let kak2 = match trusty_keys.kak().expect("Couldn't retrieve kak") {
            crypto::aes::Key::Aes256(key) => key,
            _ => panic!("Wrong type of key received"),
        };
        expect_eq!(kak1, kak2, "Calls to kak should return the same key");
    }

    #[test]
    fn kek_call_returns_key() {
        let trusty_keys = TrustyKeys;
        let kek = trusty_keys
            .root_kek(&trusty_keys.kek_context().expect("Couldn't get kek context"))
            .expect("Couldn't get kek");

        // Getting an all 0 key encryption key by chance is not likely if we got a
        // connection to HWKey
        expect_ne!(
            kek.0,
            [0; TRUSTY_KM_WRAPPING_KEY_SIZE].to_vec(),
            "Key encryption key should not be 0s"
        );
    }

    #[test]
    fn kek_two_calls_returns_same_key() {
        let trusty_keys = TrustyKeys;
        let kek1 = trusty_keys
            .root_kek(&trusty_keys.kek_context().expect("Couldn't get kek context"))
            .expect("Couldn't get kek");
        let kek2 = trusty_keys
            .root_kek(&trusty_keys.kek_context().expect("Couldn't get kek context"))
            .expect("Couldn't get kek");

        expect_eq!(kek1.0, kek2.0, "Calls to root_kek should return the same key");
    }

    #[test]
    fn kek_with_different_context_return_different_keys() {
        let context1 =
            TrustyKekContext::new(true, Some(KdfVersion::Best), Some(OsRollbackVersion::Current));
        // Transforming back and forward to raw format to get specific versions
        let context1 = TrustyKekContext::from_raw(&context1.unwrap().to_raw().unwrap()).unwrap();
        let non_legacy_context1 = match context1.clone() {
            TrustyKekContext::NonLegacyKey(context) => context,
            _ => panic!("Didn't get back a non-legacy key"),
        };
        let context1_version = match non_legacy_context1.os_rollback_version {
            OsRollbackVersion::Version(n) => n,
            _ => panic!("Didn't get an specific version"),
        };
        // Specific running/committed versions are greater than 0.
        let context2_version = context1_version - 1;
        let context2 = TrustyKekContext::new(
            true,
            Some(KdfVersion::Best),
            Some(OsRollbackVersion::Version(context2_version)),
        )
        .unwrap();
        let trusty_keys = TrustyKeys;
        let kek1 = trusty_keys
            .root_kek(&context1.to_raw().expect("Couldn't serialize kek1 context"))
            .expect("Couldn't get kek");
        let kek2 = trusty_keys
            .root_kek(&context2.to_raw().expect("Couldn't serialize kek2 context"))
            .expect("Couldn't get kek");

        expect_ne!(kek1.0, kek2.0, "kek keys should be different");
    }

    #[test]
    fn legacy_kek_is_different_than_non_legacy() {
        let context1 =
            TrustyKekContext::new(true, Some(KdfVersion::Best), Some(OsRollbackVersion::Current))
                .unwrap();
        let context2 = TrustyKekContext::new(false, None, None).unwrap();
        let trusty_keys = TrustyKeys;
        let kek1 = trusty_keys
            .root_kek(&context1.to_raw().expect("Couldn't serialize kek1 context"))
            .expect("Couldn't get kek");
        let kek2 = trusty_keys
            .root_kek(&context2.to_raw().expect("Couldn't serialize kek2 context"))
            .expect("Couldn't get kek");

        expect_ne!(kek1.0, kek2.0, "kek keys should be different");
    }

    #[test]
    fn deserializing_u32s() {
        let num = deserialize_u32(&[0; 0], "");
        expect!(num.is_err(), "We need an array of exactly 4 bytes for a u32");
        let num = deserialize_u32(&[0; 3], "");
        expect!(num.is_err(), "We need an array of exactly 4 bytes for a u32");
        let num = deserialize_u32(&[0; 5], "");
        expect!(num.is_err(), "We need an array of exactly 4 bytes for a u32");
        let num = deserialize_u32(&[0; 4], "").unwrap();
        expect_eq!(num, 0, "recovered number should be 0");
        let num = deserialize_u32(&[0xff; 4], "").unwrap();
        expect_eq!(num, 0xffffffff, "recovered number should be 0xffffffff");
        let num = deserialize_u32(&[1, 0, 0, 0], "").unwrap();
        expect_eq!(num, 1, "recovered number should be 1");
        let num = deserialize_u32(&[0x78, 0x56, 0x34, 0x12], "").unwrap();
        expect_eq!(num, 0x12345678, "recovered number should be 0x12345678");
    }

    #[test]
    fn os_version_to_u32() {
        for version in 0..20 {
            let u32_version =
                os_rollback_version_to_u32(OsRollbackVersion::Version(version)).unwrap();
            expect_eq!(version, u32_version, "Wriong version received");
        }
        let curr_version = os_rollback_version_to_u32(OsRollbackVersion::Current).unwrap();
        expect_ne!(curr_version, 0, "Current version should not be 0");
    }

    #[test]
    fn deserializing_bad_kek_context_fails() {
        let ctx_1 = TrustyKekContext::from_raw(&[0; 0]);
        expect!(ctx_1.is_err(), "deserializing an empty context should fail");
        let good_ctx =
            TrustyKekContext::new(true, Some(KdfVersion::Best), Some(OsRollbackVersion::Current))
                .unwrap();
        let mut ctx_raw = good_ctx.to_raw().unwrap();
        ctx_raw.push(0);
        let ctx_2 = TrustyKekContext::from_raw(&ctx_raw);
        expect!(ctx_2.is_err(), "deserializing a bigger than expected context should fail");
        ctx_raw.pop();
        let ctx_3 = TrustyKekContext::from_raw(&ctx_raw);
        expect!(ctx_3.is_ok(), "checking that good context can be deserialized");
        ctx_raw.pop();
        let ctx_4 = TrustyKekContext::from_raw(&ctx_raw);
        expect!(ctx_4.is_err(), "deserializing a smaller than expected context should fail");
        let ctx_5 = TrustyKekContext::from_raw(&[0; TrustyKekContext::SERIALIZED_SIZE]);
        expect!(ctx_5.is_err(), "deserializing a smaller than expected context should fail");
    }

    #[test]
    fn test_kek_context_serialization() {
        let original_ctx = TrustyKekContext::new(
            true,
            Some(KdfVersion::Best),
            Some(OsRollbackVersion::Version(2)),
        )
        .unwrap();
        let recovered_ctx = TrustyKekContext::from_raw(&original_ctx.to_raw().unwrap()).unwrap();
        expect_eq!(original_ctx, recovered_ctx, "Didn't get back same context");
        let original_ctx = TrustyKekContext::new(false, None, None).unwrap();
        let recovered_ctx = TrustyKekContext::from_raw(&original_ctx.to_raw().unwrap()).unwrap();
        expect_eq!(original_ctx, recovered_ctx, "Didn't get back same context");
    }

    #[test]
    fn test_kek_context_creation() {
        //Testing that non legacy context requires all parameters to be present
        let non_legacy_ctx = TrustyKekContext::new(true, None, Some(OsRollbackVersion::Version(2)));
        expect!(
            non_legacy_ctx.is_err(),
            "We should not be able to create a non legacy context without KDF version"
        );
        let non_legacy_ctx = TrustyKekContext::new(true, Some(KdfVersion::Best), None);
        expect!(
            non_legacy_ctx.is_err(),
            "We should not be able to create a non legacy context without OS rollback version"
        );
        let non_legacy_ctx = TrustyKekContext::new(
            true,
            Some(KdfVersion::Best),
            Some(OsRollbackVersion::Version(2)),
        );
        expect!(non_legacy_ctx.is_ok(), "Couldn't create non legacy context");
        //Testing that legacy context requires all optional parameters to be None
        let legacy_ctx = TrustyKekContext::new(
            false,
            Some(KdfVersion::Best),
            Some(OsRollbackVersion::Version(2)),
        );
        expect!(
            legacy_ctx.is_err(),
            "We should not be able to create a non legacy with optional parameters"
        );
        let legacy_ctx = TrustyKekContext::new(false, None, Some(OsRollbackVersion::Version(2)));
        expect!(
            legacy_ctx.is_err(),
            "We should not be able to create a non legacy context with a OS Rollback version"
        );
        let legacy_ctx = TrustyKekContext::new(false, Some(KdfVersion::Best), None);
        expect!(
            legacy_ctx.is_err(),
            "We should not be able to create a non legacy context without OS rollback version"
        );
        let legacy_ctx = TrustyKekContext::new(false, None, None);
        expect!(legacy_ctx.is_ok(), "Couldn't create legacy context");
    }
}
