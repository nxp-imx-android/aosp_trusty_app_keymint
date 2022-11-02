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
//! Trusty implementation of StorageKeyWrapper trait.
use alloc::vec::Vec;
use hwwsk;
use kmr_common::{
    crypto::{aes, KeyMaterial, OpaqueOr},
    explicit, km_err, vec_try_with_capacity, Error,
};
use kmr_ta::device::StorageKeyWrapper;
use tipc::Handle;
use trusty_std::ffi::CStr;

const HWWSK_PORT: &'static [u8] = b"com.android.trusty.hwwsk\0";

pub struct TrustyStorageKeyWrapper;

impl StorageKeyWrapper for TrustyStorageKeyWrapper {
    fn ephemeral_wrap(&self, key_material: &KeyMaterial) -> Result<Vec<u8>, Error> {
        let aes_key = match key_material {
            KeyMaterial::Aes(key) => explicit!(key)?,
            _ => return Err(km_err!(UnsupportedAlgorithm, "Only explicit AES keys are supported")),
        };
        let key: &[u8] = match aes_key {
            aes::Key::Aes128(key) => key,
            aes::Key::Aes192(key) => key,
            aes::Key::Aes256(key) => key,
        };

        let port =
            CStr::from_bytes_with_nul(HWWSK_PORT).expect("HWWSK_PORT was not null terminated");

        let session = Handle::connect(port)
            .map_err(|_| km_err!(SecureHwCommunicationFailed, "Failed to connect to hwwsk"))?;

        let buf = &mut [0u8; hwwsk::HWWSK_MAX_MSG_SIZE as usize];

        let wrapped_key_buffer = hwwsk::export_key(&session, buf, key)
            .map_err(|_| km_err!(SecureHwCommunicationFailed, "Hwwsk failed to wrap key"))?;
        let mut wrapped_key = vec_try_with_capacity!(wrapped_key_buffer.len())?;
        wrapped_key.extend_from_slice(wrapped_key_buffer);
        Ok(wrapped_key)
    }
}

// Not adding unit tests because we do not have a mock server on AOSP for hwwsk.
