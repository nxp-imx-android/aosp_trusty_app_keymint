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
//! This library implements the functionality used by the Keymint Trusty
//! application.
#![allow(unused)] //TODO: remove unused and fix any dependency issues.
#![no_std]

use kmr_common::crypto;
use kmr_ta;

pub mod attest;

pub use FakeKeys as TrustyKeys;

// TODO: maintain the bootloader status and update it as the bootloader informs
// Trusty when it is done.
pub struct TrustyBootLoaderStatus;
impl kmr_ta::device::BootloaderStatus for TrustyBootLoaderStatus {}

// TODO: replace with a real implementation
pub struct FakeKeys;

impl kmr_ta::device::RetrieveKeyMaterial for FakeKeys {
    fn root_kek(&self) -> crypto::RawKeyMaterial {
        crypto::RawKeyMaterial(b"0123456789012345".to_vec())
    }
    fn kak(&self) -> crypto::aes::Key {
        crypto::aes::Key::Aes256([0; 32])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kmr_ta::device::RetrieveKeyMaterial;
    use test::*;

    test::init!();

    #[test]
    fn kak_call_returns_key() {
        let trusty_keys = TrustyKeys;

        let kak = trusty_keys.kak();

        expect!(matches!(kak, crypto::aes::Key::Aes256(_)), "Should have received an AES 256b key");

        let key = if let crypto::aes::Key::Aes256(kak_key) = kak {
            kak_key
        } else {
            panic!("Because we checked that the key type was Aes256 this should never happen");
        };
        // Getting an all 0 password by chance is not likely if we got a connection to HWKey
        //expect_ne!(key, [0; 32], "password should not be 0s"); // functionality not implemented yet
    }
}
