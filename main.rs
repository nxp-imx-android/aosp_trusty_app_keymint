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

//! Main entrypoint for KeyMint/Rust trusted application (TA) on Trusty.

use keymint::{
    AttestationIds, CertSignInfo, SharedSddManager, TrustyAes, TrustyKeys, TrustyMonotonicClock,
    TrustyRpc, TrustySecureDeletionSecretManager, TrustyStorageKeyWrapper,
};
use kmr_common::crypto;
use kmr_crypto_boring::{
    aes::BoringAes, aes_cmac::BoringAesCmac, des::BoringDes, ec::BoringEc, eq::BoringEq,
    hmac::BoringHmac, rng::BoringRng, rsa::BoringRsa,
};
use kmr_ta::{HardwareInfo, RpcInfo, RpcInfoV3};
use log::info;

fn main() {
    trusty_log::init();

    info!("Hello from Keymint Rust!");

    let hw_info = HardwareInfo {
        version_number: 3,
        security_level: kmr_common::wire::keymint::SecurityLevel::TrustedEnvironment,
        impl_name: "TEE KeyMint in Rust",
        author_name: "Google",
        unique_id: "TEE KeyMint TA",
    };

    let rpc_info_v3 = RpcInfoV3 {
        author_name: "Google",
        unique_id: "TEE KeyMint TA",
        fused: false,
        supported_num_of_keys_in_csr: kmr_wire::rpc::MINIMUM_SUPPORTED_KEYS_IN_CSR,
    };

    let mut rng = BoringRng::default();
    let clock = TrustyMonotonicClock;
    let aes = TrustyAes::default();
    let imp = crypto::Implementation {
        rng: &mut rng,
        clock: Some(&clock),
        compare: &BoringEq,
        aes: &aes,
        des: &BoringDes,
        hmac: &BoringHmac,
        rsa: &BoringRsa::default(),
        ec: &BoringEc::default(),
        ckdf: &BoringAesCmac,
        hkdf: &BoringHmac,
    };
    let sign_info = CertSignInfo;
    let mut att_ids = AttestationIds;
    let trusty_keys = TrustyKeys;
    let key_wrapper = TrustyStorageKeyWrapper;
    let sdd_mgr = TrustySecureDeletionSecretManager::new();
    let mut shared_sdd_mgr = SharedSddManager::new(sdd_mgr);
    let mut legacy_sdd_mgr = shared_sdd_mgr.clone();
    let mut legacy_key = keymint::TrustyLegacyKeyBlobHandler {
        aes: &BoringAes,
        hkdf: &BoringHmac,
        sdd_mgr: Some(&mut legacy_sdd_mgr),
        keys: &trusty_keys,
    };
    let trusty_rpc = TrustyRpc;
    let dev = kmr_ta::device::Implementation {
        keys: &trusty_keys,
        sign_info: &sign_info,
        attest_ids: Some(&mut att_ids),
        sdd_mgr: Some(&mut shared_sdd_mgr),
        bootloader: &kmr_ta::device::BootloaderDone,
        sk_wrapper: Some(&key_wrapper),
        tup: &kmr_ta::device::TrustedPresenceUnsupported,
        legacy_key: Some(&mut legacy_key),
        rpc: &trusty_rpc,
    };
    keymint::handle_port_connections(hw_info, RpcInfo::V3(rpc_info_v3), imp, dev)
        .expect("handle_port_connections returned an error");
}
