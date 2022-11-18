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
use alloc::vec::Vec;
use core::cell::RefCell;
use keymint::{
    AttestationIds, CertSignInfo, TrustyKeys, TrustySecureDeletionSecretManager,
    TrustyStorageKeyWrapper,
};
use kmr_common::crypto;
use kmr_crypto_boring::{
    aes::BoringAes, aes_cmac::BoringAesCmac, des::BoringDes, ec::BoringEc, eq::BoringEq,
    hmac::BoringHmac, rng::BoringRng, rsa::BoringRsa,
};
use kmr_ta::{HardwareInfo, KeyMintTa, RpcInfo, RpcInfoV3};
use log::{debug, info};
use tipc::{
    Deserialize, Handle, Manager, PortCfg, Serialize, Serializer, Service, TipcError, Uuid,
};
use trusty_std::alloc::TryAllocFrom;

const KEYMINT_MAX_BUFFER_LENGTH: usize = 4096;

struct Context {
    _uuid: Uuid,
}

struct KMMessage(Vec<u8>);

impl Deserialize for KMMessage {
    type Error = TipcError;
    const MAX_SERIALIZED_SIZE: usize = KEYMINT_MAX_BUFFER_LENGTH;

    fn deserialize(bytes: &[u8], _handles: &[Handle]) -> Result<Self, TipcError> {
        Ok(KMMessage(Vec::try_alloc_from(bytes)?))
    }
}

impl<'s> Serialize<'s> for KMMessage {
    fn serialize<'a: 's, S: Serializer<'s>>(
        &'a self,
        serializer: &mut S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.0.as_slice())
    }
}

struct KMService<'a> {
    km_ta: RefCell<KeyMintTa<'a>>,
}

impl<'a> KMService<'a> {
    fn new(
        hw_info: HardwareInfo,
        rpc_info: RpcInfo,
        imp: crypto::Implementation<'a>,
        dev: kmr_ta::device::Implementation<'a>,
    ) -> Self {
        KMService { km_ta: RefCell::new(KeyMintTa::new(hw_info, rpc_info, imp, dev)) }
    }

    fn process_message(&self, req_data: &[u8]) -> Vec<u8> {
        self.km_ta.borrow_mut().process(req_data)
    }
}

impl<'a> Service for KMService<'a> {
    type Connection = Context;
    type Message = KMMessage;

    fn on_connect(
        &self,
        _port: &PortCfg,
        _handle: &Handle,
        peer: &Uuid,
    ) -> Result<Option<Self::Connection>, TipcError> {
        debug!("In keymint: on_connect. Client Uuid: {:?}.", peer);
        Ok(Some(Context { _uuid: peer.clone() }))
    }

    fn on_message(
        &self,
        _connection: &Self::Connection,
        handle: &Handle,
        msg: Self::Message,
    ) -> Result<bool, TipcError> {
        debug!("In keymint: on_message.");
        let resp = self.process_message(&msg.0);
        handle.send(&KMMessage(resp))?;
        Ok(true)
    }
}

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
    let clock = crypto::NoOpClock {};
    let imp = crypto::Implementation {
        rng: &mut rng,
        clock: Some(&clock),
        compare: &BoringEq,
        aes: &BoringAes,
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
    let mut sdd_mgr = TrustySecureDeletionSecretManager::new();
    // TODO: replace no-ops with actual implementations
    let dev = kmr_ta::device::Implementation {
        keys: &trusty_keys,
        sign_info: &sign_info,
        attest_ids: Some(&mut att_ids),
        sdd_mgr: Some(&mut sdd_mgr),
        bootloader: &kmr_ta::device::BootloaderDone,
        sk_wrapper: Some(&key_wrapper),
        //TODO: Implement TrustedUserPresence for Trusty
        tup: &kmr_ta::device::TrustedPresenceUnsupported,
        legacy_key: None,
        // TODO (b/253926846) add HWBCC backed implementation
        rpc: &kmr_ta::device::NoOpRetrieveRpcArtifacts,
    };

    let service = KMService::new(hw_info, RpcInfo::V3(rpc_info_v3), imp, dev);

    let port = PortCfg::new("com.android.trusty.keymint")
        .expect("In keymint: could not create port config.")
        .allow_ta_connect()
        .allow_ns_connect();
    let buffer = [0u8; 4096];
    let manager = Manager::<_, _, 1, 1>::new(service, port, buffer)
        .expect("In keymint: could not create service manager.");
    manager.run_event_loop().expect("In keymint: service manager encountered an error");
}
