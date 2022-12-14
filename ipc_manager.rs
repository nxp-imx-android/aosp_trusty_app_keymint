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
//! Trusty handler for IPC connections. It handles both secure and non-secure world ports.
use alloc::{rc::Rc, vec::Vec};
use core::{cell::RefCell, mem};
use kmr_common::{
    crypto::{self, hmac},
    km_err,
    wire::legacy::{
        self, GetAuthTokenKeyResponse, TrustyPerformSecureOpReq, TrustyPerformSecureOpRsp,
    },
    Error,
};
use kmr_ta::{self, split_rsp, HardwareInfo, KeyMintTa, RpcInfo};
use log::{debug, error, info};
use tipc::{
    service_dispatcher, Deserialize, Handle, Manager, PortCfg, Serialize, Serializer, Service,
    TipcError, Uuid,
};
use trusty_std::alloc::FallibleVec;
use trusty_std::alloc::TryAllocFrom;

const KM_NS_TIPC_SRV_PORT: &str = "com.android.trusty.keymint";
// TODO: change port name to handle current secure world message without needing to change other
//       components
#[cfg(not(rust_km_legacy_port))]
const KM_SEC_TIPC_SRV_PORT: &str = "com.android.trusty.keymint.secure";
#[cfg(rust_km_legacy_port)]
const KM_SEC_TIPC_SRV_PORT: &str = "com.android.trusty.keymaster.secure";

const KEYMINT_MAX_BUFFER_LENGTH: usize = 4096;
const KEYMINT_MAX_MESSAGE_CONTENT_SIZE: usize = 4000;

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
    km_ta: Rc<RefCell<KeyMintTa<'a>>>,
}

impl<'a> KMService<'a> {
    fn new(km_ta: Rc<RefCell<KeyMintTa<'a>>>) -> Self {
        KMService { km_ta }
    }

    fn handle_message(&self, req_data: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
        let resp = self.km_ta.borrow_mut().process(req_data);
        split_rsp(resp.as_slice(), KEYMINT_MAX_MESSAGE_CONTENT_SIZE)
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
        // TODO: remove "In keymint: on_connect" once we use a logger that prints more context.
        info!("In keymint: on_connect. Accepted connection from Uuid {:?}.", peer);
        Ok(Some(Context { _uuid: peer.clone() }))
    }

    fn on_message(
        &self,
        _connection: &Self::Connection,
        handle: &Handle,
        msg: Self::Message,
    ) -> Result<bool, TipcError> {
        // TODO: remove "In keymint: on_message" once we use a logger that prints more context.
        debug!("In keymint: on_message.");
        let resp_vec = self.handle_message(&msg.0).map_err(|e| match e {
            Error::Hal(_, err_msg) => {
                error!("In keymint: on_message. Error: {} in handling the message.", err_msg);
                TipcError::InvalidData
            }
            Error::Alloc(err_msg) => {
                error!("In keymint: on_message. Error: {} in handling the message.", err_msg);
                TipcError::AllocError
            }
            _ => TipcError::UnknownError,
        })?;
        for resp in resp_vec {
            handle.send(&KMMessage(resp))?;
        }
        Ok(true)
    }
}

struct KMSecureService<'a> {
    km_ta: Rc<RefCell<KeyMintTa<'a>>>,
}

impl<'a> KMSecureService<'a> {
    fn new(km_ta: Rc<RefCell<KeyMintTa<'a>>>) -> Self {
        KMSecureService { km_ta }
    }
}

impl<'a> Service for KMSecureService<'a> {
    type Connection = Context;
    type Message = KMMessage;

    fn on_connect(
        &self,
        _port: &PortCfg,
        _handle: &Handle,
        peer: &Uuid,
    ) -> Result<Option<Self::Connection>, TipcError> {
        // TODO: remove "In keymint: secure on_connect" once we use a logger that prints
        //       more context.
        info!("In keymint: secure on_connect. Accepted connection from Uuid {:?}.", peer);
        Ok(Some(Context { _uuid: peer.clone() }))
    }

    fn on_message(
        &self,
        _connection: &Self::Connection,
        handle: &Handle,
        msg: Self::Message,
    ) -> Result<bool, TipcError> {
        // TODO: remove "In keymint: secure on_message" once we use a logger that prints
        //       more context.
        debug!("In keymint: on_messagesecure on_message.");

        let req_msg = legacy::deserialize_trusty_secure_req(&msg.0).map_err(|e| {
            error!("Received error when parsing message: {:?}", e);
            TipcError::InvalidData
        })?;
        match req_msg {
            TrustyPerformSecureOpReq::GetAuthTokenKey(_) => {
                let resp_msg = match self.km_ta.borrow().get_hmac_key() {
                    Some(mut payload) => {
                        TrustyPerformSecureOpRsp::GetAuthTokenKey(GetAuthTokenKeyResponse {
                            key_material: mem::take(&mut payload.0),
                        })
                    }
                    None => {
                        error!("hmac_key is not available");
                        return Err(TipcError::UnknownError);
                    }
                };
                let resp = legacy::serialize_trusty_secure_rsp(&resp_msg).map_err(|e| {
                    error!("Received error when parsing response message: {:?}", e);
                    TipcError::InvalidData
                })?;
                handle.send(&KMMessage(resp))?;
                Ok(true)
            }
        }
    }
}

service_dispatcher! {
    enum KMServiceDispatcher<'a> {
        KMService<'a>,
        KMSecureService<'a>,
    }
}

pub fn handle_port_connections<'a>(
    hw_info: HardwareInfo,
    rpc_info: RpcInfo,
    imp: crypto::Implementation<'a>,
    dev: kmr_ta::device::Implementation<'a>,
) -> Result<(), Error> {
    let km_ta = Rc::new(RefCell::new(KeyMintTa::new(hw_info, rpc_info, imp, dev)));
    let ns_service = KMService::new(Rc::clone(&km_ta));
    let sec_service = KMSecureService::new(km_ta);

    let mut dispatcher = KMServiceDispatcher::<2>::new().map_err(|e| {
        km_err!(UnknownError, "could not create multi-service dispatcher. Received error: {:?}", e)
    })?;
    let cfg = PortCfg::new(KM_NS_TIPC_SRV_PORT)
        .map_err(|e| {
            km_err!(
                UnknownError,
                "could not create port config for {}. Received error: {:?}",
                KM_NS_TIPC_SRV_PORT,
                e
            )
        })?
        .allow_ta_connect()
        .allow_ns_connect();
    dispatcher.add_service(Rc::new(ns_service), cfg).map_err(|e| {
        km_err!(
            UnknownError,
            "could not add non-secure service to dispatcher. Received error: {:?}",
            e
        )
    })?;
    let cfg = PortCfg::new(KM_SEC_TIPC_SRV_PORT)
        .map_err(|e| {
            km_err!(
                UnknownError,
                "could not create port config for {}. Received error: {:?}",
                KM_SEC_TIPC_SRV_PORT,
                e
            )
        })?
        .allow_ta_connect();
    dispatcher.add_service(Rc::new(sec_service), cfg).map_err(|e| {
        km_err!(UnknownError, "could not add secure service to dispatcher. Received error: {:?}", e)
    })?;
    let buffer = [0u8; 4096];
    let manager = Manager::<_, _, 2, 2>::new_with_dispatcher(dispatcher, buffer).map_err(|e| {
        km_err!(UnknownError, "could not create service manager. Received error: {:?}", e)
    })?;
    manager
        .run_event_loop()
        .map_err(|e| km_err!(UnknownError, "service manager received error: {:?}", e))?;
    Err(km_err!(SecureHwCommunicationFailed, "KeyMint TA handler terminated unexpectedly."))
}

#[cfg(test)]
mod tests {
    use super::*;
    use test::{expect, expect_eq, expect_ne};
    use trusty_std::ffi::{CString, TryNewError};

    #[test]
    fn connection_test() {
        // Only doing a connection test because the auth token key is not available for unittests.
        let port1 = CString::try_new(KM_NS_TIPC_SRV_PORT).unwrap();
        let session1 = Handle::connect(port1.as_c_str()).unwrap();
        let port2 = CString::try_new(KM_SEC_TIPC_SRV_PORT).unwrap();
        let session2 = Handle::connect(port2.as_c_str()).unwrap();
    }
}
