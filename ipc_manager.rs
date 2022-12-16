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
        self, ConfigureBootPatchlevelResponse, GetAuthTokenKeyResponse, GetVersion2Response,
        GetVersionResponse, SetBootParamsResponse, TrustyMessageId, TrustyPerformOpReq,
        TrustyPerformOpRsp, TrustyPerformSecureOpReq, TrustyPerformSecureOpRsp,
    },
    Error,
};
use kmr_ta::{self, split_rsp, HardwareInfo, KeyMintTa, RpcInfo};
use kmr_wire::keymint::BootInfo;
use log::{debug, error, info};
use std::ops::Deref;
use system_state::{ProvisioningAllowedFlagValues, SystemState, SystemStateFlag};
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

#[cfg(not(rust_km_legacy_port))]
const KM_NS_LEGACY_TIPC_SRV_PORT: &str = "com.android.trusty.keymaster.ns";
#[cfg(rust_km_legacy_port)]
const KM_NS_LEGACY_TIPC_SRV_PORT: &str = "com.android.trusty.keymaster";

const KEYMINT_MAX_BUFFER_LENGTH: usize = 4096;
const KEYMINT_MAX_MESSAGE_CONTENT_SIZE: usize = 4000;

struct Context {
    _uuid: Uuid,
}

struct KMMessage(Vec<u8>);

impl Deserialize for KMMessage {
    type Error = TipcError;
    const MAX_SERIALIZED_SIZE: usize = KEYMINT_MAX_BUFFER_LENGTH;

    fn deserialize(bytes: &[u8], _handles: &mut [Option<Handle>]) -> Result<Self, TipcError> {
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

struct KMLegacyService<'a> {
    km_ta: Rc<RefCell<KeyMintTa<'a>>>,
    boot_info: RefCell<Option<BootInfo>>,
    boot_patchlevel: RefCell<Option<u32>>,
}

impl<'a> KMLegacyService<'a> {
    fn new(km_ta: Rc<RefCell<KeyMintTa<'a>>>) -> Self {
        KMLegacyService {
            km_ta,
            boot_info: RefCell::new(None),
            boot_patchlevel: RefCell::new(None),
        }
    }

    fn boot_done(&self) -> bool {
        self.km_ta.borrow().is_hal_info_set()
    }

    fn get_system_state_provisioning_flag(&self) -> Result<ProvisioningAllowedFlagValues, Error> {
        let system_state_session = SystemState::try_connect().map_err(|_| {
            km_err!(SecureHwCommunicationFailed, "couldn't connect to system state provider")
        })?;
        let flag =
            system_state_session.get_flag(SystemStateFlag::ProvisioningAllowed).map_err(|_| {
                km_err!(
                    SecureHwCommunicationFailed,
                    "couldn't get ProvisioningAllowed system state flag"
                )
            })?;
        ProvisioningAllowedFlagValues::try_from(flag).map_err(|_| {
            km_err!(
                SecureHwCommunicationFailed,
                "couldn't parse ProvisioningAllowed system state flag from value {}",
                flag
            )
        })
    }

    fn system_state_provisioning_allowed(&self) -> Result<bool, Error> {
        Ok(match self.get_system_state_provisioning_flag()? {
            ProvisioningAllowedFlagValues::ProvisioningAllowed => true,
            _ => false,
        })
    }

    fn system_state_provisioning_allowed_at_boot(&self) -> Result<bool, Error> {
        Ok(match self.get_system_state_provisioning_flag()? {
            ProvisioningAllowedFlagValues::ProvisioningAllowed => true,
            ProvisioningAllowedFlagValues::ProvisioningAllowedAtBoot => true,
            _ => false,
        })
    }

    fn can_provision(&self) -> Result<bool, Error> {
        if self.boot_done() {
            self.system_state_provisioning_allowed()
        } else {
            self.system_state_provisioning_allowed_at_boot()
        }
    }

    fn maybe_set_boot_info(&self) {
        match (self.boot_info.borrow().as_ref(), self.boot_patchlevel.borrow().as_ref()) {
            (Some(info), Some(boot_patchlevel)) => {
                // All the information is available to set the boot info, so combine it and pass to
                // the TA.
                let boot_info = BootInfo {
                    verified_boot_key: info.verified_boot_key.clone(),
                    device_boot_locked: info.device_boot_locked,
                    verified_boot_state: info.verified_boot_state,
                    verified_boot_hash: info.verified_boot_hash.clone(),
                    boot_patchlevel: *boot_patchlevel,
                };
                if let Err(e) = self.km_ta.borrow_mut().set_boot_info(boot_info) {
                    error!("failed to set boot info: {:?}", e);
                }
            }
            _ => info!("not all boot information available yet"),
        }
    }

    fn handle_message(&self, req_msg: TrustyPerformOpReq) -> Result<TrustyPerformOpRsp, Error> {
        let cmd_code = req_msg.code();
        // Checking that if we received a bootloader message we are at a stage when we can process
        // it
        if self.boot_done() && legacy::is_trusty_bootloader_req(&req_msg) {
            return Err(km_err!(
                Unimplemented,
                "bootloader command {:?} not allowed after configure command",
                cmd_code
            ));
        }

        if legacy::is_trusty_provisioning_req(&req_msg) && !(self.can_provision()?) {
            return Err(km_err!(Unimplemented, "provisioning command {:?} not allowed", cmd_code));
        }

        // Handling received message
        match req_msg {
            TrustyPerformOpReq::GetVersion(_req) => {
                // Match the values returned by C++ KeyMint (from `AndroidKeymaster::GetVersion`).
                Ok(TrustyPerformOpRsp::GetVersion(GetVersionResponse {
                    major_ver: 2,
                    minor_ver: 0,
                    subminor_ver: 0,
                }))
            }
            TrustyPerformOpReq::GetVersion2(req) => {
                // Match the values returned by C++ KeyMint (from `AndroidKeymaster::GetVersion2`).
                let km_version = legacy::KmVersion::KeyMint3;
                let message_version = km_version.message_version();
                let max_message_version = core::cmp::min(req.max_message_version, message_version);
                Ok(TrustyPerformOpRsp::GetVersion2(GetVersion2Response {
                    max_message_version,
                    km_version,
                    km_date: legacy::KM_DATE,
                }))
            }
            TrustyPerformOpReq::SetBootParams(req) => {
                // Check if this is the first time we receive a SetBootParams cmd
                if self.boot_info.borrow().is_some() {
                    return Err(km_err!(Unimplemented, "command SetBootParams only allowed once"));
                }

                // Saving boot_info so command won't be accepted a second time
                let boot_info = BootInfo {
                    verified_boot_key: req.verified_boot_key,
                    device_boot_locked: req.device_locked,
                    verified_boot_state: req.verified_boot_state,
                    verified_boot_hash: req.verified_boot_hash,
                    boot_patchlevel: 0, // boot_patchlevel is received on ConfigureBootPatchlevel
                };
                self.boot_info.borrow_mut().replace(boot_info);

                // Checking if we can send set boot info with the info we currently have
                self.maybe_set_boot_info();

                Ok(TrustyPerformOpRsp::SetBootParams(SetBootParamsResponse {}))
            }
            TrustyPerformOpReq::ConfigureBootPatchlevel(req) => {
                // Check if this is the first time we receive a ConfigureBootPatchlevel cmd
                if self.boot_patchlevel.borrow().is_some() {
                    return Err(km_err!(
                        Unimplemented,
                        "command ConfigureBootPatchlevel only allowed once"
                    ));
                }

                // Saving boot_patchlevel so command won't be accepted a second time
                self.boot_patchlevel.borrow_mut().replace(req.boot_patchlevel);

                // Checking if we can send set boot info with the info we currently have
                self.maybe_set_boot_info();

                Ok(TrustyPerformOpRsp::ConfigureBootPatchlevel(ConfigureBootPatchlevelResponse {}))
            }
            _ => Err(km_err!(Unimplemented, "received command {:?} not supported", cmd_code)),
        }
    }
}

impl<'a> Service for KMLegacyService<'a> {
    type Connection = Context;
    type Message = KMMessage;

    fn on_connect(
        &self,
        _port: &PortCfg,
        _handle: &Handle,
        peer: &Uuid,
    ) -> Result<Option<Self::Connection>, TipcError> {
        // TODO: remove "In keymint: legacy on_connect" once we use a logger that prints
        //       more context.
        info!("In keymint: legacy on_connect. Accepted connection from Uuid {:?}.", peer);
        Ok(Some(Context { _uuid: peer.clone() }))
    }

    fn on_message(
        &self,
        _connection: &Self::Connection,
        handle: &Handle,
        msg: Self::Message,
    ) -> Result<bool, TipcError> {
        // TODO: remove "In keymint: legacy on_message" once we use a logger that prints
        //       more context.
        debug!("In keymint: legacy on_message.");
        let req_msg = legacy::deserialize_trusty_req(&msg.0).map_err(|e| {
            error!("Received error when parsing legacy message: {:?}", e);
            TipcError::InvalidData
        })?;
        let op = req_msg.code();

        let resp = match self.handle_message(req_msg) {
            Ok(resp_msg) => legacy::serialize_trusty_rsp(resp_msg).map_err(|e| {
                error!("failed to serialize legacy response message: {:?}", e);
                TipcError::InvalidData
            })?,
            Err(Error::Hal(rc, msg)) => {
                error!("operation {:?} failed: {:?} {}", op, rc, msg);
                legacy::serialize_trusty_error_rsp(op, rc).map_err(|e| {
                    error!("failed to serialize legacy error {:?} response message: {:?}", rc, e);
                    TipcError::InvalidData
                })?
            }
            Err(e) => {
                error!("error handling legacy message: {:?}", e);
                return Err(TipcError::UnknownError);
            }
        };
        handle.send(&KMMessage(resp))?;
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
    fn handle_message(
        &self,
        req_msg: TrustyPerformSecureOpReq,
    ) -> Result<TrustyPerformSecureOpRsp, Error> {
        match req_msg {
            TrustyPerformSecureOpReq::GetAuthTokenKey(_) => {
                match self.km_ta.borrow().get_hmac_key() {
                    Some(mut payload) => {
                        Ok(TrustyPerformSecureOpRsp::GetAuthTokenKey(GetAuthTokenKeyResponse {
                            key_material: mem::take(&mut payload.0),
                        }))
                    }
                    None => Err(km_err!(UnknownError, "hmac_key is not available")),
                }
            }
        }
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
        let op = req_msg.code();

        let resp = match self.handle_message(req_msg) {
            Ok(resp_msg) => legacy::serialize_trusty_secure_rsp(resp_msg).map_err(|e| {
                error!("failed to serialize legacy response secure message: {:?}", e);
                TipcError::InvalidData
            })?,
            Err(Error::Hal(rc, msg)) => {
                error!("operation {:?} failed: {:?} {}", op, rc, msg);
                legacy::serialize_trusty_secure_error_rsp(op, rc).map_err(|e| {
                    error!(
                        "failed to serialize legacy error {:?} response secure message: {:?}",
                        rc, e
                    );
                    TipcError::InvalidData
                })?
            }
            Err(e) => {
                error!("error handling secure legacy message: {:?}", e);
                return Err(TipcError::UnknownError);
            }
        };
        handle.send(&KMMessage(resp))?;
        Ok(true)
    }
}

service_dispatcher! {
    enum KMServiceDispatcher<'a> {
        KMService<'a>,
        KMSecureService<'a>,
        KMLegacyService<'a>,
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
    let legacy_service = KMLegacyService::new(Rc::clone(&km_ta));
    let sec_service = KMSecureService::new(km_ta);

    let mut dispatcher = KMServiceDispatcher::<3>::new().map_err(|e| {
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
    let cfg = PortCfg::new(KM_NS_LEGACY_TIPC_SRV_PORT)
        .map_err(|e| {
            km_err!(
                UnknownError,
                "could not create port config for {}. Received error: {:?}",
                KM_NS_LEGACY_TIPC_SRV_PORT,
                e
            )
        })?
        .allow_ta_connect()
        .allow_ns_connect();
    dispatcher.add_service(Rc::new(legacy_service), cfg).map_err(|e| {
        km_err!(UnknownError, "could not add secure service to dispatcher. Received error: {:?}", e)
    })?;
    let buffer = [0u8; 4096];
    let manager = Manager::<_, _, 3, 4>::new_with_dispatcher(dispatcher, buffer).map_err(|e| {
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
    use kmr_wire::{
        keymint::VerifiedBootState,
        legacy::{self, InnerSerialize},
    };
    use test::{expect, expect_eq, expect_ne};
    use trusty_std::ffi::{CString, TryNewError};

    const CONFIGURE_BOOT_PATCHLEVEL_CMD: u32 =
        legacy::TrustyKeymasterOperation::ConfigureBootPatchlevel as u32;
    const SET_BOOT_PARAMS_CMD: u32 = legacy::TrustyKeymasterOperation::SetBootParams as u32;

    #[test]
    fn connection_test() {
        // Only doing a connection test because the auth token key is not available for unittests.
        let port1 = CString::try_new(KM_NS_TIPC_SRV_PORT).unwrap();
        let session1 = Handle::connect(port1.as_c_str()).unwrap();
        let port2 = CString::try_new(KM_SEC_TIPC_SRV_PORT).unwrap();
        let session2 = Handle::connect(port2.as_c_str()).unwrap();
        let port3 = CString::try_new(KM_NS_LEGACY_TIPC_SRV_PORT).unwrap();
        let session3 = Handle::connect(port3.as_c_str()).unwrap();
    }

    fn get_configure_boot_patchlevel_message(
        boot_patchlevel: u32,
    ) -> Result<Vec<u8>, legacy::Error> {
        let mut req = Vec::<u8>::new();
        let cmd = CONFIGURE_BOOT_PATCHLEVEL_CMD << legacy::TRUSTY_CMD_SHIFT;
        req.extend_from_slice(&cmd.to_ne_bytes());
        boot_patchlevel.serialize_into(&mut req)?;
        Ok(req)
    }

    fn get_set_boot_params_message(
        os_version: u32,
        os_patchlevel: u32,
        device_locked: bool,
        verified_boot_state: VerifiedBootState,
        verified_boot_key: Vec<u8>,
        verified_boot_hash: Vec<u8>,
    ) -> Result<Vec<u8>, legacy::Error> {
        let mut req = Vec::<u8>::new();
        let cmd = SET_BOOT_PARAMS_CMD << legacy::TRUSTY_CMD_SHIFT;
        req.extend_from_slice(&cmd.to_ne_bytes());
        os_version.serialize_into(&mut req)?;
        os_patchlevel.serialize_into(&mut req)?;
        device_locked.serialize_into(&mut req)?;
        verified_boot_state.serialize_into(&mut req)?;
        verified_boot_key.serialize_into(&mut req)?;
        verified_boot_hash.serialize_into(&mut req)?;
        Ok(req)
    }

    #[test]
    fn send_setbootparams_configure_setbootparams_configure() {
        let port = CString::try_new(KM_NS_LEGACY_TIPC_SRV_PORT).unwrap();
        let session = Handle::connect(port.as_c_str()).unwrap();

        // Creating a SetBootParams message
        let os_version = 1;
        let os_patchlevel = 0x202010;
        let device_locked = true;
        let verified_boot_state = VerifiedBootState::Unverified;
        let verified_boot_key = [0u8; 32];
        let verified_boot_hash = [0u8; 32];
        let req = get_set_boot_params_message(
            os_version,
            os_patchlevel,
            device_locked,
            verified_boot_state,
            verified_boot_key.to_vec(),
            verified_boot_hash.to_vec(),
        )
        .expect("couldn't construct SetBootParams request");
        let set_boot_param_req = KMMessage(req);

        // Sending SetBootParamsRequest
        session.send(&set_boot_param_req);
        let buf = &mut [0; KEYMINT_MAX_BUFFER_LENGTH as usize];
        let response: Result<KMMessage, _> = session.recv(buf);
        expect!(response.is_ok(), "Should be able to call SetBootParams");

        // Creating a ConfigureBootPatchlevelRequest message
        let boot_patchlevel = 0x20201010;
        let req =
            get_configure_boot_patchlevel_message(boot_patchlevel).expect("Couldn't construct msg");
        let configure_bootpatchlevel_req = KMMessage(req);

        // Sending ConfigureBootPatchlevelRequest
        session.send(&configure_bootpatchlevel_req);
        let buf = &mut [0; KEYMINT_MAX_BUFFER_LENGTH as usize];
        let response: Result<KMMessage, _> = session.recv(buf);
        expect!(response.is_ok(), "Should be able to call ConfigureBootPatchlevel");

        // Checking that sending the message a second time fails
        session.send(&set_boot_param_req);
        let response: Result<KMMessage, _> = session.recv(buf);
        expect!(response.is_err(), "Shouldn't be able to call SetBootParams a second time");

        // Last message will kill our session, recreate it
        let session = Handle::connect(port.as_c_str()).unwrap();

        // Checking that sending the message a second time fails
        session.send(&configure_bootpatchlevel_req);
        let response: Result<KMMessage, _> = session.recv(buf);
        expect!(
            response.is_err(),
            "Shouldn't be able to call ConfigureBootPatchlevel a second time"
        );
    }

    // Not running the next 3 tests because we never restart the server, which means that
    // the server remembers the commands from the previous test. Also not using #[ignore] because
    // it doesn't seem to be supported yet.

    //#[test]
    fn send_configure_configure_setbootparams_setbootparams() {
        let port = CString::try_new(KM_NS_LEGACY_TIPC_SRV_PORT).unwrap();
        let session = Handle::connect(port.as_c_str()).unwrap();

        // Creating a ConfigureBootPatchlevelRequest message
        let boot_patchlevel = 0x20201010;
        let req =
            get_configure_boot_patchlevel_message(boot_patchlevel).expect("Couldn't construct msg");
        let req = KMMessage(req);

        // Sending ConfigureBootPatchlevelRequest
        session.send(&req);
        let buf = &mut [0; KEYMINT_MAX_BUFFER_LENGTH as usize];
        let response: Result<KMMessage, _> = session.recv(buf);
        expect!(response.is_ok(), "Should be able to call ConfigureBootPatchlevel");

        // Checking that sending the message a second time fails
        session.send(&req);
        let response: Result<KMMessage, _> = session.recv(buf);
        expect!(
            response.is_err(),
            "Shouldn't be able to call ConfigureBootPatchlevel a second time"
        );

        // Last message will kill our session, recreate it
        let session = Handle::connect(port.as_c_str()).unwrap();

        // Creating a SetBootParams message
        let os_version = 1;
        let os_patchlevel = 0x202010;
        let device_locked = true;
        let verified_boot_state = VerifiedBootState::Unverified;
        let verified_boot_key = [0u8; 32];
        let verified_boot_hash = [0u8; 32];
        let req = get_set_boot_params_message(
            os_version,
            os_patchlevel,
            device_locked,
            verified_boot_state,
            verified_boot_key.to_vec(),
            verified_boot_hash.to_vec(),
        )
        .expect("couldn't construct SetBootParams request");
        let req = KMMessage(req);

        // Sending SetBootParamsRequest
        session.send(&req);
        let buf = &mut [0; KEYMINT_MAX_BUFFER_LENGTH as usize];
        let response: Result<KMMessage, _> = session.recv(buf);
        expect!(response.is_ok(), "Should be able to call SetBootParams");

        // Checking that sending the message a second time fails
        session.send(&req);
        let response: Result<KMMessage, _> = session.recv(buf);
        expect!(response.is_err(), "Shouldn't be able to call SetBootParams a second time");
    }

    //#[test]
    fn send_setbootparams_setbootparams_configure_configure() {
        let port = CString::try_new(KM_NS_LEGACY_TIPC_SRV_PORT).unwrap();
        let session = Handle::connect(port.as_c_str()).unwrap();

        // Creating a SetBootParams message
        let os_version = 1;
        let os_patchlevel = 0x202010;
        let device_locked = true;
        let verified_boot_state = VerifiedBootState::Unverified;
        let verified_boot_key = [0u8; 32];
        let verified_boot_hash = [0u8; 32];
        let req = get_set_boot_params_message(
            os_version,
            os_patchlevel,
            device_locked,
            verified_boot_state,
            verified_boot_key.to_vec(),
            verified_boot_hash.to_vec(),
        )
        .expect("couldn't construct SetBootParams request");
        let req = KMMessage(req);

        // Sending SetBootParamsRequest
        session.send(&req);
        let buf = &mut [0; KEYMINT_MAX_BUFFER_LENGTH as usize];
        let response: Result<KMMessage, _> = session.recv(buf);
        expect!(response.is_ok(), "Should be able to call SetBootParams");

        // Checking that sending the message a second time fails
        session.send(&req);
        let response: Result<KMMessage, _> = session.recv(buf);
        expect!(response.is_err(), "Shouldn't be able to call SetBootParams a second time");

        // Last message will kill our session, recreate it
        let session = Handle::connect(port.as_c_str()).unwrap();

        // Creating a ConfigureBootPatchlevelRequest message
        let boot_patchlevel = 0x20201010;
        let req =
            get_configure_boot_patchlevel_message(boot_patchlevel).expect("Couldn't construct msg");
        let req = KMMessage(req);

        // Sending ConfigureBootPatchlevelRequest
        session.send(&req);
        let buf = &mut [0; KEYMINT_MAX_BUFFER_LENGTH as usize];
        let response: Result<KMMessage, _> = session.recv(buf);
        expect!(response.is_ok(), "Should be able to call ConfigureBootPatchlevel");

        // Checking that sending the message a second time fails
        session.send(&req);
        let response: Result<KMMessage, _> = session.recv(buf);
        expect!(
            response.is_err(),
            "Shouldn't be able to call ConfigureBootPatchlevel a second time"
        );
    }

    //#[test]
    fn send_configure_setbootparams_setbootparams_configure() {
        let port = CString::try_new(KM_NS_LEGACY_TIPC_SRV_PORT).unwrap();
        let session = Handle::connect(port.as_c_str()).unwrap();

        // Creating a ConfigureBootPatchlevelRequest message
        let boot_patchlevel = 0x20201010;
        let req =
            get_configure_boot_patchlevel_message(boot_patchlevel).expect("Couldn't construct msg");
        let configure_bootpatchlevel_req = KMMessage(req);

        // Sending ConfigureBootPatchlevelRequest
        session.send(&configure_bootpatchlevel_req);
        let buf = &mut [0; KEYMINT_MAX_BUFFER_LENGTH as usize];
        let response: Result<KMMessage, _> = session.recv(buf);
        expect!(response.is_ok(), "Should be able to call ConfigureBootPatchlevel");

        // Creating a SetBootParams message
        let os_version = 1;
        let os_patchlevel = 0x202010;
        let device_locked = true;
        let verified_boot_state = VerifiedBootState::Unverified;
        let verified_boot_key = [0u8; 32];
        let verified_boot_hash = [0u8; 32];
        let req = get_set_boot_params_message(
            os_version,
            os_patchlevel,
            device_locked,
            verified_boot_state,
            verified_boot_key.to_vec(),
            verified_boot_hash.to_vec(),
        )
        .expect("couldn't construct SetBootParams request");
        let set_boot_param_req = KMMessage(req);

        // Sending SetBootParamsRequest
        session.send(&set_boot_param_req);
        let buf = &mut [0; KEYMINT_MAX_BUFFER_LENGTH as usize];
        let response: Result<KMMessage, _> = session.recv(buf);
        expect!(response.is_ok(), "Should be able to call SetBootParams");

        // Checking that sending the message a second time fails
        session.send(&set_boot_param_req);
        let response: Result<KMMessage, _> = session.recv(buf);
        expect!(response.is_err(), "Shouldn't be able to call SetBootParams a second time");

        // Last message will kill our session, recreate it
        let session = Handle::connect(port.as_c_str()).unwrap();

        // Checking that sending the message a second time fails
        session.send(&configure_bootpatchlevel_req);
        let response: Result<KMMessage, _> = session.recv(buf);
        expect!(
            response.is_err(),
            "Shouldn't be able to call ConfigureBootPatchlevel a second time"
        );
    }
}
