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
//! Module used to interact with keymint secure storage data.
use alloc::{format, string::String, vec::Vec};
use kmr_common::{
    crypto::{self, KeyMaterial},
    km_err, vec_try, vec_try_with_capacity,
    wire::keymint::{self, ErrorCode},
    wire::AttestationIdInfo,
    Error,
};
use kmr_ta::device::{
    RetrieveAttestationIds, RetrieveCertSigningInfo, SigningAlgorithm, SigningKeyType,
};
use storage::{OpenMode, Port, SecureFile, Session};

use protobuf::{self, Message};

use crate::keymaster_attributes;

const KM_ATTESTATION_ID_FILENAME: &'static str = "AttestationIds";

const KM_ATTESTATION_KEY_CERT_PREFIX: &'static str = "AttestKeyCert";

fn get_key_slot_file_name(algorithm: SigningAlgorithm) -> String {
    let suffix = match algorithm {
        SigningAlgorithm::Ec => "ec",
        SigningAlgorithm::Rsa => "rsa",
    };
    format!("{}.{}", KM_ATTESTATION_KEY_CERT_PREFIX, suffix)
}

pub(crate) fn delete_attestation_ids() -> Result<(), Error> {
    let mut session = Session::new(Port::TamperProof, true)
        .map_err(|_| km_err!(SecureHwCommunicationFailed, "Failed to connect to storage port"))?;
    session
        .remove(KM_ATTESTATION_ID_FILENAME)
        .map_err(|_| km_err!(SecureHwCommunicationFailed, "Couldn't delete atestation IDs file"))?;
    Ok(())
}

fn get_file_contents(file_name: &str) -> Result<Vec<u8>, Error> {
    let mut session = Session::new(Port::TamperProof, true)
        .map_err(|_| km_err!(SecureHwCommunicationFailed, "Failed to connect to storage port"))?;
    let file = session
        .open_file(file_name, OpenMode::Open)
        .map_err(|_| km_err!(SecureHwCommunicationFailed, "Couldn't open {}", file_name))?;
    let size = session
        .get_size(&file)
        .map_err(|_| km_err!(SecureHwCommunicationFailed, "Couldn't get {} size", file_name))?;
    let mut buffer = vec_try![0; size]?;
    let content = session
        .read_all(&file, buffer.as_mut_slice())
        .map_err(|_| km_err!(SecureHwCommunicationFailed, "Couldn't read {}", file_name))?;
    let total_size = content.len();
    buffer.resize(total_size, 0);
    Ok(buffer)
}

pub(crate) fn read_attestation_ids() -> Result<AttestationIdInfo, Error> {
    let content = get_file_contents(KM_ATTESTATION_ID_FILENAME)?;
    let mut attestation_ids_pb: keymaster_attributes::AttestationIds =
        Message::parse_from_bytes(content.as_slice())
            .map_err(|_| km_err!(UnknownError, "Couldn't parse attestation IDs proto"))?;

    let brand = attestation_ids_pb.take_brand();
    let device = attestation_ids_pb.take_device();
    let product = attestation_ids_pb.take_product();
    let serial = attestation_ids_pb.take_serial();
    let imei = attestation_ids_pb.take_imei();
    let meid = attestation_ids_pb.take_meid();
    let manufacturer = attestation_ids_pb.take_manufacturer();
    let model = attestation_ids_pb.take_model();

    Ok(AttestationIdInfo { brand, device, product, serial, imei, meid, manufacturer, model })
}

fn read_attestation_key_content(
    key_type: SigningKeyType,
) -> Result<keymaster_attributes::AttestationKey, Error> {
    let file_name = get_key_slot_file_name(key_type.algo_hint);
    let content = get_file_contents(&file_name)?;

    let pb = Message::parse_from_bytes(content.as_slice())
        .map_err(|_| km_err!(UnknownError, "Couldn't parse attestation key proto"))?;
    Ok(pb)
}

pub(crate) fn read_attestation_key(key_type: SigningKeyType) -> Result<KeyMaterial, Error> {
    let mut attestation_key_pb: keymaster_attributes::AttestationKey =
        read_attestation_key_content(key_type)?;

    if !(attestation_key_pb.has_key()) {
        return Err(km_err!(UnknownError, "Attestation Key file found but it had no key"));
    }
    let key_buffer = attestation_key_pb.take_key();
    let key = match key_type.algo_hint {
        SigningAlgorithm::Ec => crypto::ec::import_pkcs8_key(key_buffer.as_slice())?,
        SigningAlgorithm::Rsa => {
            let (key_material, key_size, exponent) =
                crypto::rsa::import_pkcs8_key(key_buffer.as_slice())?;
            key_material
        }
    };
    // TODO: Do we need to support KEYMASTER_SOFT_ATTESTATION_FALLBACK flow?
    Ok(key)
}

pub(crate) fn get_cert_chain(key_type: SigningKeyType) -> Result<Vec<keymint::Certificate>, Error> {
    let mut attestation_certs_pb: keymaster_attributes::AttestationKey =
        read_attestation_key_content(key_type)?;
    let certs = attestation_certs_pb.take_certs();

    let num_certs = certs.len();
    if (num_certs == 0) {
        return Err(km_err!(UnknownError, "Attestation Key file found but it had no certs"));
    }
    let mut certificates = vec_try_with_capacity!(num_certs)?;
    for mut cert in certs {
        let certificate = keymint::Certificate { encoded_certificate: cert.take_content() };
        certificates.push(certificate);
    }
    // TODO: Do we need to support KEYMASTER_SOFT_ATTESTATION_FALLBACK flow?
    Ok(certificates)
}

pub struct AttestationIds;

impl RetrieveAttestationIds for AttestationIds {
    fn get(&self) -> Result<AttestationIdInfo, Error> {
        read_attestation_ids()
    }

    /// Destroy all attestation IDs associated with the device.
    fn destroy_all(&mut self) -> Result<(), Error> {
        delete_attestation_ids()
    }
}

pub struct CertSignInfo;

impl RetrieveCertSigningInfo for CertSignInfo {
    fn signing_key(&self, key_type: SigningKeyType) -> Result<KeyMaterial, Error> {
        read_attestation_key(key_type)
    }

    fn cert_chain(&self, key_type: SigningKeyType) -> Result<Vec<keymint::Certificate>, Error> {
        get_cert_chain(key_type)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use core::iter::zip;
    use kmr_common::wire::AttestationIdInfo;
    use kmr_ta::device::{SigningAlgorithm, SigningKey, SigningKeyType};
    use log::info;
    use protobuf::RepeatedField;
    use test::{expect, expect_eq, expect_ne};

    // Generated by:
    // openssl genpkey -out rsakey2.key -outform DER -algorithm RSA -pkeyopt rsa_keygen_bits:2048
    // openssl pkcs8 -topk8 -in rsakey2.key -outform der -nocrypt -out rsakey.key
    const RSA_KEY: &'static [u8] = include_bytes!("rsakey.key");
    // Generated by:
    // openssl ecparam -name prime256v1 -genkey -outform der -out eckey2.key
    // openssl pkcs8 -topk8 -in eckey2.key -outform der -nocrypt -out eckey.key
    const EC_KEY: &'static [u8] = include_bytes!("eckey.key");

    fn create_file(file_name: &str) -> (Session, SecureFile) {
        let mut session =
            Session::new(Port::TamperProof, true).expect("Couldn't connect to storage");
        let file = session
            .open_file(file_name, OpenMode::Create)
            .expect("Couldn't create attestation file.");
        (session, file)
    }

    fn create_attestation_id_file() -> (Session, SecureFile) {
        create_file(KM_ATTESTATION_ID_FILENAME)
    }

    fn create_attestation_key_file(algorithm: SigningAlgorithm) -> (Session, SecureFile) {
        let file_name = get_key_slot_file_name(algorithm);
        create_file(&file_name)
    }

    fn delete_key_file(algorithm: SigningAlgorithm) {
        let file_name = get_key_slot_file_name(algorithm);
        let mut session =
            Session::new(Port::TamperProof, true).expect("Couldn't connect to storage");
        session.remove(&file_name).expect("Couldn't delete attestation file.");
    }

    fn delete_attestation_id_file() {
        let mut session =
            Session::new(Port::TamperProof, true).expect("Couldn't connect to storage");
        session.remove(KM_ATTESTATION_ID_FILENAME).expect("Couldn't delete attestation IDs file.");
    }

    fn check_attestation_id_file_exists() -> bool {
        let mut session =
            Session::new(Port::TamperProof, true).expect("Couldn't connect to storage");
        session.open_file(KM_ATTESTATION_ID_FILENAME, OpenMode::Open).is_ok()
    }

    fn compare_attestation_ids(lhs: &AttestationIdInfo, rhs: &AttestationIdInfo) {
        expect_eq!(lhs.brand, rhs.brand, "brand doesn't match");
        expect_eq!(lhs.device, rhs.device, "device doesn't match");
        expect_eq!(lhs.product, rhs.product, "product doesn't match");
        expect_eq!(lhs.serial, rhs.serial, "serial doesn't match");
        expect_eq!(lhs.imei, rhs.imei, "imei doesn't match");
        expect_eq!(lhs.meid, rhs.meid, "meid doesn't match");
        expect_eq!(lhs.manufacturer, rhs.manufacturer, "manufacturer doesn't match");
        expect_eq!(lhs.model, rhs.model, "model doesn't match");
    }

    fn read_certificates_test(algorithm: SigningAlgorithm) {
        let (mut session, mut file) = create_attestation_key_file(algorithm);
        let mut key_cert = keymaster_attributes::AttestationKey::new();
        let certs_data = [[b'a'; 2048], [b'\0'; 2048], [b'c'; 2048]];

        let mut certs = protobuf::RepeatedField::<keymaster_attributes::AttestationCert>::new();

        for cert_data in certs_data.iter() {
            let mut cert = keymaster_attributes::AttestationCert::new();
            cert.set_content(cert_data.to_vec());
            certs.push(cert);
        }

        key_cert.set_certs(certs);

        let serialized_buffer = key_cert.write_to_bytes().expect("Couldn't serialize certs");

        session.write_all(&mut file, &serialized_buffer).unwrap();

        file.close();
        session.close();

        let key_type = SigningKeyType { which: SigningKey::Batch, algo_hint: algorithm };
        let certs = get_cert_chain(key_type).expect("Couldn't get certificates from storage");
        delete_key_file(algorithm);

        expect_eq!(certs.len(), 3, "Didn't recover all certificates");
        for (cert, cert_data) in zip(certs.iter(), certs_data.iter()) {
            expect_eq!(cert.encoded_certificate, cert_data.to_vec(), "Wrong certificate retrieved");
        }

        // Trying now using just a raw protobuf with same data
        let field_header = [18, 131, 16, 10, 128, 16];
        let mut raw_protobuf = Vec::new();
        for cert_data in certs_data.iter() {
            raw_protobuf.extend_from_slice(&field_header);
            raw_protobuf.extend_from_slice(cert_data);
        }
        let (mut session, mut file) = create_attestation_key_file(algorithm);
        session.write_all(&mut file, &raw_protobuf).unwrap();

        file.close();
        session.close();
        let certs_comp = get_cert_chain(key_type).expect("Couldn't get certificates from storage");

        expect_eq!(certs, certs_comp, "Retrieved certificates didn't match");

        delete_key_file(algorithm);
    }

    #[test]
    fn read_ec_rsa_certificates() {
        read_certificates_test(SigningAlgorithm::Rsa);
        read_certificates_test(SigningAlgorithm::Ec);
    }

    fn read_key_test(algorithm: SigningAlgorithm) {
        let (mut session, mut file) = create_attestation_key_file(algorithm);

        let mut key_cert = keymaster_attributes::AttestationKey::new();

        let test_key = match algorithm {
            SigningAlgorithm::Rsa => RSA_KEY,
            SigningAlgorithm::Ec => EC_KEY,
        };

        key_cert.set_key(test_key.to_vec());

        let serialized_buffer = key_cert.write_to_bytes().expect("Couldn't serialize key");
        session.write_all(&mut file, &serialized_buffer).unwrap();
        file.close();
        session.close();

        let key_type = SigningKeyType { which: SigningKey::Batch, algo_hint: algorithm };
        let att_key = read_attestation_key(key_type).expect("Couldn't read key from storage");

        delete_key_file(algorithm);

        // Trying now using just a raw protobuf with same data
        let key_header = match algorithm {
            SigningAlgorithm::Rsa => [10, 191, 9],
            SigningAlgorithm::Ec => [10, 138, 1],
        };
        let mut raw_protobuf = Vec::new();
        raw_protobuf.extend_from_slice(&key_header);
        raw_protobuf.extend_from_slice(&test_key);

        let (mut session, mut file) = create_attestation_key_file(algorithm);
        session.write_all(&mut file, &raw_protobuf).unwrap();
        file.close();
        session.close();

        let att_key_comp = read_attestation_key(key_type).expect("Couldn't read key from storage");

        expect_eq!(att_key, att_key_comp);

        delete_key_file(algorithm);
    }

    #[test]
    fn read_ec_rsa_key() {
        read_key_test(SigningAlgorithm::Rsa);
        read_key_test(SigningAlgorithm::Ec);
    }

    #[test]
    fn single_attestation_id_field() {
        let (mut session, mut file) = create_attestation_id_file();

        let mut attestation_ids = keymaster_attributes::AttestationIds::new();
        let brand = b"new brand";

        attestation_ids.set_brand(brand.to_vec());

        let serialized_buffer =
            attestation_ids.write_to_bytes().expect("Couldn't serialize attestationIds");

        session.write_all(&mut file, &serialized_buffer).unwrap();

        file.close();
        session.close();

        let attestation_ids_info =
            read_attestation_ids().expect("Couldn't read attestation IDs from storage");

        delete_attestation_id_file();
        expect_eq!(
            check_attestation_id_file_exists(),
            false,
            "Couldn't delete attestation IDs file"
        );

        expect_eq!(attestation_ids_info.brand, brand.to_vec(), "brand doesn't match");
        expect_eq!(attestation_ids_info.device.len(), 0, "shouldn't have a device");
        expect_eq!(attestation_ids_info.product.len(), 0, "shouldn't have a product");
        expect_eq!(attestation_ids_info.serial.len(), 0, "shouldn't have a serial");
        expect_eq!(attestation_ids_info.imei.len(), 0, "shouldn't have a imei");
        expect_eq!(attestation_ids_info.meid.len(), 0, "shouldn't have a meid");
        expect_eq!(attestation_ids_info.manufacturer.len(), 0, "shouldn't have a manufacturer");
        expect_eq!(attestation_ids_info.model.len(), 0, "shouldn't have a model");

        // Now using a raw protobuf
        let raw_protobuf = [10, 9, 110, 101, 119, 32, 98, 114, 97, 110, 100];
        let (mut session, mut file) = create_attestation_id_file();
        session.write_all(&mut file, &raw_protobuf).unwrap();
        file.close();
        session.close();
        let attestation_ids_comp = read_attestation_ids()
            .expect("Couldn't read comparison set of attestation IDs from storage");

        compare_attestation_ids(&attestation_ids_info, &attestation_ids_comp);

        delete_attestation_id_file();
        expect_eq!(
            check_attestation_id_file_exists(),
            false,
            "Couldn't delete attestation IDs file"
        );
    }

    #[test]
    fn all_attestation_id_fields() {
        let (mut session, mut file) = create_attestation_id_file();

        let mut attestation_ids = keymaster_attributes::AttestationIds::new();
        let brand = b"unknown brand";
        let device = b"my brand new device";
        let product = b"";
        let serial = vec![b'9'; 64];
        let imei = b" ";
        let meid = b"\0";
        let manufacturer = b"manufacturer #$%%^";
        let model = b"working one";

        attestation_ids.set_brand(brand.to_vec());
        attestation_ids.set_device(device.to_vec());
        attestation_ids.set_product(product.to_vec());
        attestation_ids.set_serial(serial.clone());
        attestation_ids.set_imei(imei.to_vec());
        attestation_ids.set_meid(meid.to_vec());
        attestation_ids.set_manufacturer(manufacturer.to_vec());
        attestation_ids.set_model(model.to_vec());

        let serialized_buffer =
            attestation_ids.write_to_bytes().expect("Couldn't serialize attestationIds");

        session.write_all(&mut file, &serialized_buffer).unwrap();

        file.close();
        session.close();

        let attestation_ids_info =
            read_attestation_ids().expect("Couldn't read attestation IDs from storage");

        delete_attestation_id_file();
        expect_eq!(
            check_attestation_id_file_exists(),
            false,
            "Couldn't delete attestation IDs file"
        );

        expect_eq!(attestation_ids_info.brand, brand.to_vec(), "brand doesn't match");
        expect_eq!(attestation_ids_info.device, device.to_vec(), "device doesn't match");
        expect_eq!(attestation_ids_info.product, product.to_vec(), "product doesn't match");
        expect_eq!(attestation_ids_info.serial, serial, "serial doesn't match");
        expect_eq!(attestation_ids_info.imei, imei.to_vec(), "imei doesn't match");
        expect_eq!(attestation_ids_info.meid, meid.to_vec(), "meid doesn't match");
        expect_eq!(
            attestation_ids_info.manufacturer,
            manufacturer.to_vec(),
            "manufacturer doesn't match"
        );
        expect_eq!(attestation_ids_info.model, model.to_vec(), "model doesn't match");

        // Now trying the same from a raw protobuf
        let raw_protobuf = [
            10, 13, 117, 110, 107, 110, 111, 119, 110, 32, 98, 114, 97, 110, 100, 18, 19, 109, 121,
            32, 98, 114, 97, 110, 100, 32, 110, 101, 119, 32, 100, 101, 118, 105, 99, 101, 26, 0,
            34, 64, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57,
            57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57,
            57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57,
            42, 1, 32, 50, 1, 0, 58, 18, 109, 97, 110, 117, 102, 97, 99, 116, 117, 114, 101, 114,
            32, 35, 36, 37, 37, 94, 66, 11, 119, 111, 114, 107, 105, 110, 103, 32, 111, 110, 101,
        ];

        let (mut session, mut file) = create_attestation_id_file();
        session.write_all(&mut file, &raw_protobuf).unwrap();
        file.close();
        session.close();

        let attestation_ids_comp = read_attestation_ids()
            .expect("Couldn't read comparison set of attestation IDs from storage");

        compare_attestation_ids(&attestation_ids_info, &attestation_ids_comp);

        delete_attestation_id_file();
        expect_eq!(
            check_attestation_id_file_exists(),
            false,
            "Couldn't delete attestation IDs file"
        );
    }

    #[test]
    fn delete_attestation_ids_file() {
        let (mut session, mut file) = create_attestation_id_file();
        let raw_protobuf = [10, 9, 110, 101, 119, 32, 98, 114, 97, 110, 100];
        session.write_all(&mut file, &raw_protobuf).unwrap();
        file.close();
        session.close();
        expect!(check_attestation_id_file_exists(), "Couldn't create attestation IDs file");
        expect!(delete_attestation_ids().is_ok(), "Couldn't delete attestation IDs file");
        expect_eq!(
            check_attestation_id_file_exists(),
            false,
            "Attestation IDs file was not deleted"
        );
    }

    #[test]
    fn protobuf_lib_version() {
        // We are generating the protobuf rust files out of tree because we cannot do it in-tree yet
        // Because the version of the tool used to autogenerate the files has to match the protobuf
        // library version, we check it here.
        expect_eq!("2.27.1", protobuf::VERSION, "autogenerated files version mistmatch");
    }
}
