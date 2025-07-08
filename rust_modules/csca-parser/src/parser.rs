use crate::CscaError;
use base64::{engine::general_purpose, Engine as _};
use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;
use der::{Decode, Encode};
use regex::Regex;
use x509_parser::asn1_rs::ToDer;
use x509_parser::oid_registry::*;
use x509_parser::prelude::*;
use x509_parser::public_key::PublicKey;

// Define the CSCA Master List structure similar to your Go code
#[derive(Debug)]
pub struct CscaMasterList {
    pub version: i32,
    pub cert_list: Vec<Vec<u8>>, // Raw certificate data - each Vec<u8> is a certificate in DER format
}

pub struct LdifParser {
    pkd_regex: Regex,
}

// A wrapper that owns the certificate DER data
#[derive(Clone)]
pub struct OwnedCertificate {
    der_data: Vec<u8>,
}

impl OwnedCertificate {
    pub fn from_der(der_data: Vec<u8>) -> Result<Self, CscaError> {
        // Validate that this is a valid certificate
        X509Certificate::from_der(&der_data)
            .map_err(|e| CscaError::X509Error(format!("Invalid certificate DER data: {}", e)))?;

        Ok(OwnedCertificate { der_data })
    }

    pub fn from_pem(pem_bytes: Vec<u8>) -> Result<Self, CscaError> {
        let content = str::from_utf8(&pem_bytes)?;
        let pem_obj = ::pem::parse(content)
            .map_err(|e| CscaError::PemError(format!("Failed to parse PEM data: {}", e)))?;

        if pem_obj.tag() != "CERTIFICATE" {
            return Err(CscaError::PemError(
                "PEM object is not a certificate".to_string(),
            ));
        }

        let der_data = pem_obj.contents().to_vec();
        Self::from_der(der_data)
    }

    pub fn parse(&self) -> Result<X509Certificate, CscaError> {
        let (_, cert) = X509Certificate::from_der(&self.der_data)
            .map_err(|e| CscaError::X509Error(format!("Failed to parse certificate: {}", e)))?;
        Ok(cert)
    }

    pub fn der_data(&self) -> &[u8] {
        &self.der_data
    }

    /// Find the master certificate that signed this slave certificate
    /// Returns the first matching master certificate from the provided list
    pub fn find_master_certificate(
        &self,
        masters: &[OwnedCertificate],
    ) -> Result<Option<OwnedCertificate>, CscaError> {
        let slave_cert = self.parse()?;

        // Find candidates by matching issuer with subject
        let mut candidates = Vec::new();
        for master in masters {
            let master_cert = master.parse()?;

            // Check if issuer matches subject
            if slave_cert.issuer() == master_cert.subject() {
                candidates.push(master.clone());
            }
        }

        // Get the Authority Key Identifier from the slave certificate
        let slave_aki = self.extract_authority_key_identifier(&slave_cert)?;

        // Filter candidates by matching AKI with SKI
        for candidate in candidates {
            let master_cert = candidate.parse()?;

            // Get the Subject Key Identifier from the master certificate
            if let Ok(master_ski) = self.extract_subject_key_identifier(&master_cert) {
                if slave_aki == master_ski {
                    return Ok(Some(candidate));
                }
            }
        }

        Ok(None)
    }

    /// Extract Authority Key Identifier from a certificate
    fn extract_authority_key_identifier(
        &self,
        cert: &X509Certificate,
    ) -> Result<Vec<u8>, CscaError> {
        // Look for Authority Key Identifier extension
        for ext in cert.extensions() {
            if ext.oid == OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER {
                if let ParsedExtension::AuthorityKeyIdentifier(aki) = ext.parsed_extension() {
                    if let Some(key_id) = &aki.key_identifier {
                        return Ok(key_id.0.to_vec());
                    }
                }
            }
        }

        Err(CscaError::X509Error(
            "Authority Key Identifier extension not found".to_string(),
        ))
    }

    /// Extract Subject Key Identifier from a certificate
    fn extract_subject_key_identifier(&self, cert: &X509Certificate) -> Result<Vec<u8>, CscaError> {
        // Look for Subject Key Identifier extension
        for ext in cert.extensions() {
            if ext.oid == OID_X509_EXT_SUBJECT_KEY_IDENTIFIER {
                if let ParsedExtension::SubjectKeyIdentifier(ski) = ext.parsed_extension() {
                    return Ok(ski.0.to_vec());
                }
            }
        }

        Err(CscaError::X509Error(
            "Subject Key Identifier extension not found".to_string(),
        ))
    }

    pub fn extract_raw_public_key(&self) -> Result<Vec<u8>, CscaError> {
        // Extract the public key matching Go's ExtractPubKeys behavior
        let cert = self.parse()?;
        let public_key_info = cert.public_key();

        let parsed_public_key = match public_key_info.parsed() {
            Ok(parsed) => parsed,
            Err(e) => {
                return Err(CscaError::X509Error(format!(
                    "Failed to parse public key: {}",
                    e
                )));
            }
        };

        match parsed_public_key {
            PublicKey::RSA(rsa_key) => {
                // Extract RSA modulus
                Ok(rsa_key
                    .modulus
                    .iter()
                    .cloned()
                    .collect::<Vec<u8>>())
            }
            PublicKey::EC(ec_point) => {
                // For EC keys, return the raw point data directly
                // This avoids the type parameter issues with EncodedPoint::from_bytes
                Ok(ec_point.data().to_vec())
            }
            PublicKey::DSA(dsa_key) => {
                // For DSA, return the raw public key data
                Ok(dsa_key.to_vec())
            }
            PublicKey::GostR3410(gost_key) => {
                // For GOST R 34.10, return the raw public key data
                Ok(gost_key.to_vec())
            }
            PublicKey::GostR3410_2012(gost_key) => {
                // For GOST R 34.10-2012, return the raw public key data
                Ok(gost_key.to_vec())
            }
            _ => {
                // For other public key types, return the raw algorithm identifier and key data
                let spki = &public_key_info.subject_public_key;
                spki.to_der_vec_raw().map_err(|e| CscaError::X509Error(format!("Failed to serialize public key: {}", e)))
            },
        }
    }
}

impl LdifParser {
    pub fn new() -> Self {
        Self {
            pkd_regex: Regex::new(r"(?s)pkdMasterListContent:: (.*?)\n\n").unwrap(),
        }
    }

    pub fn parse(&self, data: &[u8]) -> Result<Vec<X509Certificate>, CscaError> {
        let content = str::from_utf8(data)?;
        self.parse_string(content)
    }

    pub fn parse_string(&self, content: &str) -> Result<Vec<X509Certificate>, CscaError> {
        let owned_certs = self.parse_to_owned_certificates(content)?;
        let mut certificates = Vec::new();

        for owned_cert in owned_certs {
            // Use Box::leak to make the certificate data live for the entire program duration
            // This is necessary because X509Certificate needs to borrow from the DER data
            let static_data: &'static [u8] = Box::leak(owned_cert.der_data.into_boxed_slice());
            match X509Certificate::from_der(static_data) {
                Ok((_, cert)) => certificates.push(cert),
                Err(e) => eprintln!("Warning: Failed to parse certificate: {}", e),
            }
        }

        if certificates.is_empty() {
            return Err(CscaError::NoCertificatesFound);
        }

        Ok(certificates)
    }

    pub fn parse_to_owned_certificates(
        &self,
        content: &str,
    ) -> Result<Vec<OwnedCertificate>, CscaError> {
        let mut all_certificates = Vec::new();

        // Find all pkdMasterListContent entries - each match is a master list
        let mut master_lists = Vec::new();

        for captures in self.pkd_regex.captures_iter(content) {
            if let Some(base64_match) = captures.get(1) {
                let base64_data = base64_match.as_str();

                // Remove newline + space patterns (continuation lines)
                let clean_base64 = base64_data.replace("\n ", "");

                // Decode base64
                let decoded = general_purpose::STANDARD.decode(clean_base64.trim())?;

                // println!("Decoded length: {}", decoded.len());
                // println!(
                //     "First 32 bytes: {:?}",
                //     &decoded[..std::cmp::min(32, decoded.len())]
                // );

                // Parse this PKD entry as a master list
                match self.parse_pkd_entry(&decoded) {
                    Ok(master_list) => {
                        master_lists.push(master_list);
                    }
                    Err(e) => {
                        eprintln!("Warning: Failed to parse PKD entry: {} {}", e, clean_base64);
                    }
                }
            }
        }

        // Convert all master lists to owned certificates
        for master_list in master_lists {
            for cert_data in master_list.cert_list {
                match OwnedCertificate::from_der(cert_data) {
                    Ok(cert) => all_certificates.push(cert),
                    Err(e) => eprintln!("Warning: Failed to create certificate from DER: {}", e),
                }
            }
        }

        if all_certificates.is_empty() {
            return Err(CscaError::NoCertificatesFound);
        }

        Ok(all_certificates)
    }

    fn parse_pkd_entry(&self, data: &[u8]) -> Result<CscaMasterList, CscaError> {
        // Try to parse as strict DER first
        match self.parse_pkd_entry_der(data) {
            Ok(master_list) => Ok(master_list),
            Err(der_error) => {
                // If DER parsing fails, try BER parsing as fallback
                match self.parse_pkd_entry_ber(data) {
                    Ok(master_list) => Ok(master_list),
                    Err(ber_error) => {
                        // If both fail, return the original DER error
                        Err(CscaError::DerError(format!(
                            "Failed to parse PKD entry as both DER and BER. DER error: {}. BER error: {}",
                            der_error, ber_error
                        )))
                    }
                }
            }
        }
    }

    fn parse_pkd_entry_der(&self, data: &[u8]) -> Result<CscaMasterList, CscaError> {
        // Parse the ContentInfo structure
        let content_info = ContentInfo::from_der(data)
            .map_err(|e| CscaError::DerError(format!("Failed to parse ContentInfo: {}", e)))?;

        // Extract SignedData from the content
        let content_der = content_info
            .content
            .to_der()
            .map_err(|e| CscaError::DerError(format!("Failed to serialize content: {}", e)))?;

        let signed_data = SignedData::from_der(&content_der)
            .map_err(|e| CscaError::DerError(format!("Failed to parse SignedData: {}", e)))?;

        // Get the encapsulated content (the master list)
        if let Some(econtent) = &signed_data.encap_content_info.econtent {
            // Get the raw bytes from econtent
            let encap_data = econtent
                .to_der()
                .map_err(|e| CscaError::DerError(format!("Failed to serialize econtent: {}", e)))?;

            // Parse the ASN.1 structure to extract the master list
            let master_list = self.parse_encap_data_with_asn1(&encap_data)?;

            Ok(master_list)
        } else {
            Err(CscaError::DerError(
                "No encapsulated content found in SignedData".to_string(),
            ))
        }
    }

    fn parse_pkd_entry_ber(&self, data: &[u8]) -> Result<CscaMasterList, CscaError> {
        // For BER encoded data, we need to manually parse the structure
        // This is a simplified approach that looks for certificates directly in the data
        use ::der_parser::ber::parse_ber_sequence;

        // Try to parse the top-level sequence
        match parse_ber_sequence(data) {
            Ok((_, _)) => {
                // Look for embedded certificates in the parsed structure
                let master_list = self.extract_certificates_from_ber_data(data)?;
                Ok(master_list)
            }
            Err(e) => Err(CscaError::DerError(format!(
                "Failed to parse BER sequence: {}",
                e
            ))),
        }
    }

    fn extract_certificates_from_ber_data(&self, data: &[u8]) -> Result<CscaMasterList, CscaError> {
        // Scan through the data looking for certificate patterns
        let mut cert_list = Vec::new();
        let mut pos = 0;
        let version = 0i32; // Default version

        while pos < data.len() {
            if pos + 4 < data.len() && data[pos] == 0x30 {
                // Found a potential certificate (SEQUENCE)
                if let Some(cert_der) = self.extract_certificate_at_position(data, pos) {
                    // Validate it's actually a certificate
                    if let Ok((_, _)) = X509Certificate::from_der(&cert_der) {
                        let cert_len = cert_der.len();
                        cert_list.push(cert_der);
                        pos += cert_len;
                    } else {
                        pos += 1;
                    }
                } else {
                    pos += 1;
                }
            } else {
                pos += 1;
            }
        }

        if cert_list.is_empty() {
            return Err(CscaError::NoCertificatesFound);
        }

        Ok(CscaMasterList { version, cert_list })
    }

    fn parse_encap_data_with_asn1(&self, data: &[u8]) -> Result<CscaMasterList, CscaError> {
        // The encapsulated data might be wrapped in an OCTET STRING
        let actual_data = if data.len() > 2 && data[0] == 0x04 {
            // OCTET STRING tag (0x04)

            let length_byte = data[1];
            if length_byte & 0x80 == 0 {
                // Short form length
                let content_length = length_byte as usize;
                if data.len() >= 2 + content_length {
                    &data[2..2 + content_length]
                } else {
                    return Err(CscaError::DerError(
                        "Invalid OCTET STRING length".to_string(),
                    ));
                }
            } else {
                // Long form length - more complex parsing needed
                let length_bytes = (length_byte & 0x7f) as usize;
                if length_bytes == 0 || length_bytes > 4 || data.len() < 2 + length_bytes {
                    return Err(CscaError::DerError(
                        "Invalid OCTET STRING length encoding".to_string(),
                    ));
                }

                let mut content_length = 0usize;
                for i in 0..length_bytes {
                    content_length = (content_length << 8) | data[2 + i] as usize;
                }

                let start = 2 + length_bytes;
                if data.len() >= start + content_length {
                    &data[start..start + content_length]
                } else {
                    return Err(CscaError::DerError(
                        "Invalid OCTET STRING content length".to_string(),
                    ));
                }
            }
        } else {
            data
        };

        // Parse the sequence elements step by step
        let mut version = 0i32;
        let mut cert_list = Vec::new();

        // Try to parse version and certificates from the sequence
        // This is a simplified approach - we'll scan for X.509 certificates
        let mut pos = 0;
        let mut found_version = false;

        // First, try to find version (INTEGER)
        while pos < actual_data.len() && !found_version {
            if actual_data[pos] == 0x02 {
                // INTEGER tag
                if pos + 1 < actual_data.len() {
                    let length = actual_data[pos + 1] as usize;
                    if length > 0 && length <= 4 && pos + 2 + length <= actual_data.len() {
                        let mut ver = 0i32;
                        for i in 0..length {
                            ver = (ver << 8) | actual_data[pos + 2 + i] as i32;
                        }
                        version = ver;
                        found_version = true;

                        pos += 2 + length;
                    } else {
                        pos += 1;
                    }
                } else {
                    pos += 1;
                }
            } else {
                pos += 1;
            }
        }

        // Now scan for certificates (SEQUENCE starting with 0x30)
        pos = 0;
        while pos < actual_data.len() {
            if actual_data[pos] == 0x30 {
                // Found a potential certificate (SEQUENCE)
                if let Some(cert_der) = self.extract_certificate_at_position(actual_data, pos) {
                    // Validate it's actually a certificate
                    if let Ok((_, _)) = X509Certificate::from_der(&cert_der) {
                        let cert_len = cert_der.len();
                        cert_list.push(cert_der);
                        pos += cert_len;
                    } else {
                        pos += 1;
                    }
                } else {
                    pos += 1;
                }
            } else {
                pos += 1;
            }
        }

        Ok(CscaMasterList { version, cert_list })
    }

    fn extract_certificate_at_position(&self, data: &[u8], pos: usize) -> Option<Vec<u8>> {
        if pos + 2 >= data.len() {
            return None;
        }

        // Parse the length field of the SEQUENCE
        let length_byte = data[pos + 1];
        if length_byte & 0x80 == 0 {
            // Short form length
            let content_length = length_byte as usize;
            let total_length = 2 + content_length;
            if pos + total_length <= data.len() {
                return Some(data[pos..pos + total_length].to_vec());
            }
        } else {
            // Long form length
            let length_bytes = (length_byte & 0x7f) as usize;
            if length_bytes == 0 || length_bytes > 4 || pos + 2 + length_bytes > data.len() {
                return None;
            }

            let mut content_length = 0usize;
            for i in 0..length_bytes {
                content_length = (content_length << 8) | data[pos + 2 + i] as usize;
            }

            let total_length = 2 + length_bytes + content_length;
            if pos + total_length <= data.len() {
                return Some(data[pos..pos + total_length].to_vec());
            }
        }

        None
    }
}

pub struct PemParser;

impl PemParser {
    pub fn new() -> Self {
        Self
    }

    /// Parse PEM-encoded certificates from bytes
    pub fn parse(&self, data: &[u8]) -> Result<Vec<OwnedCertificate>, CscaError> {
        let content = str::from_utf8(data)?;
        self.parse_string(content)
    }

    /// Parse PEM-encoded certificates from a string
    pub fn parse_string(&self, content: &str) -> Result<Vec<OwnedCertificate>, CscaError> {
        let pem_objects = ::pem::parse_many(content)
            .map_err(|e| CscaError::PemError(format!("Failed to parse PEM data: {}", e)))?;

        let mut certificates = Vec::new();

        for pem_obj in pem_objects {
            // Only process CERTIFICATE objects
            if pem_obj.tag() == "CERTIFICATE" {
                // The contents are already DER-encoded
                let der_data = pem_obj.contents().to_vec();

                // Validate that this is a valid certificate
                match OwnedCertificate::from_der(der_data) {
                    Ok(cert) => certificates.push(cert),
                    Err(e) => {
                        eprintln!("Warning: Failed to parse certificate from PEM: {}", e);
                    }
                }
            }
        }

        if certificates.is_empty() {
            return Err(CscaError::NoCertificatesFound);
        }

        Ok(certificates)
    }
}

impl Default for LdifParser {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for PemParser {
    fn default() -> Self {
        Self::new()
    }
}
