use crate::CscaError;
use regex::Regex;
use std::str;
use base64::{Engine as _, engine::general_purpose};
use x509_parser::prelude::*;
use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;
use der::{Decode, Encode};

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
    
    pub fn parse(&self) -> Result<X509Certificate, CscaError> {
        let (_, cert) = X509Certificate::from_der(&self.der_data)
            .map_err(|e| CscaError::X509Error(format!("Failed to parse certificate: {}", e)))?;
        Ok(cert)
    }
    
    pub fn der_data(&self) -> &[u8] {
        &self.der_data
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

    pub fn parse_to_owned_certificates(&self, content: &str) -> Result<Vec<OwnedCertificate>, CscaError> {
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
                
                // Parse this PKD entry as a master list
                match self.parse_pkd_entry(&decoded) {
                    Ok(master_list) => {
                        master_lists.push(master_list);
                    }
                    Err(e) => {
                        eprintln!("Warning: Failed to parse PKD entry: {}", e);
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
        println!("=== Parsing PKD Entry ===");
        println!("PKD data length: {} bytes", data.len());
        println!("PKD data hex preview: {}", hex::encode(&data[..std::cmp::min(32, data.len())]));

        // Parse the ContentInfo structure
        let content_info = ContentInfo::from_der(data)
            .map_err(|e| CscaError::DerError(format!("Failed to parse ContentInfo: {}", e)))?;
        
        println!("✓ ContentInfo parsed successfully");
        println!("  Content type: {:?}", content_info.content_type);
        
        // Extract SignedData from the content
        let content_der = content_info.content.to_der()
            .map_err(|e| CscaError::DerError(format!("Failed to serialize content: {}", e)))?;
        
        println!("  Content DER length: {} bytes", content_der.len());
        
        let signed_data = SignedData::from_der(&content_der)
            .map_err(|e| CscaError::DerError(format!("Failed to parse SignedData: {}", e)))?;
        
        println!("✓ SignedData parsed successfully");
        println!("  SignedData version: {:?}", signed_data.version);
        println!("  SignedData encap_content_info.econtent_type: {:?}", signed_data.encap_content_info.econtent_type);
        
        // Get the encapsulated content (the master list)
        if let Some(econtent) = &signed_data.encap_content_info.econtent {
            println!("✓ Encapsulated content found");
            
            // Get the raw bytes from econtent
            let encap_data = econtent.to_der()
                .map_err(|e| CscaError::DerError(format!("Failed to serialize econtent: {}", e)))?;
            
            println!("  Encapsulated content length: {} bytes", encap_data.len());
            println!("  Encapsulated content hex preview: {}", hex::encode(&encap_data[..std::cmp::min(64, encap_data.len())]));
            
            // Parse the ASN.1 structure to extract the master list
            let master_list = self.parse_encap_data_with_asn1(&encap_data)?;
            
            println!("✓ Master list parsed successfully");
            println!("  Version: {}", master_list.version);
            println!("  Certificate count: {}", master_list.cert_list.len());
            
            Ok(master_list)
        } else {
            Err(CscaError::DerError("No encapsulated content found in SignedData".to_string()))
        }
    }
    
    fn parse_encap_data_with_asn1(&self, data: &[u8]) -> Result<CscaMasterList, CscaError> {
        println!("=== Parsing ASN.1 Master List with asn1 crate ===");
        println!("Data length: {} bytes", data.len());
        println!("Data hex preview: {}", hex::encode(&data[..std::cmp::min(64, data.len())]));
        
        // The encapsulated data might be wrapped in an OCTET STRING
        let actual_data = if data.len() > 2 && data[0] == 0x04 {
            // OCTET STRING tag (0x04)
            println!("Data is wrapped in OCTET STRING, extracting...");
            let length_byte = data[1];
            if length_byte & 0x80 == 0 {
                // Short form length
                let content_length = length_byte as usize;
                if data.len() >= 2 + content_length {
                    &data[2..2 + content_length]
                } else {
                    return Err(CscaError::DerError("Invalid OCTET STRING length".to_string()));
                }
            } else {
                // Long form length - more complex parsing needed
                let length_bytes = (length_byte & 0x7f) as usize;
                if length_bytes == 0 || length_bytes > 4 || data.len() < 2 + length_bytes {
                    return Err(CscaError::DerError("Invalid OCTET STRING length encoding".to_string()));
                }
                
                let mut content_length = 0usize;
                for i in 0..length_bytes {
                    content_length = (content_length << 8) | data[2 + i] as usize;
                }
                
                let start = 2 + length_bytes;
                if data.len() >= start + content_length {
                    &data[start..start + content_length]
                } else {
                    return Err(CscaError::DerError("Invalid OCTET STRING content length".to_string()));
                }
            }
        } else {
            data
        };
        
        println!("Actual data length: {} bytes", actual_data.len());
        println!("Actual data hex preview: {}", hex::encode(&actual_data[..std::cmp::min(64, actual_data.len())]));
        
        println!("✓ Starting to parse master list structure");
        
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
                        println!("Found version: {}", version);
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
                        println!("Found certificate at position {}, length: {}", pos - cert_len, cert_len);
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
        
        println!("Successfully extracted {} certificates", cert_list.len());
        
        Ok(CscaMasterList {
            version,
            cert_list,
        })
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
