pub mod parser;
pub mod error;

pub use parser::{LdifParser, OwnedCertificate, PemParser};
pub use error::{CscaError, CertificateError};

// UniFFI setup
uniffi::setup_scaffolding!();

/// Parse LDIF bytes and return raw certificate DER data
/// This function returns a vector of raw certificate bytes (DER format)
/// suitable for parsing with tools like peculiar/asn1-schema
#[uniffi::export]
pub fn parse_ldif(data: Vec<u8>) -> Result<Vec<Vec<u8>>, CscaError> {
    let parser = LdifParser::new();
    let content = std::str::from_utf8(&data)?;
    let certificates = parser.parse_to_owned_certificates(content)?;
    Ok(certificates.into_iter().map(|cert| cert.der_data().to_vec()).collect())
}

/// Parse LDIF string and return raw certificate DER data
/// This function returns a vector of raw certificate bytes (DER format)
/// suitable for parsing with tools like peculiar/asn1-schema
#[uniffi::export]
pub fn parse_ldif_string(data: String) -> Result<Vec<Vec<u8>>, CscaError> {
    let parser = LdifParser::new();
    let certificates = parser.parse_to_owned_certificates(&data)?;
    Ok(certificates.into_iter().map(|cert| cert.der_data().to_vec()).collect())
}

/// Parse PEM bytes and return raw certificate DER data
/// This function returns a vector of raw certificate bytes (DER format)
/// suitable for parsing with tools like peculiar/asn1-schema
#[uniffi::export]
pub fn parse_pem(data: Vec<u8>) -> Result<Vec<Vec<u8>>, CscaError> {
    let parser = PemParser::new();
    let certificates = parser.parse(&data)?;
    Ok(certificates.into_iter().map(|cert| cert.der_data().to_vec()).collect())
}

/// Parse PEM string and return raw certificate DER data
/// This function returns a vector of raw certificate bytes (DER format)
/// suitable for parsing with tools like peculiar/asn1-schema
#[uniffi::export]
pub fn parse_pem_string(data: String) -> Result<Vec<Vec<u8>>, CscaError> {
    let parser = PemParser::new();
    let certificates = parser.parse_string(&data)?;
    Ok(certificates.into_iter().map(|cert| cert.der_data().to_vec()).collect())
}

/// Find the master certificate for a given slave certificate
/// Returns the DER data of the master certificate if found
#[uniffi::export]
pub fn find_master_certificate(slave_cert_der: Vec<u8>, master_certs_der: Vec<Vec<u8>>) -> Result<Option<Vec<u8>>, CscaError> {
    let slave_cert = OwnedCertificate::from_der(slave_cert_der)?;

    // Convert master certificate DER data to OwnedCertificate objects
    let mut master_certs = Vec::new();
    for master_der in master_certs_der {
        match OwnedCertificate::from_der(master_der) {
            Ok(cert) => master_certs.push(cert),
            Err(_) => continue, // Skip invalid certificates
        }
    }

    // Find the master certificate
    let master_cert = slave_cert.find_master_certificate(&master_certs)?;

    Ok(master_cert.map(|cert| cert.der_data().to_vec()))
}

// Keep the original convenience functions for backwards compatibility
/// Parse LDIF bytes and return a list of owned certificates
pub fn parse_ldif_original(data: &[u8]) -> Result<Vec<OwnedCertificate>, CscaError> {
    let parser = LdifParser::new();
    let content = std::str::from_utf8(data)?;
    parser.parse_to_owned_certificates(content)
}

/// Parse LDIF string and return a list of owned certificates
pub fn parse_ldif_string_original(data: &str) -> Result<Vec<OwnedCertificate>, CscaError> {
    let parser = LdifParser::new();
    parser.parse_to_owned_certificates(data)
}

/// Parse PEM bytes and return a list of owned certificates
pub fn parse_pem_original(data: &[u8]) -> Result<Vec<OwnedCertificate>, CscaError> {
    let parser = PemParser::new();
    parser.parse(data)
}

/// Parse PEM string and return a list of owned certificates
pub fn parse_pem_string_original(data: &str) -> Result<Vec<OwnedCertificate>, CscaError> {
    let parser = PemParser::new();
    parser.parse_string(data)
}
