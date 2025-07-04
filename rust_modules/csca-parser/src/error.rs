use thiserror::Error;

#[derive(Error, Debug, uniffi::Error)]
#[uniffi(flat_error)]
pub enum CscaError {
    #[error("LDIF parsing error: {0}")]
    LdifParseError(String),
    
    #[error("Certificate error: {0}")]
    CertificateError(String),
    
    #[error("Invalid LDIF format")]
    InvalidFormat,
    
    #[error("No certificates found in LDIF")]
    NoCertificatesFound,
    
    #[error("Base64 decode error: {0}")]
    Base64Error(String),
    
    #[error("UTF-8 conversion error: {0}")]
    Utf8Error(String),

    #[error("ASN.1 parsing error: {0}")]
    Asn1Error(String),

    #[error("DER parsing error: {0}")]
    DerError(String),

    #[error("X509 parsing error: {0}")]
    X509Error(String),
    
    #[error("PEM parsing error: {0}")]
    PemError(String),
}

// Convert from other error types to CscaError
impl From<base64::DecodeError> for CscaError {
    fn from(err: base64::DecodeError) -> Self {
        CscaError::Base64Error(err.to_string())
    }
}

impl From<std::str::Utf8Error> for CscaError {
    fn from(err: std::str::Utf8Error) -> Self {
        CscaError::Utf8Error(err.to_string())
    }
}

impl From<CertificateError> for CscaError {
    fn from(err: CertificateError) -> Self {
        CscaError::CertificateError(err.to_string())
    }
}

#[derive(Error, Debug)]
pub enum CertificateError {
    #[error("Parse error: {0}")]
    ParseError(String),
    
    #[error("Invalid certificate data")]
    InvalidData,
    
    #[error("Certificate expired")]
    Expired,
    
    #[error("X509 parsing error: {0}")]
    X509Error(String),
}
