use std::fs;

use csca_parser::{find_master_certificate, parse_ldif_original, OwnedCertificate};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Example usage of find_master_certificate

    // Read the LDIF file
    let data = fs::read("assets/ldif.ldif")?;

    // Parse the LDIF to get certificate DER data
    let certificates = match parse_ldif_original(&data) {
        Ok(certs) => certs,
        Err(e) => {
            eprintln!("Failed to parse LDIF: {}", e);
            return Ok(());
        }
    };

    if certificates.len() < 2 {
        eprintln!("Need at least 2 certificates to demonstrate master finding");
        return Ok(());
    }

    // Take the first certificate as the "slave" and the rest as potential masters
    let slave_cert_pem = base64::decode("...").unwrap();
    let slave_cert = OwnedCertificate::from_pem(slave_cert_pem)?;
    let master_certs_der = certificates[1..].into_iter().map(|cert| cert.der_data().to_vec()).collect();

    // Find the master certificate
    match find_master_certificate(slave_cert.der_data().to_vec(), master_certs_der) {
        Ok(Some(master_der)) => {
            println!("Found master certificate! DER length: {} bytes", master_der.len());
            println!("Master certificate hex (first 32 bytes): {}",
                     hex::encode(&master_der[..std::cmp::min(32, master_der.len())]));
        }
        Ok(None) => {
            println!("No master certificate found");
        }
        Err(e) => {
            println!("Error finding master certificate: {}", e);
        }
    }

    Ok(())
}
