use csca_parser::{parse_ldif_original};
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Read the LDIF file
    let data = fs::read("assets/icaopkd-list.ldif")?;

    println!("Reading LDIF file with {} bytes", data.len());

    // Parse the LDIF file
    match parse_ldif_original(&data) {
        Ok(certificates) => {
            println!("Successfully parsed {} certificates", certificates.len());

            // Print info about each certificate
            for (i, cert) in certificates.iter().enumerate().take(5) {
                match cert.parse() {
                    Ok(parsed_cert) => {
                        println!("Certificate {}: Subject: {}", i + 1, parsed_cert.subject);
                        println!("  Issuer: {}", parsed_cert.issuer);
                        println!("  Serial: {}", parsed_cert.serial);
                        println!("  Not Before: {}", parsed_cert.validity.not_before);
                        println!("  Not After: {}", parsed_cert.validity.not_after);
                    }
                    Err(e) => {
                        println!("Certificate {}: Failed to parse: {}", i + 1, e);
                    }
                }
            }
        }
        Err(e) => {
            println!("Failed to parse LDIF: {}", e);
        }
    }

    Ok(())
}
