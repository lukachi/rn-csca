use csca_parser::{parse_pem_original};
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Read the PEM file
    let data = fs::read("assets/ICAO.pem")?;
    
    println!("Reading PEM file with {} bytes", data.len());
    
    // Parse the PEM file
    match parse_pem_original(&data) {
        Ok(certificates) => {
            println!("Successfully parsed {} certificates", certificates.len());
            
            // Print info about each certificate (first 10 for brevity)
            for (i, cert) in certificates.iter().enumerate().take(10) {
                match cert.parse() {
                    Ok(parsed_cert) => {
                        println!("Certificate {}: Subject: {}", i + 1, parsed_cert.subject);
                        println!("  Issuer: {}", parsed_cert.issuer);
                        println!("  Serial: {}", parsed_cert.serial);
                        println!("  Not Before: {}", parsed_cert.validity.not_before);
                        println!("  Not After: {}", parsed_cert.validity.not_after);
                        println!("  Public Key Algorithm: {:?}", parsed_cert.public_key().algorithm);
                        println!("  Signature Algorithm: {:?}", parsed_cert.signature_algorithm);
                        println!("  Extensions: {} found", parsed_cert.extensions().len());
                        
                        // Print basic key info
                        match parsed_cert.public_key().algorithm.algorithm.to_string().as_str() {
                            "1.2.840.10045.2.1" => println!("  Key Type: ECC"),
                            "1.2.840.113549.1.1.1" => println!("  Key Type: RSA"),
                            other => println!("  Key Type: {} (OID: {})", other, other),
                        }
                        
                        println!();
                    }
                    Err(e) => {
                        println!("Certificate {}: Failed to parse: {}", i + 1, e);
                    }
                }
            }
            
            if certificates.len() > 10 {
                println!("... and {} more certificates", certificates.len() - 10);
            }
        }
        Err(e) => {
            println!("Failed to parse PEM: {}", e);
        }
    }
    
    Ok(())
}
