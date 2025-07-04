use csca_parser::{parse_ldif_original, parse_pem_original};
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== CSCA Parser Demo ===");
    
    // Test LDIF parsing
    println!("\n1. Testing LDIF parsing:");
    if let Ok(ldif_data) = fs::read("assets/ldif.ldif") {
        println!("Reading LDIF file with {} bytes", ldif_data.len());
        
        match parse_ldif_original(&ldif_data) {
            Ok(certificates) => {
                println!("✓ Successfully parsed {} certificates from LDIF", certificates.len());
                
                // Show first certificate details
                if let Some(cert) = certificates.first() {
                    if let Ok(parsed_cert) = cert.parse() {
                        println!("  First certificate:");
                        println!("    Subject: {}", parsed_cert.subject);
                        println!("    Issuer: {}", parsed_cert.issuer);
                        println!("    Valid from: {} to {}", 
                            parsed_cert.validity.not_before, 
                            parsed_cert.validity.not_after);
                    }
                }
            }
            Err(e) => {
                println!("✗ Failed to parse LDIF: {}", e);
            }
        }
    } else {
        println!("⚠ LDIF file not found, skipping LDIF test");
    }
    
    // Test PEM parsing
    println!("\n2. Testing PEM parsing:");
    if let Ok(pem_data) = fs::read("assets/ICAO.pem") {
        println!("Reading PEM file with {} bytes", pem_data.len());
        
        match parse_pem_original(&pem_data) {
            Ok(certificates) => {
                println!("✓ Successfully parsed {} certificates from PEM", certificates.len());
                
                // Show first certificate details
                if let Some(cert) = certificates.first() {
                    if let Ok(parsed_cert) = cert.parse() {
                        println!("  First certificate:");
                        println!("    Subject: {}", parsed_cert.subject);
                        println!("    Issuer: {}", parsed_cert.issuer);
                        println!("    Valid from: {} to {}", 
                            parsed_cert.validity.not_before, 
                            parsed_cert.validity.not_after);
                    }
                }
                
                // Count certificate types
                let mut ecc_count = 0;
                let mut rsa_count = 0;
                let mut other_count = 0;
                
                for cert in certificates.iter().take(100) { // Sample first 100 for performance
                    if let Ok(parsed_cert) = cert.parse() {
                        match parsed_cert.public_key().algorithm.algorithm.to_string().as_str() {
                            "1.2.840.10045.2.1" => ecc_count += 1,
                            "1.2.840.113549.1.1.1" => rsa_count += 1,
                            _ => other_count += 1,
                        }
                    }
                }
                
                println!("  Certificate types (first 100):");
                println!("    ECC: {}", ecc_count);
                println!("    RSA: {}", rsa_count);
                println!("    Other: {}", other_count);
            }
            Err(e) => {
                println!("✗ Failed to parse PEM: {}", e);
            }
        }
    } else {
        println!("⚠ PEM file not found, skipping PEM test");
    }
    
    println!("\n=== Demo Complete ===");
    Ok(())
}
