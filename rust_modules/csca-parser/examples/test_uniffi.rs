use csca_parser::*;
use std::fs;

fn main() {
    println!("Testing UniFFI export functions:");
    
    // Test with real PEM file
    let pem_path = "assets/ICAO.pem";
    match fs::read_to_string(pem_path) {
        Ok(pem_content) => {
            println!("✓ Read PEM file: {} bytes", pem_content.len());
            
            // Test parse_pem_string
            match parse_pem_string(pem_content.clone()) {
                Ok(certificates) => {
                    println!("✓ parse_pem_string: Found {} certificates", certificates.len());
                    for (i, cert_bytes) in certificates.iter().enumerate() {
                        println!("  Certificate {}: {} bytes", i, cert_bytes.len());
                        // Show first few bytes as hex
                        if cert_bytes.len() > 8 {
                            println!("    First 8 bytes: {:02x?}", &cert_bytes[0..8]);
                        }
                    }
                }
                Err(e) => {
                    println!("✗ parse_pem_string failed: {}", e);
                }
            }

            // Test parse_pem
            match parse_pem(pem_content.as_bytes().to_vec()) {
                Ok(certificates) => {
                    println!("✓ parse_pem: Found {} certificates", certificates.len());
                    for (i, cert_bytes) in certificates.iter().enumerate() {
                        println!("  Certificate {}: {} bytes", i, cert_bytes.len());
                        // Show first few bytes as hex
                        if cert_bytes.len() > 8 {
                            println!("    First 8 bytes: {:02x?}", &cert_bytes[0..8]);
                        }
                    }
                }
                Err(e) => {
                    println!("✗ parse_pem failed: {}", e);
                }
            }
        }
        Err(e) => {
            println!("✗ Failed to read PEM file: {}", e);
        }
    }
    
    // Test with LDIF file
    let ldif_path = "assets/ldif.ldif";
    match fs::read_to_string(ldif_path) {
        Ok(ldif_content) => {
            println!("\n✓ Read LDIF file: {} bytes", ldif_content.len());
            
            // Test parse_ldif_string
            match parse_ldif_string(ldif_content.clone()) {
                Ok(certificates) => {
                    println!("✓ parse_ldif_string: Found {} certificates", certificates.len());
                    for (i, cert_bytes) in certificates.iter().enumerate() {
                        println!("  Certificate {}: {} bytes", i, cert_bytes.len());
                        // Show first few bytes as hex
                        if cert_bytes.len() > 8 {
                            println!("    First 8 bytes: {:02x?}", &cert_bytes[0..8]);
                        }
                    }
                }
                Err(e) => {
                    println!("✗ parse_ldif_string failed: {}", e);
                }
            }

            // Test parse_ldif
            match parse_ldif(ldif_content.as_bytes().to_vec()) {
                Ok(certificates) => {
                    println!("✓ parse_ldif: Found {} certificates", certificates.len());
                    for (i, cert_bytes) in certificates.iter().enumerate() {
                        println!("  Certificate {}: {} bytes", i, cert_bytes.len());
                        // Show first few bytes as hex
                        if cert_bytes.len() > 8 {
                            println!("    First 8 bytes: {:02x?}", &cert_bytes[0..8]);
                        }
                    }
                }
                Err(e) => {
                    println!("✗ parse_ldif failed: {}", e);
                }
            }
        }
        Err(e) => {
            println!("✗ Failed to read LDIF file: {}", e);
        }
    }
    
    println!("\nAll tests completed!");
}
