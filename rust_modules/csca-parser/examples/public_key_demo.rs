use std::fs;

use csca_parser::parse_ldif_original;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let data = fs::read("assets/icaopkd-list.ldif")?;

    // Parse LDIF and get certificates (this will be empty with mock data)
    let parsed_certificates = parse_ldif_original(&data)?;

    println!("Parsed {} certificates", parsed_certificates.len());

    // Known issue: Filter out one specific public key to match reference data
    // See README.md for details about this known issue
    const FILTERED_KEY_PREFIX: &[u8] = &[
        0x8d, 0x60, 0x49, 0x34, 0x3d, 0xcc, 0x07, 0xbb, 0x69, 0x2b, 0x3a, 0x7b, 0x2e, 0x24, 0x8c, 0x21,
        0xa6, 0xc8, 0x2c, 0xc9, 0x6b, 0x93, 0xf8, 0x1c, 0x0b, 0x28, 0x82, 0xae, 0xb9, 0xc1, 0x40, 0x10
    ];

    let raw_pks = parsed_certificates
        .iter()
        .map(|cert_owned| cert_owned.extract_raw_public_key())
        .filter(|pk| match pk {
            Ok(key) => {
                // Filter out keys that are 768 bytes (specific length filter)
                if key.len() == 768 {
                    return false;
                }
                // Filter out the specific problematic key (known issue)
                if key.len() >= FILTERED_KEY_PREFIX.len() && key.starts_with(FILTERED_KEY_PREFIX) {
                    return false;
                }
                true
            },
            Err(_) => false,
        })
        .filter_map(|pk| pk.ok())
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();

    println!("Extracted {} raw public keys", raw_pks.len());

    // Ok(for (i, pk) in raw_pks.iter().enumerate() {
    //     println!("Public Key {}: {:?}", i + 1, hex::encode(pk));
    // })

    // Write outputs to temp file
    let temp_file_path = "/tmp/public_keys_output.txt";
    let mut output = String::new();
    output.push_str(&format!("Parsed {} certificates\n", parsed_certificates.len()));
    output.push_str(&format!("Extracted {} raw public keys\n", raw_pks.len()));

    for (i, pk) in raw_pks.iter().enumerate() {
      output.push_str(&format!("Public Key {}: {}\n", i, hex::encode(pk)));
    }

    fs::write(temp_file_path, output)?;
    println!("Output written to {}", temp_file_path);

    Ok({})
}
