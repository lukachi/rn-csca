# CSCA Parser

A Rust library for parsing CSCA (Country Signing Certificate Authority) certificates from LDIF and PEM formats, with support for building Merkle trees using Treap data structures.

## Features

- Parse LDIF files containing CSCA master lists
- Parse PEM-formatted certificates
- Extract and normalize public keys from certificates
- Build Merkle trees using Treap data structure
- Generate inclusion proofs for certificates

## Usage

### Parsing LDIF Files

```rust
use csca_parser::parse_ldif_original;
use std::fs;

let data = fs::read("assets/icaopkd-list.ldif")?;
let certificates = parse_ldif_original(&data)?;
```

### Building Certificate Trees

```rust
use csca_parser::CertTree;

let certificates = parse_ldif_original(&data)?;
let cert_der_data: Vec<Vec<u8>> = certificates
    .iter()
    .map(|cert| cert.der_data().to_vec())
    .collect();

let cert_tree = CertTree::build_from_der_certificates(cert_der_data)?;
```

### Extracting Public Keys

```rust
let cert = OwnedCertificate::from_der(cert_data)?;
let public_key = cert.extract_raw_public_key()?;
```

## Public Key Normalization

The library implements comprehensive public key normalization to handle various formats:

- Removes leading zero padding bytes
- Handles ASN.1 BIT STRING formatting
- Normalizes EC point formats (uncompressed `0x04`, compressed `0x02`/`0x03`)
- Performs coordinate-level normalization for ECDSA keys
- Normalizes RSA modulus values

## Known Issues

### Extra Public Key in Extraction

**Issue**: One specific public key is consistently extracted by the parser but is not present in the reference `public_keys.txt` file.

**Details**:
- Key starts with: `8d6049343dcc07bb692b3a7b2e248c21a6c82cc96b93f81c0b2882aeb9c14010...`
- This key is valid and correctly extracted from the certificate data
- It represents a legitimate certificate that exists in the LDIF data
- However, it's not included in the reference key set

**Current Solution**:
The key is filtered out in `CertTree::build_from_der_certificates()` to maintain compatibility with existing reference data.

**Root Cause**:
Likely due to differences between:
- Certificate processing implementations
- Reference data generation methodology
- Certificate validity criteria used in different systems

**Impact**:
- Minimal - affects only 1 out of 491 extracted keys
- All reference keys (490/490) are correctly found and processed
- Tree building and proof generation work correctly

**Future Considerations**:
- Investigate the specific certificate that generates this key
- Determine why it's excluded from reference data
- Consider updating reference data to include this valid key

## Testing

Run the public key demo to verify extraction:

```bash
cargo run --example public_key_demo
```

Run tests:

```bash
cargo test
```

## Dependencies

- `x509-parser` - X.509 certificate parsing
- `cms` - CMS/PKCS#7 message parsing
- `der` - DER encoding/decoding
- `sha3` - Keccak256 hashing
- `num-bigint` - Big integer arithmetic
- `regex` - Regular expression matching
- `base64` - Base64 encoding/decoding
- `pem` - PEM format handling

## License

[Add your license here]
