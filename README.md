# rn-csca

Interact with ldif and pem CSCAs

## Installation

```sh
npm install rn-csca
```

## Usage

```js
import { parsePem, parsePemString, parseLdif, parseLdifString, findMasterCertificate } from 'rn-csca';

// Parse PEM file from string
const pemString = `-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJANy...
-----END CERTIFICATE-----`;

try {
  const certificates = parsePemString(pemString);
  console.log(`Found ${certificates.length} certificates`);

  // Each certificate is returned as raw DER data (ArrayBuffer)
  certificates.forEach((certDer, index) => {
    console.log(`Certificate ${index}: ${certDer.byteLength} bytes`);
  });
} catch (error) {
  console.error('Failed to parse PEM:', error);
}

// Parse PEM file from bytes
const pemBytes = new TextEncoder().encode(pemString);
const certificates = parsePem(pemBytes.buffer);

// Parse LDIF file from string
const ldifString = `dn: cn=certificate1
objectClass: certificationAuthority
cACertificate:: MIIBkTCB+wIJANy...`;

try {
  const ldifCertificates = parseLdifString(ldifString);
  console.log(`Found ${ldifCertificates.length} certificates from LDIF`);
} catch (error) {
  console.error('Failed to parse LDIF:', error);
}

// Parse LDIF file from bytes
const ldifBytes = new TextEncoder().encode(ldifString);
const ldifCertificates = parseLdif(ldifBytes.buffer);

// Find master certificate for a slave certificate
const slaveCertDer = certificates[0]; // First certificate as slave
const masterCertsDer = certificates.slice(1); // Rest as potential masters

try {
  const masterCert = findMasterCertificate(slaveCertDer, masterCertsDer);
  if (masterCert) {
    console.log(`Found master certificate: ${masterCert.byteLength} bytes`);
  } else {
    console.log('No master certificate found');
  }
} catch (error) {
  console.error('Error finding master certificate:', error);
}
```


## Contributing

See the [contributing guide](CONTRIBUTING.md) to learn how to contribute to the repository and the development workflow.

## License

MIT

---

Made with [create-react-native-library](https://github.com/callstack/react-native-builder-bob)
