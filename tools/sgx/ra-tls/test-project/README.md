# SGX DCAP Quote Verification Test Project

This is a comprehensive test project for the JavaScript implementation of SGX DCAP quote verification. It includes tests for both Node.js and web browser environments.

## Features

- Node.js test suite using Mocha/Chai
- Web browser test interface
- Mock quote generation for testing
- Example usage code
- Support for both P-256 and P-384 attestation keys

## Installation

```bash
npm install
```

## Running Tests

### Node.js Tests

Run all tests:
```bash
npm test
```

Run tests in watch mode:
```bash
npm run test:watch
```

### Web Browser Tests

Start the test server:
```bash
npm run serve
```

Then open your browser to:
- http://localhost:3000 - Main test page
- http://localhost:3000/examples.html - Usage examples

## Project Structure

```
test-project/
├── package.json           # Dependencies and scripts
├── README.md             # This file
├── server.js             # Web server for browser tests
├── test/                 # Node.js test suite
│   ├── basic.test.js     # Basic functionality tests
│   ├── p384.test.js      # P-384 specific tests
│   └── mock-data.js      # Mock quote data for testing
├── web/                  # Web browser test files
│   ├── index.html        # Main test page
│   ├── examples.html     # Usage examples
│   └── test.js           # Browser test logic
└── examples/             # Example code
    ├── node-example.js   # Node.js usage example
    └── browser-example.html  # Browser usage example
```

## Test Coverage

The test suite covers:

1. **Quote Extraction**
   - Standard TCG DICE format (CBOR)
   - Legacy OID format
   - Both P-256 and P-384 quotes

2. **Quote Structure Parsing**
   - Version 3 and 4 quotes
   - Attestation key type validation
   - Report data extraction

3. **Signature Verification**
   - P-256 ECDSA signatures
   - P-384 ECDSA signatures
   - Hash algorithm selection (SHA-256, SHA-384)

4. **Measurement Policy**
   - MRENCLAVE validation
   - MRSIGNER validation
   - ISV_PROD_ID validation
   - ISV_SVN validation

5. **Error Handling**
   - Invalid quote formats
   - Unsupported attestation key types
   - Malformed signatures
   - Certificate chain errors

## Mock Data

Since real SGX quotes require actual hardware, this test project uses mock data that simulates the structure of real quotes. The mock data includes:

- Valid P-256 quotes
- Valid P-384 quotes
- Invalid quotes (for negative testing)
- Various TCB statuses

**Note:** These tests use mock data and do not validate against real SGX hardware. For production validation, you must test with actual SGX quotes from real hardware.

## Usage Examples

### Node.js Example

```javascript
const { verifyQuote } = require('../sgx-quote-verify.js');

async function verifyRaTlsCert(certPem) {
    try {
        const result = await verifyQuote(certPem, {
            pccsUrl: 'https://api.trustedservices.intel.com/sgx/certification/v4',
            expectedMrEnclave: '0123456789abcdef...',
            expectedMrSigner: 'fedcba9876543210...',
            allowDebugEnclave: false,
            allowOutdatedTcb: false
        });
        
        console.log('Verification successful:', result);
        return result;
    } catch (error) {
        console.error('Verification failed:', error.message);
        throw error;
    }
}
```

### Browser Example

```html
<!DOCTYPE html>
<html>
<head>
    <script src="https://cdn.jsdelivr.net/npm/node-forge@1.3.1/dist/forge.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/cbor-web@9.0.0/dist/cbor.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/elliptic@6.5.4/dist/elliptic.min.js"></script>
    <script src="sgx-quote-verify.js"></script>
</head>
<body>
    <script>
        async function verify() {
            const result = await SGXQuoteVerifier.verifyQuote(certPem, {
                expectedMrEnclave: '0123...',
                allowDebugEnclave: false
            });
            console.log('Verified:', result);
        }
    </script>
</body>
</html>
```

## Known Limitations

1. **No Real Hardware Testing**: Tests use mock data, not real SGX quotes
2. **Intel Root CA**: G3/G4 root CAs are placeholders (use `trustedRootCAs` option)
3. **PCCS Endpoint**: May need adjustment for your PCCS setup
4. **No Integration Tests**: No tests against actual Intel PCCS

## Contributing

When adding new tests:
1. Add test cases to the appropriate test file
2. Update mock data if needed
3. Ensure tests pass in both Node.js and browser environments
4. Update this README with new test coverage

## Security Notes

- This implementation is for testing and development purposes
- Always validate against real SGX hardware before production use
- Provide your own trusted root CAs via `options.trustedRootCAs`
- Never disable security checks (`allowDebugEnclave`, `allowOutdatedTcb`) in production
- Always specify expected measurements (`expectedMrEnclave`, `expectedMrSigner`)

## References

- [Intel SGX DCAP Documentation](https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/)
- [Gramine RA-TLS Documentation](https://gramine.readthedocs.io/en/stable/attestation.html)
- [TCG DICE Attestation Architecture](https://trustedcomputinggroup.org/work-groups/dice-architectures/)
