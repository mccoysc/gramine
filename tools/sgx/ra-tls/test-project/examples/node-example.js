const path = require('path');
const { verifyQuote } = require(path.join(__dirname, '../../sgx-quote-verify.js'));

async function example1_basicVerification() {
    console.log('\n=== Example 1: Basic Quote Verification ===\n');
    
    const raTlsCertPem = `-----BEGIN CERTIFICATE-----
... your RA-TLS certificate here ...
-----END CERTIFICATE-----`;
    
    try {
        const result = await verifyQuote(raTlsCertPem, {
            pccsUrl: 'https://api.trustedservices.intel.com/sgx/certification/v4',
            allowDebugEnclave: false,
            allowOutdatedTcb: false
        });
        
        console.log('✓ Verification successful!');
        console.log('Measurements:');
        console.log(`  MRENCLAVE: ${result.measurements.mrenclave}`);
        console.log(`  MRSIGNER:  ${result.measurements.mrsigner}`);
        console.log(`  ISV_PROD_ID: ${result.measurements.isvProdId}`);
        console.log(`  ISV_SVN: ${result.measurements.isvSvn}`);
        console.log(`TCB Status: ${result.tcbStatus}`);
        console.log(`Quote Version: ${result.quoteVersion}`);
        console.log(`Attestation Key Type: ${result.attestationKeyType === 2 ? 'P-256' : 'P-384'}`);
        
    } catch (error) {
        console.error('✗ Verification failed:', error.message);
    }
}

async function example2_withMeasurementPolicy() {
    console.log('\n=== Example 2: Verification with Measurement Policy ===\n');
    
    const raTlsCertPem = `-----BEGIN CERTIFICATE-----
... your RA-TLS certificate here ...
-----END CERTIFICATE-----`;
    
    const expectedMrEnclave = '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef';
    const expectedMrSigner = 'fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321';
    
    try {
        const result = await verifyQuote(raTlsCertPem, {
            pccsUrl: 'https://api.trustedservices.intel.com/sgx/certification/v4',
            expectedMrEnclave: expectedMrEnclave,
            expectedMrSigner: expectedMrSigner,
            expectedIsvProdId: 1,
            expectedIsvSvn: 1,
            allowDebugEnclave: false,
            allowOutdatedTcb: false
        });
        
        console.log('✓ Verification successful with measurement policy!');
        console.log('The enclave matches the expected measurements.');
        
    } catch (error) {
        console.error('✗ Verification failed:', error.message);
        
        if (error.message.includes('MRENCLAVE mismatch')) {
            console.error('The enclave code does not match the expected measurement.');
        } else if (error.message.includes('MRSIGNER mismatch')) {
            console.error('The enclave signer does not match the expected identity.');
        }
    }
}

async function example3_customPccs() {
    console.log('\n=== Example 3: Using Custom PCCS ===\n');
    
    const raTlsCertPem = `-----BEGIN CERTIFICATE-----
... your RA-TLS certificate here ...
-----END CERTIFICATE-----`;
    
    try {
        const result = await verifyQuote(raTlsCertPem, {
            pccsUrl: 'https://your-pccs-server.example.com',
            apiKey: 'your-api-key-if-needed',
            allowDebugEnclave: false,
            allowOutdatedTcb: false
        });
        
        console.log('✓ Verification successful using custom PCCS!');
        
    } catch (error) {
        console.error('✗ Verification failed:', error.message);
    }
}

async function example4_withCaching() {
    console.log('\n=== Example 4: Verification with Caching ===\n');
    
    const cache = new Map();
    
    const cacheRead = async (key) => {
        const value = cache.get(key);
        if (value) {
            console.log(`  Cache hit: ${key}`);
        }
        return value || null;
    };
    
    const cacheWrite = async (key, data) => {
        console.log(`  Cache write: ${key}`);
        cache.set(key, data);
    };
    
    const raTlsCertPem = `-----BEGIN CERTIFICATE-----
... your RA-TLS certificate here ...
-----END CERTIFICATE-----`;
    
    try {
        console.log('First verification (will fetch from PCCS):');
        await verifyQuote(raTlsCertPem, {
            pccsUrl: 'https://api.trustedservices.intel.com/sgx/certification/v4',
            cacheRead,
            cacheWrite
        });
        
        console.log('\nSecond verification (will use cache):');
        await verifyQuote(raTlsCertPem, {
            pccsUrl: 'https://api.trustedservices.intel.com/sgx/certification/v4',
            cacheRead,
            cacheWrite
        });
        
        console.log(`\nCache contains ${cache.size} entries`);
        
    } catch (error) {
        console.error('✗ Verification failed:', error.message);
    }
}

async function example5_customRootCAs() {
    console.log('\n=== Example 5: Using Custom Root CAs ===\n');
    
    const customRootCA = `-----BEGIN CERTIFICATE-----
... your custom root CA certificate ...
-----END CERTIFICATE-----`;
    
    const raTlsCertPem = `-----BEGIN CERTIFICATE-----
... your RA-TLS certificate here ...
-----END CERTIFICATE-----`;
    
    try {
        const result = await verifyQuote(raTlsCertPem, {
            pccsUrl: 'https://api.trustedservices.intel.com/sgx/certification/v4',
            trustedRootCAs: [customRootCA],
            allowDebugEnclave: false
        });
        
        console.log('✓ Verification successful with custom root CA!');
        
    } catch (error) {
        console.error('✗ Verification failed:', error.message);
    }
}

async function example6_p384Quote() {
    console.log('\n=== Example 6: Verifying P-384 Quote ===\n');
    
    const raTlsCertPem = `-----BEGIN CERTIFICATE-----
... your RA-TLS certificate with P-384 quote ...
-----END CERTIFICATE-----`;
    
    try {
        const result = await verifyQuote(raTlsCertPem, {
            pccsUrl: 'https://api.trustedservices.intel.com/sgx/certification/v4'
        });
        
        if (result.attestationKeyType === 3) {
            console.log('✓ Successfully verified P-384 quote!');
            console.log('  Coordinate Size: 48 bytes');
            console.log('  Signature Size: 96 bytes');
            console.log('  Hash Algorithm: SHA-384');
        } else {
            console.log('✓ Verified, but this is a P-256 quote, not P-384');
        }
        
    } catch (error) {
        console.error('✗ Verification failed:', error.message);
    }
}

async function runAllExamples() {
    console.log('SGX DCAP Quote Verification - Node.js Examples');
    console.log('='.repeat(60));
    
    console.log('\nNote: These examples use placeholder certificates.');
    console.log('Replace with actual RA-TLS certificates for real verification.\n');
    
    console.log('Uncomment the examples you want to run:\n');
    
    console.log('Example 1: Basic verification without measurement policy');
    console.log('Example 2: Verification with MRENCLAVE/MRSIGNER checks');
    console.log('Example 3: Using a custom PCCS server');
    console.log('Example 4: Implementing caching for collateral');
    console.log('Example 5: Using custom root CA certificates');
    console.log('Example 6: Verifying P-384 quotes');
}

if (require.main === module) {
    runAllExamples().catch(console.error);
}

module.exports = {
    example1_basicVerification,
    example2_withMeasurementPolicy,
    example3_customPccs,
    example4_withCaching,
    example5_customRootCAs,
    example6_p384Quote
};
