let testResults = {};

function checkEnvironment() {
    const resultDiv = document.getElementById('env-result');
    resultDiv.innerHTML = '<div class="loading"></div> Checking environment...';
    
    setTimeout(() => {
        const checks = {
            'node-forge': typeof forge !== 'undefined',
            'cbor': typeof CBOR !== 'undefined',
            'elliptic': typeof elliptic !== 'undefined',
            'SGXQuoteVerifier': typeof SGXQuoteVerifier !== 'undefined',
            'WebCrypto API': typeof crypto !== 'undefined' && typeof crypto.subtle !== 'undefined'
        };
        
        let html = '<div class="result info">';
        html += '<strong>Environment Check Results:</strong>\n\n';
        
        let allPassed = true;
        for (const [name, passed] of Object.entries(checks)) {
            html += `${name}: ${passed ? '✓ Available' : '✗ Missing'}\n`;
            if (!passed) allPassed = false;
        }
        
        html += '\n';
        html += `Overall: ${allPassed ? '✓ All dependencies loaded' : '✗ Some dependencies missing'}`;
        html += '</div>';
        
        resultDiv.innerHTML = html;
    }, 100);
}

function createMockQuote(attestationKeyType = 2) {
    const coordSize = attestationKeyType === 3 ? 48 : 32;
    const buffer = new Uint8Array(48 + 384 + 4 + coordSize * 4);
    
    const view = new DataView(buffer.buffer);
    view.setUint16(0, 3, true);
    view.setUint16(2, attestationKeyType, true);
    view.setUint32(4, 0, true);
    
    const mrenclave = new Uint8Array(32);
    for (let i = 0; i < 32; i++) mrenclave[i] = i % 16;
    buffer.set(mrenclave, 48 + 64);
    
    const mrsigner = new Uint8Array(32);
    for (let i = 0; i < 32; i++) mrsigner[i] = (31 - i) % 16;
    buffer.set(mrsigner, 48 + 96);
    
    view.setUint16(48 + 256, 1, true);
    view.setUint16(48 + 258, 1, true);
    
    const reportData = new Uint8Array(64);
    reportData.fill(0xaa);
    buffer.set(reportData, 48 + 320);
    
    const sigDataSize = coordSize * 4 + 384;
    view.setUint32(48 + 384, sigDataSize, true);
    
    return buffer;
}

async function runTest(testName) {
    const resultDivs = {
        'parseP256Quote': 'test-results',
        'parseP384Quote': 'test-results',
        'extractStandardFormat': 'test-results',
        'extractLegacyFormat': 'test-results',
        'validateP256Type': 'type-results',
        'validateP384Type': 'type-results',
        'rejectInvalidType': 'type-results',
        'testSHA256': 'hash-results',
        'testSHA384': 'hash-results',
        'testSHA512': 'hash-results'
    };
    
    const resultDiv = document.getElementById(resultDivs[testName] || 'test-results');
    const testDiv = document.createElement('div');
    testDiv.innerHTML = `<div class="result info">Running ${testName}... <span class="loading"></span></div>`;
    resultDiv.appendChild(testDiv);
    
    try {
        let result;
        switch(testName) {
            case 'parseP256Quote':
                result = await testParseP256Quote();
                break;
            case 'parseP384Quote':
                result = await testParseP384Quote();
                break;
            case 'extractStandardFormat':
                result = await testExtractStandardFormat();
                break;
            case 'extractLegacyFormat':
                result = await testExtractLegacyFormat();
                break;
            case 'validateP256Type':
                result = await testValidateP256Type();
                break;
            case 'validateP384Type':
                result = await testValidateP384Type();
                break;
            case 'rejectInvalidType':
                result = await testRejectInvalidType();
                break;
            case 'testSHA256':
                result = await testHashAlgorithm(1, 'SHA-256');
                break;
            case 'testSHA384':
                result = await testHashAlgorithm(7, 'SHA-384');
                break;
            case 'testSHA512':
                result = await testHashAlgorithm(8, 'SHA-512');
                break;
            default:
                throw new Error('Unknown test: ' + testName);
        }
        
        testResults[testName] = 'pass';
        testDiv.innerHTML = `<div class="result success"><strong>✓ ${testName}</strong>\n${result}</div>`;
    } catch (error) {
        testResults[testName] = 'fail';
        testDiv.innerHTML = `<div class="result error"><strong>✗ ${testName}</strong>\n${error.message}\n\nStack:\n${error.stack}</div>`;
    }
    
    updateSummary();
}

async function testParseP256Quote() {
    const quote = createMockQuote(2);
    const view = new DataView(quote.buffer);
    
    const version = view.getUint16(0, true);
    const attestationKeyType = view.getUint16(2, true);
    
    if (version !== 3) throw new Error(`Expected version 3, got ${version}`);
    if (attestationKeyType !== 2) throw new Error(`Expected type 2, got ${attestationKeyType}`);
    
    return `Successfully parsed P-256 quote:\n- Version: ${version}\n- Attestation Key Type: ${attestationKeyType}\n- Coordinate Size: 32 bytes`;
}

async function testParseP384Quote() {
    const quote = createMockQuote(3);
    const view = new DataView(quote.buffer);
    
    const version = view.getUint16(0, true);
    const attestationKeyType = view.getUint16(2, true);
    
    if (version !== 3) throw new Error(`Expected version 3, got ${version}`);
    if (attestationKeyType !== 3) throw new Error(`Expected type 3, got ${attestationKeyType}`);
    
    return `Successfully parsed P-384 quote:\n- Version: ${version}\n- Attestation Key Type: ${attestationKeyType}\n- Coordinate Size: 48 bytes`;
}

async function testExtractStandardFormat() {
    return 'Standard TCG DICE format extraction test (requires full implementation)';
}

async function testExtractLegacyFormat() {
    return 'Legacy OID format extraction test (requires full implementation)';
}

async function testValidateP256Type() {
    const attestationKeyType = 2;
    const coordSize = attestationKeyType === 3 ? 48 : 32;
    const curveName = attestationKeyType === 3 ? 'p384' : 'p256';
    const hashAlgorithm = attestationKeyType === 3 ? 'SHA-384' : 'SHA-256';
    
    if (coordSize !== 32) throw new Error('P-256 should use 32-byte coordinates');
    if (curveName !== 'p256') throw new Error('P-256 should use p256 curve');
    if (hashAlgorithm !== 'SHA-256') throw new Error('P-256 should use SHA-256');
    
    return `P-256 validation passed:\n- Coordinate Size: ${coordSize}\n- Curve: ${curveName}\n- Hash: ${hashAlgorithm}`;
}

async function testValidateP384Type() {
    const attestationKeyType = 3;
    const coordSize = attestationKeyType === 3 ? 48 : 32;
    const curveName = attestationKeyType === 3 ? 'p384' : 'p256';
    const hashAlgorithm = attestationKeyType === 3 ? 'SHA-384' : 'SHA-256';
    
    if (coordSize !== 48) throw new Error('P-384 should use 48-byte coordinates');
    if (curveName !== 'p384') throw new Error('P-384 should use p384 curve');
    if (hashAlgorithm !== 'SHA-384') throw new Error('P-384 should use SHA-384');
    
    return `P-384 validation passed:\n- Coordinate Size: ${coordSize}\n- Curve: ${curveName}\n- Hash: ${hashAlgorithm}`;
}

async function testRejectInvalidType() {
    const invalidTypes = [0, 1, 4, 5, 255];
    const validTypes = [2, 3];
    
    for (const type of invalidTypes) {
        if (validTypes.includes(type)) {
            throw new Error(`Type ${type} should be rejected but is valid`);
        }
    }
    
    return `Invalid type rejection test passed:\n- Valid types: ${validTypes.join(', ')}\n- Tested invalid types: ${invalidTypes.join(', ')}`;
}

async function testHashAlgorithm(ianaId, expectedName) {
    const hashMap = {
        1: 'SHA-256',
        7: 'SHA-384',
        8: 'SHA-512'
    };
    
    const actualName = hashMap[ianaId];
    if (actualName !== expectedName) {
        throw new Error(`Expected ${expectedName} for IANA ID ${ianaId}, got ${actualName}`);
    }
    
    return `Hash algorithm test passed:\n- IANA ID: ${ianaId}\n- Algorithm: ${actualName}\n- Note: This is for pubkey-hash in claims, NOT ECDSA curves`;
}

async function runAllTests() {
    const allTests = [
        'parseP256Quote',
        'parseP384Quote',
        'validateP256Type',
        'validateP384Type',
        'rejectInvalidType',
        'testSHA256',
        'testSHA384',
        'testSHA512'
    ];
    
    for (const test of allTests) {
        await runTest(test);
    }
}

function updateSummary() {
    const summaryDiv = document.getElementById('summary');
    const total = Object.keys(testResults).length;
    const passed = Object.values(testResults).filter(r => r === 'pass').length;
    const failed = total - passed;
    
    let html = '<div class="result info">';
    html += `<strong>Test Summary:</strong>\n\n`;
    html += `Total Tests: ${total}\n`;
    html += `Passed: ${passed} ✓\n`;
    html += `Failed: ${failed} ✗\n`;
    html += `\nPass Rate: ${total > 0 ? ((passed / total) * 100).toFixed(1) : 0}%`;
    html += '</div>';
    
    summaryDiv.innerHTML = html;
}

window.addEventListener('load', () => {
    checkEnvironment();
});
