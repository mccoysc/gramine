const forge = require('node-forge');

function createMockQuoteV3(attestationKeyType = 2) {
    const coordSize = attestationKeyType === 3 ? 48 : 32;
    const buffer = Buffer.alloc(48 + 384 + 4 + coordSize * 4);
    
    buffer.writeUInt16LE(3, 0);
    buffer.writeUInt16LE(attestationKeyType, 2);
    buffer.writeUInt32LE(0, 4);
    
    const mrenclave = Buffer.from('1234567890abcdef'.repeat(4), 'hex');
    mrenclave.copy(buffer, 48 + 64);
    
    const mrsigner = Buffer.from('fedcba0987654321'.repeat(4), 'hex');
    mrsigner.copy(buffer, 48 + 96);
    
    buffer.writeUInt16LE(1, 48 + 256);
    buffer.writeUInt16LE(1, 48 + 258);
    
    const reportData = Buffer.alloc(64);
    reportData.fill(0xaa);
    reportData.copy(buffer, 48 + 320);
    
    const sigDataSize = coordSize * 4 + 384;
    buffer.writeUInt32LE(sigDataSize, 48 + 384);
    
    return buffer;
}

function createMockRaTlsCert(quoteBuffer, useStandardFormat = true) {
    const pki = forge.pki;
    const keys = pki.rsa.generateKeyPair(2048);
    const cert = pki.createCertificate();
    
    cert.publicKey = keys.publicKey;
    cert.serialNumber = '01';
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date();
    cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);
    
    const attrs = [{
        name: 'commonName',
        value: 'test.example.com'
    }];
    cert.setSubject(attrs);
    cert.setIssuer(attrs);
    
    if (useStandardFormat) {
        const cbor = require('cbor');
        const evidence = cbor.encode({
            'quote': quoteBuffer,
            'pubkey-hash': [[1, Buffer.alloc(32).fill(0xbb)]]
        });
        const tagged = cbor.encode(new cbor.Tagged(60000, evidence));
        
        cert.setExtensions([{
            id: '1.3.6.1.4.1.11129.2.1.26',
            critical: false,
            value: tagged.toString('binary')
        }]);
    } else {
        cert.setExtensions([{
            id: '1.2.840.113741.1.13.1',
            critical: false,
            value: quoteBuffer.toString('binary')
        }]);
    }
    
    cert.sign(keys.privateKey, forge.md.sha256.create());
    
    return pki.certificateToPem(cert);
}

function createMockCollateral() {
    return {
        tcbInfo: JSON.stringify({
            tcbInfo: {
                version: 3,
                issueDate: '2024-01-01T00:00:00Z',
                nextUpdate: '2025-01-01T00:00:00Z',
                fmspc: '00906EA10000',
                pceId: '0000',
                tcbType: 0,
                tcbEvaluationDataNumber: 12,
                tcbLevels: [{
                    tcb: {
                        sgxtcbcomponents: Array(16).fill({ svn: 0 }),
                        pcesvn: 0
                    },
                    tcbDate: '2024-01-01T00:00:00Z',
                    tcbStatus: 'UpToDate'
                }]
            },
            signature: Buffer.alloc(64).toString('hex')
        }),
        tcbSigningChain: createMockCertChain(),
        qeIdentity: JSON.stringify({
            enclaveIdentity: {
                version: 2,
                issueDate: '2024-01-01T00:00:00Z',
                nextUpdate: '2025-01-01T00:00:00Z',
                tcbEvaluationDataNumber: 12,
                miscselect: '00000000',
                miscselectMask: 'FFFFFFFF',
                attributes: '11000000000000000000000000000000',
                attributesMask: 'FBFFFFFFFFFFFFFF0000000000000000',
                mrsigner: 'fedcba0987654321'.repeat(4),
                isvprodid: 1,
                tcbLevels: [{
                    tcb: {
                        isvsvn: 1
                    },
                    tcbDate: '2024-01-01T00:00:00Z',
                    tcbStatus: 'UpToDate'
                }]
            },
            signature: Buffer.alloc(64).toString('hex')
        }),
        qeSigningChain: createMockCertChain(),
        pckCertChain: [createMockPckCert()],
        crl: null
    };
}

function createMockCertChain() {
    const pki = forge.pki;
    const rootKeys = pki.rsa.generateKeyPair(2048);
    const rootCert = pki.createCertificate();
    
    rootCert.publicKey = rootKeys.publicKey;
    rootCert.serialNumber = '01';
    rootCert.validity.notBefore = new Date();
    rootCert.validity.notAfter = new Date();
    rootCert.validity.notAfter.setFullYear(rootCert.validity.notBefore.getFullYear() + 10);
    
    const rootAttrs = [{
        name: 'commonName',
        value: 'Intel SGX Root CA'
    }, {
        name: 'organizationName',
        value: 'Intel Corporation'
    }];
    rootCert.setSubject(rootAttrs);
    rootCert.setIssuer(rootAttrs);
    rootCert.setExtensions([{
        name: 'basicConstraints',
        cA: true
    }]);
    
    rootCert.sign(rootKeys.privateKey, forge.md.sha256.create());
    
    return pki.certificateToPem(rootCert);
}

function createMockPckCert() {
    const pki = forge.pki;
    const keys = pki.rsa.generateKeyPair(2048);
    const cert = pki.createCertificate();
    
    cert.publicKey = keys.publicKey;
    cert.serialNumber = '01';
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date();
    cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);
    
    const attrs = [{
        name: 'commonName',
        value: 'Intel SGX PCK Certificate'
    }];
    cert.setSubject(attrs);
    cert.setIssuer(attrs);
    
    const fmspcAsn1 = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OCTETSTRING, false,
        Buffer.from('00906EA10000', 'hex').toString('binary'));
    const fmspcExt = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
        forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OID, false,
            forge.asn1.oidToDer('1.2.840.113741.1.13.1.4').getBytes()),
        fmspcAsn1
    ]);
    
    cert.setExtensions([{
        id: '1.2.840.113741.1.13.1',
        critical: false,
        value: forge.asn1.toDer(fmspcExt).getBytes()
    }]);
    
    cert.sign(keys.privateKey, forge.md.sha256.create());
    
    return pki.certificateToPem(cert);
}

module.exports = {
    createMockQuoteV3,
    createMockRaTlsCert,
    createMockCollateral,
    createMockCertChain,
    createMockPckCert
};
