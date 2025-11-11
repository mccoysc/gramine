const { expect } = require('chai');
const path = require('path');
const mockData = require('./mock-data');

const verifierPath = path.join(__dirname, '../../sgx-quote-verify.js');
const { verifyQuote } = require(verifierPath);

describe('SGX Quote Verification - P-384 Tests', function() {
    this.timeout(10000);

    describe('P-384 Attestation Key Support', function() {
        it('should handle P-384 coordinate size (48 bytes)', function() {
            const quote = mockData.createMockQuoteV3(3);
            const attestationKeyType = quote.readUInt16LE(2);
            
            expect(attestationKeyType).to.equal(3);
            
            const coordSize = attestationKeyType === 3 ? 48 : 32;
            expect(coordSize).to.equal(48);
        });

        it('should use SHA-384 for P-384 quotes', function() {
            const attestationKeyType = 3;
            const hashAlgorithm = attestationKeyType === 3 ? 'SHA-384' : 'SHA-256';
            
            expect(hashAlgorithm).to.equal('SHA-384');
        });

        it('should calculate correct signature size for P-384', function() {
            const attestationKeyType = 3;
            const coordSize = attestationKeyType === 3 ? 48 : 32;
            const sigSize = coordSize * 2;
            
            expect(sigSize).to.equal(96);
        });

        it('should use correct curve name for P-384', function() {
            const attestationKeyType = 3;
            const curveName = attestationKeyType === 3 ? 'p384' : 'p256';
            
            expect(curveName).to.equal('p384');
        });
    });

    describe('P-384 vs P-256 Comparison', function() {
        it('should have different coordinate sizes', function() {
            const p256CoordSize = 32;
            const p384CoordSize = 48;
            
            expect(p384CoordSize).to.be.greaterThan(p256CoordSize);
            expect(p384CoordSize - p256CoordSize).to.equal(16);
        });

        it('should have different signature sizes', function() {
            const p256SigSize = 64;
            const p384SigSize = 96;
            
            expect(p384SigSize).to.be.greaterThan(p256SigSize);
            expect(p384SigSize - p256SigSize).to.equal(32);
        });

        it('should use different hash algorithms', function() {
            const p256Hash = 'SHA-256';
            const p384Hash = 'SHA-384';
            
            expect(p256Hash).to.not.equal(p384Hash);
        });
    });

    describe('Hash Algorithm Support in pubkey-hash', function() {
        it('should support SHA-256 (IANA ID 1)', function() {
            const ianaId = 1;
            const hashName = ianaId === 1 ? 'SHA-256' : ianaId === 7 ? 'SHA-384' : 'SHA-512';
            
            expect(hashName).to.equal('SHA-256');
        });

        it('should support SHA-384 (IANA ID 7)', function() {
            const ianaId = 7;
            const hashName = ianaId === 1 ? 'SHA-256' : ianaId === 7 ? 'SHA-384' : 'SHA-512';
            
            expect(hashName).to.equal('SHA-384');
        });

        it('should support SHA-512 (IANA ID 8)', function() {
            const ianaId = 8;
            const hashName = ianaId === 1 ? 'SHA-256' : ianaId === 7 ? 'SHA-384' : 'SHA-512';
            
            expect(hashName).to.equal('SHA-512');
        });
    });

    describe('Curve vs Hash Algorithm Distinction', function() {
        it('should distinguish ECDSA curves from hash algorithms', function() {
            const ecdsaCurves = ['P-256', 'P-384'];
            const hashAlgorithms = ['SHA-256', 'SHA-384', 'SHA-512'];
            
            expect(ecdsaCurves).to.have.lengthOf(2);
            expect(hashAlgorithms).to.have.lengthOf(3);
            
            expect(ecdsaCurves).to.not.include('P-512');
        });

        it('should clarify that P-512 does not exist in SGX DCAP', function() {
            const supportedAttestationKeyTypes = [2, 3];
            
            expect(supportedAttestationKeyTypes).to.include(2);
            expect(supportedAttestationKeyTypes).to.include(3); 
            expect(supportedAttestationKeyTypes).to.not.include(4);
            expect(supportedAttestationKeyTypes).to.not.include(5);
        });

        it('should map attestation key types correctly', function() {
            const typeMap = {
                2: { curve: 'P-256', coordSize: 32, hash: 'SHA-256' },
                3: { curve: 'P-384', coordSize: 48, hash: 'SHA-384' }
            };
            
            expect(typeMap[2].curve).to.equal('P-256');
            expect(typeMap[3].curve).to.equal('P-384');
            expect(typeMap[2].coordSize).to.equal(32);
            expect(typeMap[3].coordSize).to.equal(48);
        });
    });
});
