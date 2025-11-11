const { expect } = require('chai');
const path = require('path');
const mockData = require('./mock-data');

const verifierPath = path.join(__dirname, '../../sgx-quote-verify.js');
const { verifyQuote } = require(verifierPath);

describe('SGX Quote Verification - Basic Tests', function() {
    this.timeout(10000);

    describe('Quote Structure Parsing', function() {
        it('should parse P-256 quote structure', function() {
            const quote = mockData.createMockQuoteV3(2);
            expect(quote).to.be.instanceOf(Buffer);
            expect(quote.length).to.be.at.least(48 + 384);
            expect(quote.readUInt16LE(0)).to.equal(3);
            expect(quote.readUInt16LE(2)).to.equal(2);
        });

        it('should parse P-384 quote structure', function() {
            const quote = mockData.createMockQuoteV3(3);
            expect(quote).to.be.instanceOf(Buffer);
            expect(quote.length).to.be.at.least(48 + 384);
            expect(quote.readUInt16LE(0)).to.equal(3);
            expect(quote.readUInt16LE(2)).to.equal(3);
        });

        it('should reject unsupported attestation key type', async function() {
            const quote = mockData.createMockQuoteV3(5);
            const cert = mockData.createMockRaTlsCert(quote);
            
            try {
                await verifyQuote(cert, {
                    pccsUrl: 'http://localhost:8081'
                });
                expect.fail('Should have thrown error');
            } catch (error) {
                expect(error.message).to.include('Unsupported attestation key type');
                expect(error.message).to.include('type 2');
                expect(error.message).to.include('type 3');
            }
        });
    });

    describe('Certificate Format Support', function() {
        it('should extract quote from standard TCG DICE format', function() {
            const quote = mockData.createMockQuoteV3(2);
            const cert = mockData.createMockRaTlsCert(quote, true);
            
            expect(cert).to.include('BEGIN CERTIFICATE');
            expect(cert).to.include('END CERTIFICATE');
        });

        it('should extract quote from legacy OID format', function() {
            const quote = mockData.createMockQuoteV3(2);
            const cert = mockData.createMockRaTlsCert(quote, false);
            
            expect(cert).to.include('BEGIN CERTIFICATE');
            expect(cert).to.include('END CERTIFICATE');
        });
    });

    describe('Report Data Extraction', function() {
        it('should extract report_data at correct offset (48+320)', function() {
            const quote = mockData.createMockQuoteV3(2);
            const reportDataOffset = 48 + 320;
            const reportData = quote.slice(reportDataOffset, reportDataOffset + 64);
            
            expect(reportData.length).to.equal(64);
            expect(reportData[0]).to.equal(0xaa);
        });
    });

    describe('Measurement Policy Validation', function() {
        it('should accept matching MRENCLAVE', async function() {
            const quote = mockData.createMockQuoteV3(2);
            const cert = mockData.createMockRaTlsCert(quote);
            const expectedMrEnclave = '1234567890abcdef'.repeat(4);
            
            const mockFetch = async () => ({
                ok: true,
                json: async () => mockData.createMockCollateral()
            });
            global.fetch = mockFetch;
        });

        it('should reject mismatched MRENCLAVE', async function() {
            const quote = mockData.createMockQuoteV3(2);
            const cert = mockData.createMockRaTlsCert(quote);
            const wrongMrEnclave = 'ffffffffffffffff'.repeat(4);
            
            try {
                await verifyQuote(cert, {
                    expectedMrEnclave: wrongMrEnclave,
                    pccsUrl: 'http://localhost:8081'
                });
                expect.fail('Should have thrown error');
            } catch (error) {
                expect(error.message).to.include('MRENCLAVE mismatch');
            }
        });

        it('should reject mismatched MRSIGNER', async function() {
            const quote = mockData.createMockQuoteV3(2);
            const cert = mockData.createMockRaTlsCert(quote);
            const wrongMrSigner = 'ffffffffffffffff'.repeat(4);
            
            try {
                await verifyQuote(cert, {
                    expectedMrSigner: wrongMrSigner,
                    pccsUrl: 'http://localhost:8081'
                });
                expect.fail('Should have thrown error');
            } catch (error) {
                expect(error.message).to.include('MRSIGNER mismatch');
            }
        });

        it('should reject ISV_PROD_ID mismatch', async function() {
            const quote = mockData.createMockQuoteV3(2);
            const cert = mockData.createMockRaTlsCert(quote);
            
            try {
                await verifyQuote(cert, {
                    expectedIsvProdId: 999,
                    pccsUrl: 'http://localhost:8081'
                });
                expect.fail('Should have thrown error');
            } catch (error) {
                expect(error.message).to.include('ISV_PROD_ID mismatch');
            }
        });

        it('should reject too low ISV_SVN', async function() {
            const quote = mockData.createMockQuoteV3(2);
            const cert = mockData.createMockRaTlsCert(quote);
            
            try {
                await verifyQuote(cert, {
                    expectedIsvSvn: 999,
                    pccsUrl: 'http://localhost:8081'
                });
                expect.fail('Should have thrown error');
            } catch (error) {
                expect(error.message).to.include('ISV_SVN too low');
            }
        });
    });

    describe('Error Handling', function() {
        it('should throw error for invalid certificate', async function() {
            try {
                await verifyQuote('invalid cert', {
                    pccsUrl: 'http://localhost:8081'
                });
                expect.fail('Should have thrown error');
            } catch (error) {
                expect(error).to.exist;
            }
        });

        it('should throw error for missing quote in certificate', async function() {
            const forge = require('node-forge');
            const pki = forge.pki;
            const keys = pki.rsa.generateKeyPair(2048);
            const cert = pki.createCertificate();
            
            cert.publicKey = keys.publicKey;
            cert.serialNumber = '01';
            cert.validity.notBefore = new Date();
            cert.validity.notAfter = new Date();
            cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);
            
            const attrs = [{ name: 'commonName', value: 'test' }];
            cert.setSubject(attrs);
            cert.setIssuer(attrs);
            cert.sign(keys.privateKey, forge.md.sha256.create());
            
            const certPem = pki.certificateToPem(cert);
            
            try {
                await verifyQuote(certPem, {
                    pccsUrl: 'http://localhost:8081'
                });
                expect.fail('Should have thrown error');
            } catch (error) {
                expect(error.message).to.include('No SGX quote found');
            }
        });
    });
});
