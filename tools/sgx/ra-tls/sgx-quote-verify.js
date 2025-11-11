// sgx-quote-verifier.js  
// 支持Web和Node.js环境的SGX Quote验证库  

// 环境检测和依赖导入  
const isBrowser = typeof window !== 'undefined';

// 第三方库导入  
let forge, cbor, elliptic, nodeFetch;
if (isBrowser) {
    // 浏览器环境需要通过script标签引入  
    forge = window.forge;
    cbor = window.CBOR;
    elliptic = window.elliptic;
} else {
    // Node.js环境  
    forge = require('node-forge');
    cbor = require('cbor');
    elliptic = require('elliptic');
    try {
        if (typeof fetch === 'undefined') {
            nodeFetch = require('node-fetch');
        }
    } catch (e) {
    }
}

const fetchFunc = isBrowser ? window.fetch : (typeof fetch !== 'undefined' ? fetch : nodeFetch);


const ByteUtils = {
    /**
     * 将各种输入转换为字节数组（Node中为Buffer，浏览器中为Uint8Array）
     */
    toBytes(input) {
        if (isBrowser) {
            if (input instanceof Uint8Array) return input;
            if (input instanceof ArrayBuffer) return new Uint8Array(input);
            if (typeof input === 'string') {
                const bytes = new Uint8Array(input.length);
                for (let i = 0; i < input.length; i++) {
                    bytes[i] = input.charCodeAt(i);
                }
                return bytes;
            }
            if (Array.isArray(input)) return new Uint8Array(input);
            throw new Error('Cannot convert to bytes');
        } else {
            if (Buffer.isBuffer(input)) return input;
            if (input instanceof Uint8Array) return Buffer.from(input);
            if (input instanceof ArrayBuffer) return Buffer.from(input);
            if (typeof input === 'string') return Buffer.from(input, 'binary');
            if (Array.isArray(input)) return Buffer.from(input);
            throw new Error('Cannot convert to bytes');
        }
    },

    /**
     * 从Base64字符串创建字节数组
     */
    fromBase64(base64Str) {
        if (isBrowser) {
            const binaryStr = atob(base64Str);
            const bytes = new Uint8Array(binaryStr.length);
            for (let i = 0; i < binaryStr.length; i++) {
                bytes[i] = binaryStr.charCodeAt(i);
            }
            return bytes;
        } else {
            return Buffer.from(base64Str, 'base64');
        }
    },

    /**
     * 转换为Base64字符串
     */
    toBase64(bytes) {
        if (isBrowser) {
            const binaryStr = this.toBinaryString(bytes);
            return btoa(binaryStr);
        } else {
            return Buffer.from(bytes).toString('base64');
        }
    },

    /**
     * 转换为十六进制字符串
     */
    toHex(bytes) {
        return Array.from(bytes)
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    },

    /**
     * 从十六进制字符串创建字节数组
     */
    fromHex(hex) {
        const bytes = [];
        for (let i = 0; i < hex.length; i += 2) {
            bytes.push(parseInt(hex.slice(i, i + 2), 16));
        }
        return this.toBytes(bytes);
    },

    /**
     * 比较两个字节数组是否相等
     */
    equalBytes(a, b) {
        if (a.length !== b.length) return false;
        for (let i = 0; i < a.length; i++) {
            if (a[i] !== b[i]) return false;
        }
        return true;
    },

    /**
     * 切片操作
     */
    slice(bytes, start, end) {
        return bytes.slice(start, end);
    },

    /**
     * 创建DataView
     */
    dataView(bytes) {
        if (bytes.buffer) {
            return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
        }
        throw new Error('Cannot create DataView from input');
    },

    /**
     * 连接多个字节数组
     */
    concat(arrays) {
        const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
        if (isBrowser) {
            const result = new Uint8Array(totalLength);
            let offset = 0;
            for (const arr of arrays) {
                result.set(arr, offset);
                offset += arr.length;
            }
            return result;
        } else {
            return Buffer.concat(arrays);
        }
    },

    /**
     * 转换为二进制字符串（用于node-forge）
     */
    toBinaryString(bytes) {
        return Array.from(bytes)
            .map(b => String.fromCharCode(b))
            .join('');
    },

    /**
     * 从node-forge的二进制字符串转换
     */
    fromBinaryString(binaryStr) {
        const bytes = new Uint8Array(binaryStr.length);
        for (let i = 0; i < binaryStr.length; i++) {
            bytes[i] = binaryStr.charCodeAt(i);
        }
        return this.toBytes(bytes);
    }
};

// 常量定义 (基于sgx_attest.h)  
const SGX_QUOTE_MAX_SIZE = 8192;
const SGX_REPORT_BODY_SIZE = 384;

// OID定义 (基于ra_tls_common.h)  
const TCG_DICE_TAGGED_EVIDENCE_OID = '2.23.133.5.4.9';
const NON_STANDARD_INTEL_SGX_QUOTE_OID = '1.2.840.113741.1.13.1';
const LEGACY_QUOTE_OID_V1 = '0.6.9.42.840.113741.1337.6';
const LEGACY_QUOTE_OID = NON_STANDARD_INTEL_SGX_QUOTE_OID;
const TCG_DICE_TAGGED_EVIDENCE_CBOR_TAG = 60000;

// Quote验证结果枚举 (基于ra_tls_verify_dcap.c)  
const SGX_QL_QV_RESULT = {
    OK: 0x0000,
    CONFIG_NEEDED: 0x0000A001,
    OUT_OF_DATE: 0x0000A002,
    OUT_OF_DATE_CONFIG_NEEDED: 0x0000A003,
    INVALID_SIGNATURE: 0x0000A004,
    REVOKED: 0x0000A005,
    UNSPECIFIED: 0x0000A006,
    SW_HARDENING_NEEDED: 0x0000A007,
    CONFIG_AND_SW_HARDENING_NEEDED: 0x0000A008
};

const INTEL_SGX_ROOT_CA_CERTS = {
    G1: `-----BEGIN CERTIFICATE-----
MIICjzCCAjSgAwIBAgIUImUM1lqdNInzg7SVUr9QGzknBqwwCgYIKoZIzj0EAwIw
aDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv
cnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ
BgNVBAYTAlVTMB4XDTE4MDUyMTEwNDUxMFoXDTQ5MTIzMTIzNTk1OVowaDEaMBgG
A1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0
aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJBgNVBAYT
AlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC6nEwMDIYZOj/iPWsCzaEKi7
1OiOSLRFhWGjbnBVJfVnkY4u3IjkDYYL0MxO4mqsyYjlBalTVYxFP2sJBK5zlKOB
uzCBuDAfBgNVHSMEGDAWgBQiZQzWWp00ifODtJVSv1AbOScGrDBSBgNVHR8ESzBJ
MEegRaBDhkFodHRwczovL2NlcnRpZmljYXRlcy50cnVzdGVkc2VydmljZXMuaW50
ZWwuY29tL0ludGVsU0dYUm9vdENBLmRlcjAdBgNVHQ4EFgQUImUM1lqdNInzg7SV
Ur9QGzknBqwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwCgYI
KoZIzj0EAwIDSQAwRgIhAOW/5QkR+S9CiSDcNoowLuPRLsWGf/Yi7GSX94BgwTwg
AiEA4J0lrHoMs+Xo5o/sX6O9QWxHRAvZUGOdRQ7cvqRXaqI=
-----END CERTIFICATE-----`
};
INTEL_SGX_ROOT_CA_CERTS.G3=INTEL_SGX_ROOT_CA_CERTS.G1;
INTEL_SGX_ROOT_CA_CERTS.G4=INTEL_SGX_ROOT_CA_CERTS.G1;


/**  
 * 主验证函数  
 * @param {string|Buffer|Uint8Array} input - RA-TLS证书(PEM/DER)或base64编码的quote  
 * @param {Object} options - 配置选项  
 * @param {string} options.apiKey - Intel DCAP API密钥  
 * @param {string} options.pccsUrl - PCCS服务地址(默认Intel官方)  
 * @param {Function} options.cacheRead - 证书缓存读取回调 async (key) => data  
 * @param {Function} options.cacheWrite - 证书缓存写入回调 async (key, data) => void  
 * @param {boolean} options.allowOutdatedTcb - 允许过期TCB  
 * @param {boolean} options.allowDebugEnclave - 允许调试enclave  
 * @param {Array<string>} options.trustedRootCAs - 可信的根证书PEM数组（可选，默认使用所有Intel SGX Root CAs）
 * @param {string} options.expectedMrEnclave - 期望的MRENCLAVE值（十六进制字符串，可选）
 * @param {string} options.expectedMrSigner - 期望的MRSIGNER值（十六进制字符串，可选）
 * @param {number} options.expectedIsvProdId - 期望的ISV_PROD_ID值（可选）
 * @param {number} options.expectedIsvSvn - 期望的最小ISV_SVN值（可选）
 * @returns {Promise<Object>} 验证结果  
 */
async function verifyQuote(input, options = {}) {
    const {
        apiKey,
        pccsUrl = 'https://api.trustedservices.intel.com/sgx/certification/v4',
        cacheRead = async () => null,
        cacheWrite = async () => { },
        allowOutdatedTcb = false,
        allowDebugEnclave = false,
        allowHwConfigNeeded = false,
        allowSwHardeningNeeded = false,
        trustedRootCAs = null,
        expectedMrEnclave = null,
        expectedMrSigner = null,
        expectedIsvProdId = null,
        expectedIsvSvn = null
    } = options;

    try {
        // 步骤1: 提取Quote (基于extract_quote_and_verify_claims)  
        const { quote, quoteSize } = await extractQuote(input);

        // 步骤2: 解析Quote结构  
        const quoteData = parseQuoteStructure(quote);

        // 步骤3: 下载验证材料  
        const collateral = await fetchCollateral(
            quoteData,
            pccsUrl,
            apiKey,
            cacheRead,
            cacheWrite
        );

        await verifyCertChain(quoteData.certChain, collateral, trustedRootCAs);

        // 步骤5: 验证TCB  
        const tcbStatus = await verifyTCB(quoteData, collateral.tcbInfo);

        // 步骤6: 验证签名  
        await verifyQuoteSignature(quoteData, collateral);

        // 步骤7: 验证Enclave属性  
        verifyEnclaveAttributes(quoteData, allowDebugEnclave);

        // 步骤8: 检查TCB状态 (基于ra_tls_verify_dcap.c:182-229)  
        const verificationResult = evaluateTcbStatus(
            tcbStatus,
            allowOutdatedTcb,
            allowHwConfigNeeded,
            allowSwHardeningNeeded
        );

        verifyMeasurementPolicy(quoteData, {
            expectedMrEnclave,
            expectedMrSigner,
            expectedIsvProdId,
            expectedIsvSvn
        });

        return {
            verified: true,
            verificationResult,
            measurements: {
                mrenclave: ByteUtils.toHex(quoteData.mrenclave),
                mrsigner: ByteUtils.toHex(quoteData.mrsigner),
                isvProdId: quoteData.isvProdId,
                isvSvn: quoteData.isvSvn,
                attributes: quoteData.attributes,
                reportData: ByteUtils.toHex(quoteData.reportData)
            },
            tcbStatus: tcbStatusToString(tcbStatus),
            quoteVersion: quoteData.version,
            attestationKeyType: quoteData.attestationKeyType
        };
    } catch (error) {
        return {
            verified: false,
            error: error.message,
            stack: error.stack
        };
    }
}

/**  
 * 从证书或原始数据提取Quote  
 * 基于ra_tls_verify_common.c:534-549  
 */
async function extractQuote(input) {
    // 检测输入类型  
    if (typeof input === 'string') {
        // 可能是PEM证书或base64 quote  
        if (input.includes('-----BEGIN CERTIFICATE-----')) {
            return extractQuoteFromCert(input);
        } else {
            // 假设是base64编码的quote  
            const quote = ByteUtils.fromBase64(input);
            return { quote, quoteSize: quote.length };
        }
    } else if (input instanceof Uint8Array || (typeof Buffer !== 'undefined' && Buffer.isBuffer(input))) {
        // 尝试解析为证书  
        try {
            const inputBytes = ByteUtils.toBytes(input);
            const binaryStr = ByteUtils.toBinaryString(inputBytes);
            const cert = forge.pki.certificateFromAsn1(
                forge.asn1.fromDer(forge.util.createBuffer(binaryStr))
            );
            return extractQuoteFromParsedCert(cert);
        } catch {
            // 假设是原始quote数据  
            return { quote: ByteUtils.toBytes(input), quoteSize: input.length };
        }
    }

    throw new Error('Unsupported input format');
}

/**
 * 最小化DER TLV读取器 - 直接提取证书扩展（支持ECDSA证书）
 * node-forge的certificateFromPem对ECDSA证书支持有限，会抛出"OID is not RSA"错误
 * 这个函数使用最小化的DER解析来提取扩展，绕过完整的证书解析
 */
function getExtensionFromPemViaAsn1(pemCert, targetOid) {
    try {
        const pemMatch = pemCert.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/);
        if (!pemMatch) {
            throw new Error('No valid PEM certificate found');
        }
        
        const base64 = pemMatch[0]
            .replace(/-----BEGIN CERTIFICATE-----/, '')
            .replace(/-----END CERTIFICATE-----/, '')
            .replace(/\s/g, '');
        
        const derBuffer = ByteUtils.fromBase64(base64);
        
        const targetOidBytes = oidToBytes(targetOid);
        
        const extValue = extractExtensionByOid(derBuffer, targetOidBytes);
        return extValue;
    } catch (error) {
        throw new Error(`Failed to extract extension via DER parsing: ${error.message}`);
    }
}

/**
 * 将OID字符串转换为DER编码字节
 */
function oidToBytes(oid) {
    const parts = oid.split('.').map(Number);
    if (parts.length < 2) {
        throw new Error('Invalid OID format');
    }
    
    const bytes = [parts[0] * 40 + parts[1]];
    
    for (let i = 2; i < parts.length; i++) {
        let value = parts[i];
        if (value === 0) {
            bytes.push(0);
            continue;
        }
        
        const encoded = [];
        while (value > 0) {
            encoded.unshift((value & 0x7F) | (encoded.length > 0 ? 0x80 : 0));
            value >>= 7;
        }
        bytes.push(...encoded);
    }
    
    return new Uint8Array([0x06, bytes.length, ...bytes]);
}

/**
 * 从DER编码的证书中提取指定OID的扩展值
 */
function extractExtensionByOid(derBuffer, targetOidBytes) {
    let pos = 0;
    
    const readLength = () => {
        if (pos >= derBuffer.length) {
            throw new Error('Unexpected end of DER data');
        }
        
        const first = derBuffer[pos++];
        if ((first & 0x80) === 0) {
            return first;
        }
        
        const numOctets = first & 0x7F;
        if (numOctets === 0 || numOctets > 4) {
            throw new Error('Invalid DER length encoding');
        }
        
        let length = 0;
        for (let i = 0; i < numOctets; i++) {
            if (pos >= derBuffer.length) {
                throw new Error('Unexpected end of DER data');
            }
            length = (length << 8) | derBuffer[pos++];
        }
        return length;
    };
    
    const skipValue = (length) => {
        pos += length;
        if (pos > derBuffer.length) {
            throw new Error('DER value extends beyond buffer');
        }
    };
    
    const readBytes = (length) => {
        if (pos + length > derBuffer.length) {
            throw new Error('Not enough bytes to read');
        }
        const bytes = derBuffer.slice(pos, pos + length);
        pos += length;
        return bytes;
    };
    
    const matchesOid = (oidBytes) => {
        if (oidBytes.length !== targetOidBytes.length) {
            return false;
        }
        for (let i = 0; i < oidBytes.length; i++) {
            if (oidBytes[i] !== targetOidBytes[i]) {
                return false;
            }
        }
        return true;
    };
    
    if (derBuffer[pos] !== 0x30) {
        throw new Error('Certificate must start with SEQUENCE tag');
    }
    pos++;
    const certLength = readLength();
    
    if (derBuffer[pos] !== 0x30) {
        throw new Error('TBSCertificate must be a SEQUENCE');
    }
    pos++;
    const tbsLength = readLength();
    const tbsEnd = pos + tbsLength;
    
    while (pos < tbsEnd) {
        const tag = derBuffer[pos];
        
        if (tag === 0xA3) {
            pos++;
            const extContainerLength = readLength();
            
            if (derBuffer[pos] !== 0x30) {
                throw new Error('Extensions must be a SEQUENCE');
            }
            pos++;
            const extensionsLength = readLength();
            const extensionsEnd = pos + extensionsLength;
            
            while (pos < extensionsEnd) {
                if (derBuffer[pos] !== 0x30) {
                    break;
                }
                pos++;
                const extLength = readLength();
                const extEnd = pos + extLength;
                
                if (derBuffer[pos] !== 0x06) {
                    pos = extEnd;
                    continue;
                }
                const oidTag = derBuffer[pos++];
                const oidLength = readLength();
                const oidBytes = new Uint8Array([oidTag, oidLength, ...readBytes(oidLength)]);
                
                let critical = false;
                if (pos < extEnd && derBuffer[pos] === 0x01) {
                    pos++;
                    const boolLength = readLength();
                    critical = readBytes(boolLength)[0] !== 0;
                }
                
                if (pos >= extEnd) {
                    pos = extEnd;
                    continue;
                }
                
                if (derBuffer[pos] !== 0x04) {
                    pos = extEnd;
                    continue;
                }
                pos++;
                const valueLength = readLength();
                const valueBytes = readBytes(valueLength);
                
                if (matchesOid(oidBytes)) {
                    return ByteUtils.toBytes(valueBytes);
                }
                
                pos = extEnd;
            }
            
            return null;
        } else {
            pos++;
            const length = readLength();
            skipValue(length);
        }
    }
    
    return null;
}

/**  
 * 从X.509证书提取Quote  
 * 基于ra_tls_verify_common.c:534-549  
 * 支持RSA和ECDSA证书
 */
function extractQuoteFromCert(pemCert) {
    try {
        const cert = forge.pki.certificateFromPem(pemCert);
        return extractQuoteFromParsedCert(cert);
    } catch (error) {
        if (error.message && (error.message.includes('OID is not RSA') || error.message.includes('Too few bytes'))) {
            return extractQuoteFromParsedCertViaAsn1(pemCert);
        }
        throw error;
    }
}

/**
 * 使用ASN.1方式提取Quote（用于ECDSA证书）
 */
function extractQuoteFromParsedCertViaAsn1(pemCert) {
    let quoteData = getExtensionFromPemViaAsn1(pemCert, TCG_DICE_TAGGED_EVIDENCE_OID);
    if (quoteData) {
        return extractStandardQuoteFromExtension(quoteData);
    }
    
    quoteData = getExtensionFromPemViaAsn1(pemCert, LEGACY_QUOTE_OID);
    if (quoteData) {
        return extractLegacyQuoteFromExtension(quoteData);
    }
    
    quoteData = getExtensionFromPemViaAsn1(pemCert, LEGACY_QUOTE_OID_V1);
    if (quoteData) {
        return extractLegacyQuoteFromExtension(quoteData);
    }
    
    throw new Error('No SGX quote found in certificate');
}

/**
 * 从扩展数据中提取标准TCG DICE格式的Quote
 * 用于ASN.1方式提取的扩展数据
 */
function extractStandardQuoteFromExtension(extValue) {
    try {
        const cborData = cbor.decode(extValue);

        if (!cborData || cborData.tag !== TCG_DICE_TAGGED_EVIDENCE_CBOR_TAG) {
            throw new Error('Invalid CBOR tag for TCG DICE evidence');
        }

        const evidence = cborData.value;
        if (!Array.isArray(evidence) || evidence.length !== 2) {
            throw new Error('Invalid evidence structure');
        }

        const quote = evidence[0];
        const claimsBstr = evidence[1];

        if (!claimsBstr || !(claimsBstr instanceof Uint8Array || Buffer.isBuffer(claimsBstr))) {
            throw new Error('Invalid claims structure');
        }

        const claimsBytes = ByteUtils.toBytes(claimsBstr);
        const claimsBinaryStr = ByteUtils.toBinaryString(claimsBytes);
        
        const claimsHash = forge.md.sha256.create();
        claimsHash.update(claimsBinaryStr, 'raw');
        const expectedHash = claimsHash.digest().bytes();

        const quoteBuffer = ByteUtils.toBytes(quote);
        const reportDataOffset = 48 + 320;
        const actualHash = ByteUtils.slice(quoteBuffer, reportDataOffset, reportDataOffset + 32);

        const expectedHashBytes = ByteUtils.fromBinaryString(expectedHash);
        if (!ByteUtils.equalBytes(expectedHashBytes, actualHash)) {
            throw new Error('Claims hash does not match quote report_data');
        }

        return {
            quote: quoteBuffer,
            quoteSize: quoteBuffer.length
        };
    } catch (error) {
        throw new Error(`Failed to extract standard quote from extension: ${error.message}`);
    }
}

/**
 * 从扩展数据中提取遗留格式的Quote
 * 用于ASN.1方式提取的扩展数据
 * 传统格式包含：原始quote数据 + 嵌入的PCK证书链（PEM格式）
 */
function extractLegacyQuoteFromExtension(extValue) {
    const extBytes = ByteUtils.toBytes(extValue);
    
    const extString = ByteUtils.toBinaryString(extBytes);
    const pemStart = extString.indexOf('-----BEGIN CERTIFICATE-----');
    
    let quote;
    if (pemStart > 0) {
        quote = ByteUtils.slice(extBytes, 0, pemStart);
    } else {
        quote = extBytes;
    }
    
    const reportDataOffset = 48 + 320;
    const reportData = ByteUtils.slice(quote, reportDataOffset, reportDataOffset + 64);
    
    return {
        quote: quote,
        quoteSize: quote.length
    };
}

/**  
 * 从解析后的证书提取Quote  
 * 实现标准OID和遗留OID两种方式  
 */
function extractQuoteFromParsedCert(cert) {
    // 首先尝试标准TCG DICE OID (基于extract_standard_quote_and_verify_claims)  
    let quote = extractStandardQuote(cert);
    if (quote) {
        return quote;
    }

    // 回退到遗留OID (基于extract_legacy_quote_and_verify_pubkey)  
    quote = extractLegacyQuote(cert);
    if (quote) {
        return quote;
    }

    throw new Error('No SGX quote found in certificate');
}

/**  
 * 提取标准TCG DICE格式的Quote  
 * 基于ra_tls_verify_common.c:326-502  
 */
function extractStandardQuote(cert) {
    const ext = findExtension(cert, TCG_DICE_TAGGED_EVIDENCE_OID);
    if (!ext) return null;

    try {
        let extValue = ext.value;
        if (typeof extValue === 'string') {
            extValue = ByteUtils.fromBinaryString(extValue);
        } else {
            extValue = ByteUtils.toBytes(extValue);
        }

        const cborData = cbor.decode(extValue);

        if (!cborData || cborData.tag !== TCG_DICE_TAGGED_EVIDENCE_CBOR_TAG) {
            throw new Error('Invalid CBOR tag for TCG DICE evidence');
        }

        const evidence = cborData.value;
        if (!Array.isArray(evidence) || evidence.length !== 2) {
            throw new Error('Invalid evidence structure');
        }

        const quote = evidence[0];
        const claimsBstr = evidence[1];

        if (!claimsBstr || !(claimsBstr instanceof Uint8Array || Buffer.isBuffer(claimsBstr))) {
            throw new Error('Invalid claims structure');
        }

        const claimsBytes = ByteUtils.toBytes(claimsBstr);
        const claimsBinaryStr = ByteUtils.toBinaryString(claimsBytes);
        
        const claimsHash = forge.md.sha256.create();
        claimsHash.update(claimsBinaryStr, 'raw');
        const expectedHash = claimsHash.digest().bytes();

        const quoteBuffer = ByteUtils.toBytes(quote);
        const reportDataOffset = 48 + 320;  // Report body starts at 48, report_data is at offset 320 within report body
        const actualHash = ByteUtils.slice(quoteBuffer, reportDataOffset, reportDataOffset + 32);

        const expectedHashBytes = ByteUtils.fromBinaryString(expectedHash);
        if (!ByteUtils.equalBytes(expectedHashBytes, actualHash)) {
            throw new Error('Claims hash does not match quote report_data');
        }

        const claimsMap = cbor.decode(claimsBytes);

        if (claimsMap['pubkey-hash']) {
            const pubkeyHashValue = claimsMap['pubkey-hash'];
            let hashEntry;
            
            if (pubkeyHashValue instanceof Uint8Array || Buffer.isBuffer(pubkeyHashValue)) {
                hashEntry = cbor.decode(ByteUtils.toBytes(pubkeyHashValue));
            } else if (Array.isArray(pubkeyHashValue)) {
                hashEntry = pubkeyHashValue;
            } else {
                throw new Error('Invalid pubkey-hash format');
            }

            // hashEntry is [hashAlg, hashValue]  
            if (!Array.isArray(hashEntry) || hashEntry.length !== 2) {
                throw new Error('Invalid pubkey-hash array format');
            }

            const hashAlg = hashEntry[0]; // 1=SHA-256, 7=SHA-384, 8=SHA-512
            const hashValue = hashEntry[1];

            if (hashAlg !== 1 && hashAlg !== 7 && hashAlg !== 8) {
                throw new Error(`Unsupported hash algorithm in pubkey-hash: ${hashAlg}`);
            }

            const certPubkey = cert.publicKey;
            const pubkeyAsn1 = forge.pki.publicKeyToAsn1(certPubkey);
            const pubkeyDer = forge.asn1.toDer(pubkeyAsn1).getBytes();

            let computedHash;
            if (hashAlg === 1) { // SHA-256
                const hash = forge.md.sha256.create();
                hash.update(pubkeyDer, 'raw');
                computedHash = ByteUtils.fromBinaryString(hash.digest().getBytes());
            } else if (hashAlg === 7) { // SHA-384
                const hash = forge.md.sha384.create();
                hash.update(pubkeyDer, 'raw');
                computedHash = ByteUtils.fromBinaryString(hash.digest().getBytes());
            } else if (hashAlg === 8) { // SHA-512
                const hash = forge.md.sha512.create();
                hash.update(pubkeyDer, 'raw');
                computedHash = ByteUtils.fromBinaryString(hash.digest().getBytes());
            }

            const hashValueBytes = ByteUtils.toBytes(hashValue);
            if (!ByteUtils.equalBytes(computedHash, hashValueBytes)) {
                throw new Error('Public key hash mismatch');
            }
        }

        return {
            quote: quoteBuffer,
            quoteSize: quoteBuffer.length
        };
    } catch (error) {
        throw new Error(`Failed to extract standard quote: ${error.message}`);
    }
}

/**  
 * 提取遗留格式的Quote  
 * 基于ra_tls_verify_common.c:504-532  
 */
function extractLegacyQuote(cert) {
    const ext = findExtension(cert, NON_STANDARD_INTEL_SGX_QUOTE_OID);
    if (!ext) return null;

    let extValue = ext.value;
    if (typeof extValue === 'string') {
        extValue = ByteUtils.fromBinaryString(extValue);
    }
    const quote = ByteUtils.toBytes(extValue);

    // 验证公钥哈希匹配report_data  
    const certPubkey = cert.publicKey;
    const pubkeyAsn1 = forge.pki.publicKeyToAsn1(certPubkey);
    const pubkeyDer = forge.asn1.toDer(pubkeyAsn1).getBytes();

    const hash = forge.md.sha256.create();
    hash.update(pubkeyDer, 'raw');
    const pubkeyHash = ByteUtils.fromBinaryString(hash.digest().getBytes());

    const reportDataOffset = 48 + 320;  // Report body starts at 48, report_data is at offset 320 within report body
    const reportData = ByteUtils.slice(quote, reportDataOffset, reportDataOffset + 64);

    if (!ByteUtils.equalBytes(pubkeyHash, ByteUtils.slice(reportData, 0, 32))) {
        throw new Error('Public key hash does not match report_data');
    }

    return {
        quote,
        quoteSize: quote.length
    };
}

/**  
 * 查找证书扩展  
 */
function findExtension(cert, oid) {
    if (!cert.extensions) return null;

    for (const ext of cert.extensions) {
        if (ext.id === oid) {
            return ext;
        }
    }
    return null;
}

/**  
 * 解析Quote二进制结构  
 * 基于sgx_attest.h中的sgx_quote3_t定义（DCAP格式）
 */
function parseQuoteStructure(quoteBuffer) {
    const view = ByteUtils.dataView(quoteBuffer);
    let offset = 0;

    const version = view.getUint16(offset, true); offset += 2;
    const attestationKeyType = view.getUint16(offset, true); offset += 2; // 2 = ECDSA-P256, 3 = ECDSA-P384
    const teeType = view.getUint32(offset, true); offset += 4; // 0x00000000 = SGX
    const qeSvn = view.getUint16(offset, true); offset += 2;
    const pceSvn = view.getUint16(offset, true); offset += 2;
    const qeVendorId = ByteUtils.slice(quoteBuffer, offset, offset + 16); offset += 16; // UUID
    const userData = ByteUtils.slice(quoteBuffer, offset, offset + 20); offset += 20; // User data

    // Report Body (384 bytes)  
    const reportBodyStart = offset;
    const cpuSvn = ByteUtils.slice(quoteBuffer, offset, offset + 16); offset += 16;
    const miscSelect = view.getUint32(offset, true); offset += 4;
    offset += 28; // reserved  
    const attributes = ByteUtils.slice(quoteBuffer, offset, offset + 16); offset += 16;
    const mrenclave = ByteUtils.slice(quoteBuffer, offset, offset + 32); offset += 32;
    offset += 32; // reserved  
    const mrsigner = ByteUtils.slice(quoteBuffer, offset, offset + 32); offset += 32;
    offset += 96; // reserved  
    const isvProdId = view.getUint16(offset, true); offset += 2;
    const isvSvn = view.getUint16(offset, true); offset += 2;
    offset += 60; // reserved  
    const reportData = ByteUtils.slice(quoteBuffer, offset, offset + 64); offset += 64;

    const signatureSize = view.getUint32(offset, true); offset += 4;
    const signatureStart = offset;
    const signature = ByteUtils.slice(quoteBuffer, offset, offset + signatureSize);
    offset += signatureSize;

    let certChain = [];
    if (version === 3 || version === 4) {
        certChain = parseEcdsaSignatureData(signature);
    }

    return {
        version,
        attestationKeyType,
        teeType,
        qeSvn,
        pceSvn,
        qeVendorId,
        userData,
        cpuSvn,
        miscSelect,
        attributes,
        mrenclave,
        mrsigner,
        isvProdId,
        isvSvn,
        reportData,
        signature,
        certChain,
        rawQuote: quoteBuffer
    };
}

/**
 * 解析ECDSA签名数据结构
 * 基于sgx_quote_3.h中的sgx_ql_ecdsa_sig_data_t
 */
function parseEcdsaSignatureData(sigData) {
    let offset = 0;
    const view = ByteUtils.dataView(sigData);

    const ecdsaSignature = ByteUtils.slice(sigData, offset, offset + 64); offset += 64;

    const attestationPubKey = ByteUtils.slice(sigData, offset, offset + 64); offset += 64;

    const qeReport = ByteUtils.slice(sigData, offset, offset + 384); offset += 384;

    const qeReportSignature = ByteUtils.slice(sigData, offset, offset + 64); offset += 64;

    const certChain = [];
    if (offset + 2 <= sigData.length) {
        const authDataSize = view.getUint16(offset, true); offset += 2;
        
        if (authDataSize > 0 && offset + authDataSize <= sigData.length) {
            const authData = ByteUtils.slice(sigData, offset, offset + authDataSize);
            const parsedCerts = parseCertificationData(authData);
            certChain.push(...parsedCerts);
        }
    }

    return certChain;
}

/**  
 * 解析认证数据（Certification Data）
 * 基于sgx_quote_3.h中的sgx_ql_certification_data_t
 */
function parseCertificationData(authData) {
    const certChain = [];
    let offset = 0;
    const view = ByteUtils.dataView(authData);

    if (authData.length < 6) return certChain;

    const certDataType = view.getUint16(offset, true); offset += 2;
    const certDataSize = view.getUint32(offset, true); offset += 4;

    if (offset + certDataSize > authData.length) return certChain;

    const certData = ByteUtils.slice(authData, offset, offset + certDataSize);

    if (certDataType === 5) {
        const certView = ByteUtils.dataView(certData);
        let certOffset = 0;

        if (certData.length < 4) return certChain;
        
        const certCount = certView.getUint32(certOffset, true);
        certOffset += 4;

        for (let i = 0; i < certCount && certOffset < certData.length; i++) {
            if (certOffset + 4 > certData.length) break;

            const certSize = certView.getUint32(certOffset, true);
            certOffset += 4;

            if (certOffset + certSize > certData.length) break;

            const cert = ByteUtils.slice(certData, certOffset, certOffset + certSize);
            certChain.push(cert);
            certOffset += certSize;
        }
    }

    return certChain;
}

/**  
 * 下载验证所需的材料  
 * 基于DCAP协议从PCCS获取证书和TCB信息  
 */
async function fetchCollateral(quoteData, pccsUrl, apiKey, cacheRead, cacheWrite) {
    const collateral = {
        pckCertChain: null,
        tcbInfo: null,
        tcbInfoRaw: null,  // 保存原始文本用于签名验证
        qeIdentity: null,
        qeIdentityRaw: null,  // 保存原始文本用于签名验证
        rootCaCrl: null,
        pckCrls: {
            processor: null,
            platform: null
        }
    };

    // 从quote中提取FMSPC和其他标识符  
    const fmspc = extractFmspc(quoteData);
    const qeId = extractQeId(quoteData);

    // 1. 获取PCK证书链 (如果quote中没有嵌入)  
    if (!quoteData.certChain || quoteData.certChain.length === 0) {
        const pckCertKey = `pck_cert_${fmspc}`;
        let pckCertChain = await cacheRead(pckCertKey);

        if (!pckCertChain) {
            const url = `${pccsUrl}/pckcert?fmspc=${fmspc}`;
            const headers = apiKey ? { 'Ocp-Apim-Subscription-Key': apiKey } : {};

            const response = await fetchFunc(url, { headers });
            if (!response.ok) {
                throw new Error(`Failed to fetch PCK cert: ${response.status}`);
            }

            pckCertChain = await response.text();
            await cacheWrite(pckCertKey, pckCertChain);
        }

        collateral.pckCertChain = parsePemCertChain(pckCertChain);
    } else {
        collateral.pckCertChain = quoteData.certChain.map(cert => {
            const binaryStr = ByteUtils.toBinaryString(cert);
            return forge.pki.certificateFromAsn1(forge.asn1.fromDer(forge.util.createBuffer(binaryStr)));
        });
    }

    const tcbInfoKey = `tcb_info_${fmspc}`;
    let tcbInfoText = await cacheRead(tcbInfoKey);

    if (!tcbInfoText) {
        const url = `${pccsUrl}/tcb?fmspc=${fmspc}`;
        const headers = apiKey ? { 'Ocp-Apim-Subscription-Key': apiKey } : {};

        const response = await fetchFunc(url, { headers });
        if (!response.ok) {
            throw new Error(`Failed to fetch TCB info: ${response.status}`);
        }

        tcbInfoText = await response.text();
        await cacheWrite(tcbInfoKey, tcbInfoText);
    }

    collateral.tcbInfoRaw = tcbInfoText;
    collateral.tcbInfo = JSON.parse(tcbInfoText);
    
    await verifyIntelSignedJson(collateral.tcbInfo, tcbInfoText, 'tcbInfo', 'tcbInfoIssuerChain');

    const qeIdentityKey = `qe_identity`;
    let qeIdentityText = await cacheRead(qeIdentityKey);

    if (!qeIdentityText) {
        const url = `${pccsUrl}/qe/identity`;
        const headers = apiKey ? { 'Ocp-Apim-Subscription-Key': apiKey } : {};

        const response = await fetchFunc(url, { headers });
        if (!response.ok) {
            throw new Error(`Failed to fetch QE identity: ${response.status}`);
        }

        qeIdentityText = await response.text();
        await cacheWrite(qeIdentityKey, qeIdentityText);
    }

    collateral.qeIdentityRaw = qeIdentityText;
    collateral.qeIdentity = JSON.parse(qeIdentityText);
    
    await verifyIntelSignedJson(collateral.qeIdentity, qeIdentityText, 'enclaveIdentity', 'enclaveIdentityIssuerChain');

    // 4. 获取Root CA CRL  
    const crlKey = 'root_ca_crl';
    let rootCaCrl = await cacheRead(crlKey);

    if (!rootCaCrl) {
        const url = `${pccsUrl}/rootcacrl`;
        const headers = apiKey ? { 'Ocp-Apim-Subscription-Key': apiKey } : {};

        const response = await fetchFunc(url, { headers });
        if (!response.ok) {
            throw new Error(`Failed to fetch root CA CRL: ${response.status}`);
        }

        rootCaCrl = await response.text();
        await cacheWrite(crlKey, rootCaCrl);
    }

    collateral.rootCaCrl = rootCaCrl;

    if (collateral.pckCertChain && collateral.pckCertChain.length > 0) {
        const pckCert = collateral.pckCertChain[0];
        const issuerCN = getIssuerCN(pckCert);
        
        const processorCrlKey = `pck_crl_processor_${fmspc}`;
        let processorCrl = await cacheRead(processorCrlKey);
        
        if (!processorCrl) {
            try {
                const url = `${pccsUrl}/pckcrl?ca=processor`;
                const headers = apiKey ? { 'Ocp-Apim-Subscription-Key': apiKey } : {};
                const response = await fetchFunc(url, { headers });
                if (response.ok) {
                    processorCrl = await response.text();
                    await cacheWrite(processorCrlKey, processorCrl);
                }
            } catch (e) {
                console.warn('Failed to fetch processor CRL:', e.message);
            }
        }
        collateral.pckCrls.processor = processorCrl;

        const platformCrlKey = `pck_crl_platform_${fmspc}`;
        let platformCrl = await cacheRead(platformCrlKey);
        
        if (!platformCrl) {
            try {
                const url = `${pccsUrl}/pckcrl?ca=platform`;
                const headers = apiKey ? { 'Ocp-Apim-Subscription-Key': apiKey } : {};
                const response = await fetchFunc(url, { headers });
                if (response.ok) {
                    platformCrl = await response.text();
                    await cacheWrite(platformCrlKey, platformCrl);
                }
            } catch (e) {
                console.warn('Failed to fetch platform CRL:', e.message);
            }
        }
        collateral.pckCrls.platform = platformCrl;
    }

    return collateral;
}

/**
 * 验证Intel签名的JSON文档（TCB Info或QE Identity）
 * 完整实现Intel签名验证
 */
async function verifyIntelSignedJson(jsonObj, rawText, dataFieldName, issuerChainFieldName) {
    if (!jsonObj.signature) {
        throw new Error(`${dataFieldName} does not contain signature`);
    }

    if (!jsonObj[issuerChainFieldName]) {
        throw new Error(`${dataFieldName} does not contain ${issuerChainFieldName}`);
    }

    const dataStartMarker = `"${dataFieldName}":`;
    const dataStartIndex = rawText.indexOf(dataStartMarker);
    
    if (dataStartIndex === -1) {
        throw new Error(`Cannot find ${dataFieldName} in raw text`);
    }

    let braceCount = 0;
    let dataStart = -1;
    let dataEnd = -1;
    
    for (let i = dataStartIndex + dataStartMarker.length; i < rawText.length; i++) {
        if (rawText[i] === '{') {
            if (dataStart === -1) dataStart = i;
            braceCount++;
        } else if (rawText[i] === '}') {
            braceCount--;
            if (braceCount === 0 && dataStart !== -1) {
                dataEnd = i + 1;
                break;
            }
        }
    }

    if (dataStart === -1 || dataEnd === -1) {
        throw new Error(`Cannot extract ${dataFieldName} boundaries`);
    }

    const signedDataBytes = ByteUtils.toBytes(rawText.substring(dataStart, dataEnd));

    const issuerChainPem = jsonObj[issuerChainFieldName];
    const issuerCerts = parseCommaSeparatedPemChain(issuerChainPem);
    
    if (issuerCerts.length === 0) {
        throw new Error(`No certificates found in ${issuerChainFieldName}`);
    }

    await verifyIntelIssuerChain(issuerCerts);

    const signatureBase64 = jsonObj.signature;
    const signatureBytes = ByteUtils.fromBase64(signatureBase64);
    
    let r, s;
    if (signatureBytes[0] === 0x30) {
        const derSig = parseDerEcdsaSignature(signatureBytes);
        r = derSig.r;
        s = derSig.s;
    } else if (signatureBytes.length === 64 || signatureBytes.length === 96) {
        const coordSize = signatureBytes.length / 2;
        r = ByteUtils.toHex(ByteUtils.slice(signatureBytes, 0, coordSize));
        s = ByteUtils.toHex(ByteUtils.slice(signatureBytes, coordSize, coordSize * 2));
    } else {
        throw new Error('Unknown signature format');
    }

    const leafCert = issuerCerts[0];
    const leafPubKey = leafCert.publicKey;
    
    let curveName = 'p256';
    let hashAlgorithm = 'SHA-256';
    if (leafPubKey.curve) {
        curveName = leafPubKey.curve.includes('384') ? 'p384' : 'p256';
    }
    
    if (signatureBytes.length === 96 || curveName === 'p384') {
        hashAlgorithm = 'SHA-384';
    } else if (signatureBytes.length === 64 || curveName === 'p256') {
        hashAlgorithm = 'SHA-256';
    }

    let hashBuffer;
    if (isBrowser) {
        hashBuffer = await window.crypto.subtle.digest(hashAlgorithm, signedDataBytes);
    } else {
        const cryptoModule = require('crypto');
        hashBuffer = await cryptoModule.webcrypto.subtle.digest(hashAlgorithm, signedDataBytes);
    }
    const hashArray = Array.from(new Uint8Array(hashBuffer));

    const pubkeyAsn1 = forge.pki.publicKeyToAsn1(leafPubKey);
    const pubkeyDer = forge.asn1.toDer(pubkeyAsn1).getBytes();
    const pubKeyBytes = ByteUtils.fromBinaryString(pubkeyDer);
    
    const uncompressedMarker = pubKeyBytes.indexOf(0x04);
    if (uncompressedMarker === -1) {
        throw new Error('Cannot find uncompressed point marker in public key');
    }

    const coordSize = curveName === 'p384' ? 48 : 32;
    const coordStart = uncompressedMarker + 1;
    
    if (pubKeyBytes.length < coordStart + coordSize * 2) {
        throw new Error('Invalid public key length');
    }

    const pubKeyX = ByteUtils.toHex(ByteUtils.slice(pubKeyBytes, coordStart, coordStart + coordSize));
    const pubKeyY = ByteUtils.toHex(ByteUtils.slice(pubKeyBytes, coordStart + coordSize, coordStart + coordSize * 2));

    const EC = elliptic.ec;
    const ec = new EC(curveName);
    
    try {
        const key = ec.keyFromPublic({ x: pubKeyX, y: pubKeyY }, 'hex');
        const verified = key.verify(hashArray, { r, s });
        
        if (!verified) {
            throw new Error(`${dataFieldName} signature verification failed`);
        }
        
        console.info(`${dataFieldName} signature verified successfully`);
    } catch (error) {
        throw new Error(`${dataFieldName} signature verification failed: ${error.message}`);
    }

    const dataObj = jsonObj[dataFieldName];
    if (dataObj.issueDate && dataObj.nextUpdate) {
        const issueDate = new Date(dataObj.issueDate);
        const nextUpdate = new Date(dataObj.nextUpdate);
        const now = new Date();

        if (now < issueDate) {
            throw new Error(`${dataFieldName} not yet valid (issue date: ${dataObj.issueDate})`);
        }

        if (now > nextUpdate) {
            console.warn(`WARNING: ${dataFieldName} is outdated (next update: ${dataObj.nextUpdate})`);
        }
    }
}

/**
 * 解析逗号分隔的PEM证书链
 */
function parseCommaSeparatedPemChain(pemChainStr) {
    const certs = [];
    const pemParts = pemChainStr.split(',');
    
    for (const pemPart of pemParts) {
        const trimmed = pemPart.trim();
        if (trimmed.includes('-----BEGIN CERTIFICATE-----')) {
            try {
                const cert = forge.pki.certificateFromPem(trimmed);
                certs.push(cert);
            } catch (error) {
                console.warn('Failed to parse certificate from issuer chain:', error.message);
            }
        }
    }
    
    return certs;
}

/**
 * 验证Intel issuer chain到Intel SGX Root CA
 */
async function verifyIntelIssuerChain(issuerCerts) {
    if (issuerCerts.length === 0) {
        throw new Error('Empty issuer certificate chain');
    }

    const rootCerts = [
        forge.pki.certificateFromPem(INTEL_SGX_ROOT_CA_CERTS.G1),
        forge.pki.certificateFromPem(INTEL_SGX_ROOT_CA_CERTS.G3),
        forge.pki.certificateFromPem(INTEL_SGX_ROOT_CA_CERTS.G4)
    ];
    
    const caStore = forge.pki.createCaStore(rootCerts);

    try {
        const verified = forge.pki.verifyCertificateChain(caStore, issuerCerts, function(vfd, depth, chain) {
            if (vfd === true) {
                return true;
            }
            
            const cert = chain[depth];
            const now = new Date();
            
            if (now < cert.validity.notBefore) {
                vfd.error = forge.pki.certificateError.certificate.validity.notBefore;
                return false;
            }
            
            if (now > cert.validity.notAfter) {
                vfd.error = forge.pki.certificateError.certificate.validity.notAfter;
                return false;
            }
            
            return true;
        });

        if (!verified) {
            throw new Error('Intel issuer chain verification failed');
        }

        console.info('Intel issuer chain verified successfully');
    } catch (error) {
        throw new Error(`Intel issuer chain verification failed: ${error.message}`);
    }
}

/**
 * 解析DER编码的ECDSA签名
 */
function parseDerEcdsaSignature(derBytes) {
    try {
        const binaryStr = ByteUtils.toBinaryString(derBytes);
        const asn1 = forge.asn1.fromDer(forge.util.createBuffer(binaryStr));
        
        if (asn1.type !== forge.asn1.Type.SEQUENCE || asn1.value.length !== 2) {
            throw new Error('Invalid DER ECDSA signature structure');
        }
        
        const rAsn1 = asn1.value[0];
        const sAsn1 = asn1.value[1];
        
        if (rAsn1.type !== forge.asn1.Type.INTEGER || sAsn1.type !== forge.asn1.Type.INTEGER) {
            throw new Error('Invalid DER ECDSA signature: r and s must be INTEGERs');
        }
        
        const rBytes = ByteUtils.fromBinaryString(rAsn1.value);
        const sBytes = ByteUtils.fromBinaryString(sAsn1.value);
        
        let rHex = ByteUtils.toHex(rBytes);
        let sHex = ByteUtils.toHex(sBytes);
        
        while (rHex.length > 64 && rHex.startsWith('00')) {
            rHex = rHex.substring(2);
        }
        while (sHex.length > 64 && sHex.startsWith('00')) {
            sHex = sHex.substring(2);
        }
        
        return { r: rHex, s: sHex };
    } catch (error) {
        throw new Error(`Failed to parse DER ECDSA signature: ${error.message}`);
    }
}

/**
 * 获取证书的Issuer CN
 */
function getIssuerCN(cert) {
    if (!cert.issuer || !cert.issuer.attributes) {
        return '';
    }
    
    for (const attr of cert.issuer.attributes) {
        if (attr.shortName === 'CN' || attr.name === 'commonName') {
            return attr.value;
        }
    }
    
    return '';
}

/**  
 * 从quote中提取FMSPC
 * FMSPC是平台的Family-Model-Stepping-Platform-CustomSKU标识符  
 */
function extractFmspc(quoteData) {
    // 方法1: 从PCK证书扩展中提取  
    if (quoteData.certChain && quoteData.certChain.length > 0) {
        try {
            let pckCert;
            if (quoteData.certChain[0].subject) {
                pckCert = quoteData.certChain[0];
            } else {
                const binaryStr = ByteUtils.toBinaryString(quoteData.certChain[0]);
                pckCert = forge.pki.certificateFromAsn1(
                    forge.asn1.fromDer(forge.util.createBuffer(binaryStr))
                );
            }

            // FMSPC在SGX扩展中 (OID: 1.2.840.113741.1.13.1.4)  
            const fmspcExt = findExtension(pckCert, '1.2.840.113741.1.13.1.4');
            if (fmspcExt) {
                // FMSPC是6字节的值
                let fmspcValue = fmspcExt.value;
                if (typeof fmspcValue === 'string') {
                    fmspcValue = ByteUtils.fromBinaryString(fmspcValue);
                }
                const fmspcBytes = ByteUtils.toBytes(fmspcValue);
                return ByteUtils.toHex(fmspcBytes).toUpperCase();
            }
        } catch (error) {
            console.warn('Failed to extract FMSPC from PCK cert:', error.message);
        }
    }

    throw new Error('Cannot extract FMSPC from quote - PCK certificate not available or missing FMSPC extension');
}

/**  
 * 从quote中提取QE ID
 */
function extractQeId(quoteData) {
    if (quoteData.certChain && quoteData.certChain.length > 0) {
        try {
            let pckCert;
            if (quoteData.certChain[0].subject) {
                pckCert = quoteData.certChain[0];
            } else {
                const binaryStr = ByteUtils.toBinaryString(quoteData.certChain[0]);
                pckCert = forge.pki.certificateFromAsn1(
                    forge.asn1.fromDer(forge.util.createBuffer(binaryStr))
                );
            }

            // QE ID在SGX扩展中 (OID: 1.2.840.113741.1.13.1.3)  
            const qeIdExt = findExtension(pckCert, '1.2.840.113741.1.13.1.3');
            if (qeIdExt) {
                let qeIdValue = qeIdExt.value;
                if (typeof qeIdValue === 'string') {
                    qeIdValue = ByteUtils.fromBinaryString(qeIdValue);
                }
                return ByteUtils.toHex(ByteUtils.toBytes(qeIdValue));
            }
        } catch (error) {
            console.warn('Failed to extract QE ID from PCK cert:', error.message);
        }
    }

    if (quoteData.qeSvn !== undefined) {
        return `qe_svn_${quoteData.qeSvn}`;
    }

    return 'default';
}

/**  
 * 解析PEM格式的证书链
 */
function parsePemCertChain(pemChain) {
    const certs = [];
    const certRegex = /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g;
    const matches = pemChain.match(certRegex);

    if (matches) {
        for (const pemCert of matches) {
            try {
                const cert = forge.pki.certificateFromPem(pemCert);
                certs.push(cert);
            } catch (error) {
                console.warn('Failed to parse certificate:', error.message);
            }
        }
    }

    if (certs.length === 0) {
        throw new Error('No valid certificates found in PEM chain');
    }

    return certs;
}

/**  
 * 验证证书链  
 * 使用node-forge的证书验证API，支持多根证书
 */
async function verifyCertChain(certChain, collateral, trustedRootCAs = null) {
    // 步骤1: 确保有证书链可用  
    if (!certChain || certChain.length === 0) {
        if (collateral && collateral.pckCertChain) {
            certChain = collateral.pckCertChain;
        } else {
            throw new Error('No certificate chain available');
        }
    }

    if (!certChain || certChain.length === 0) {
        throw new Error('Certificate chain is empty after fallback');
    }

    let rootCerts;
    if (trustedRootCAs && Array.isArray(trustedRootCAs)) {
        rootCerts = trustedRootCAs.map(pem => forge.pki.certificateFromPem(pem));
    } else {
        rootCerts = [
            forge.pki.certificateFromPem(INTEL_SGX_ROOT_CA_CERTS.G1),
            forge.pki.certificateFromPem(INTEL_SGX_ROOT_CA_CERTS.G3),
            forge.pki.certificateFromPem(INTEL_SGX_ROOT_CA_CERTS.G4)
        ];
    }

    const caStore = forge.pki.createCaStore(rootCerts);

    const intermediateCerts = certChain.slice(1);

    try {
        const verified = forge.pki.verifyCertificateChain(caStore, [certChain[0], ...intermediateCerts], function(vfd, depth, chain) {
            if (vfd === true) {
                return true;
            }
            
            const cert = chain[depth];
            const now = new Date();
            
            if (now < cert.validity.notBefore) {
                vfd.error = forge.pki.certificateError.certificate.validity.notBefore;
                return false;
            }
            
            if (now > cert.validity.notAfter) {
                vfd.error = forge.pki.certificateError.certificate.validity.notAfter;
                return false;
            }
            
            return true;
        });

        if (!verified) {
            throw new Error('Certificate chain verification failed');
        }

        console.info('Certificate chain verified successfully against Intel SGX Root CAs');
    } catch (error) {
        throw new Error(`Certificate chain verification failed: ${error.message}`);
    }

    if (collateral && collateral.rootCaCrl) {
        console.info('Performing Root CA CRL verification');

        try {
            const crl = forge.pki.certificateRevocationListFromPem(collateral.rootCaCrl);

            let crlVerified = false;
            for (const rootCa of rootCerts) {
                try {
                    const verified = rootCa.publicKey.verify(
                        crl.tbsCertList,
                        crl.signature
                    );
                    if (verified) {
                        crlVerified = true;
                        console.info('Root CA CRL signature verified');
                        break;
                    }
                } catch (e) {
                }
            }

            if (!crlVerified) {
                throw new Error('Root CA CRL signature verification failed with all root CAs');
            }

            const now = new Date();
            if (crl.thisUpdate && now < crl.thisUpdate) {
                throw new Error(`CRL is not yet valid (thisUpdate: ${crl.thisUpdate})`);
            }
            if (crl.nextUpdate && now > crl.nextUpdate) {
                console.warn(`WARNING: CRL is outdated (nextUpdate: ${crl.nextUpdate})`);
            }

            for (let i = 0; i < certChain.length; i++) {
                const cert = certChain[i];
                const revokedCert = crl.getRevokedCertificate(cert.serialNumber);

                if (revokedCert) {
                    throw new Error(
                        `Certificate ${i} (serial: ${cert.serialNumber}) has been revoked. ` +
                        `Revocation date: ${revokedCert.revocationDate}`
                    );
                }
            }

            console.info('Root CA CRL verification completed successfully');
        } catch (error) {
            throw new Error(`Root CA CRL verification failed: ${error.message}`);
        }
    } else {
        console.warn('WARNING: No Root CA CRL provided, skipping root revocation check');
    }

    if (collateral && collateral.pckCrls) {
        console.info('Performing PCK CRL verification');
        
        const pckCert = certChain[0];
        const issuerCN = getIssuerCN(pckCert);
        
        let crlToUse = null;
        let crlType = '';
        
        if (issuerCN.includes('Processor')) {
            crlToUse = collateral.pckCrls.processor;
            crlType = 'Processor';
        } else if (issuerCN.includes('Platform')) {
            crlToUse = collateral.pckCrls.platform;
            crlType = 'Platform';
        }
        
        if (crlToUse) {
            try {
                const crl = forge.pki.certificateRevocationListFromPem(crlToUse);
                
                if (certChain.length > 1) {
                    const issuerCert = certChain[1];
                    const crlVerified = issuerCert.publicKey.verify(
                        crl.tbsCertList,
                        crl.signature
                    );
                    
                    if (!crlVerified) {
                        throw new Error(`${crlType} PCK CRL signature verification failed`);
                    }
                    
                    console.info(`${crlType} PCK CRL signature verified`);
                }
                
                const now = new Date();
                if (crl.thisUpdate && now < crl.thisUpdate) {
                    throw new Error(`${crlType} PCK CRL is not yet valid (thisUpdate: ${crl.thisUpdate})`);
                }
                if (crl.nextUpdate && now > crl.nextUpdate) {
                    console.warn(`WARNING: ${crlType} PCK CRL is outdated (nextUpdate: ${crl.nextUpdate})`);
                }
                
                const revokedCert = crl.getRevokedCertificate(pckCert.serialNumber);
                if (revokedCert) {
                    throw new Error(
                        `PCK certificate (serial: ${pckCert.serialNumber}) has been revoked. ` +
                        `Revocation date: ${revokedCert.revocationDate}`
                    );
                }
                
                console.info(`${crlType} PCK CRL verification completed successfully`);
            } catch (error) {
                throw new Error(`${crlType} PCK CRL verification failed: ${error.message}`);
            }
        } else {
            console.warn('WARNING: No appropriate PCK CRL found for verification');
        }
    } else {
        console.warn('WARNING: No PCK CRLs provided, skipping PCK revocation check');
    }

    console.info('Certificate chain verification completed successfully');
}

/**  
 * 验证TCB级别  
 * 基于ra_tls_verify_dcap.c:182-229的TCB验证逻辑  
 */
async function verifyTCB(quoteData, tcbInfo) {
    const tcbInfoObj = typeof tcbInfo === 'string' ? JSON.parse(tcbInfo) : tcbInfo;
    
    if (!tcbInfoObj.tcbInfo || !tcbInfoObj.tcbInfo.tcbLevels) {
        throw new Error('Invalid TCB Info structure');
    }
    
    const tcbLevels = tcbInfoObj.tcbInfo.tcbLevels;

    // 从quote中提取TCB组件  
    const quoteTcb = {
        cpuSvn: Array.from(quoteData.cpuSvn),
        pceSvn: quoteData.pceSvn
    };

    // 查找匹配的TCB级别  
    let matchedTcbLevel = null;
    for (const tcbLevel of tcbLevels) {
        if (!tcbLevel.tcb) {
            console.warn('TCB level missing tcb field, skipping');
            continue;
        }

        const tcbComponents = tcbLevel.tcb.sgxtcbcomponents || tcbLevel.tcb.sgxtcbcomp;
        
        if (!tcbComponents || !Array.isArray(tcbComponents) || tcbComponents.length < 16) {
            console.warn('TCB level has invalid sgxtcbcomponents, skipping');
            continue;
        }

        // 检查所有TCB组件是否匹配或更高  
        let allMatch = true;
        for (let i = 0; i < 16; i++) {
            const componentSvn = tcbComponents[i].svn !== undefined ? tcbComponents[i].svn : 0;
            if (quoteTcb.cpuSvn[i] < componentSvn) {
                allMatch = false;
                break;
            }
        }

        const tcbPceSvn = tcbLevel.tcb.pcesvn !== undefined ? tcbLevel.tcb.pcesvn : 0;
        if (allMatch && quoteTcb.pceSvn >= tcbPceSvn) {
            matchedTcbLevel = tcbLevel;
            break;
        }
    }

    if (!matchedTcbLevel) {
        throw new Error('No matching TCB level found');
    }

    // 返回TCB状态  
    return matchedTcbLevel.tcbStatus || 'Unknown';
}

/**  
 * 验证Quote签名  
 * 使用ECDSA P-256/P-384验证  
 */
async function verifyQuoteSignature(quoteData, collateral) {
    if (quoteData.version !== 3 && quoteData.version !== 4) {
        throw new Error(`Unsupported quote version: ${quoteData.version}`);
    }

    if (quoteData.attestationKeyType !== 2 && quoteData.attestationKeyType !== 3) {
        throw new Error(
            `Unsupported attestation key type: ${quoteData.attestationKeyType}. ` +
            `SGX DCAP only supports type 2 (ECDSA-P256) and type 3 (ECDSA-P384)`
        );
    }

    const sigData = quoteData.signature;
    
    // attestationKeyType: 2 = ECDSA-P256 (32-byte coordinates), 3 = ECDSA-P384 (48-byte coordinates)
    const coordSize = quoteData.attestationKeyType === 3 ? 48 : 32;
    const sigSize = coordSize * 2;
    const minSigDataSize = sigSize + sigSize + 384 + sigSize; // sig + pubkey + qe_report + qe_report_sig
    
    if (!sigData || sigData.length < minSigDataSize) {
        throw new Error(`Invalid signature data: expected at least ${minSigDataSize} bytes, got ${sigData ? sigData.length : 0}`);
    }

    let offset = 0;
    const ecdsaSignature = ByteUtils.slice(sigData, offset, offset + sigSize); offset += sigSize;
    const attestationPubKey = ByteUtils.slice(sigData, offset, offset + sigSize); offset += sigSize;

    // 验证Quote主签名  
    const headerSize = 48;
    const reportBodySize = 384;
    const signedDataSize = headerSize + reportBodySize;
    const signedData = ByteUtils.slice(quoteData.rawQuote, 0, signedDataSize);

    const curveName = quoteData.attestationKeyType === 3 ? 'p384' : 'p256';
    const hashAlgorithm = quoteData.attestationKeyType === 3 ? 'SHA-384' : 'SHA-256';
    const EC = elliptic.ec;
    const ec = new EC(curveName);

    try {
        const pubKeyX = ByteUtils.slice(attestationPubKey, 0, coordSize);
        const pubKeyY = ByteUtils.slice(attestationPubKey, coordSize, coordSize * 2);

        const key = ec.keyFromPublic({
            x: ByteUtils.toHex(pubKeyX),
            y: ByteUtils.toHex(pubKeyY)
        }, 'hex');

        let hashBuffer;
        if (isBrowser) {
            hashBuffer = await window.crypto.subtle.digest(hashAlgorithm, signedData);
        } else {
            const cryptoModule = require('crypto');
            hashBuffer = await cryptoModule.webcrypto.subtle.digest(hashAlgorithm, signedData);
        }
        const hashArray = Array.from(new Uint8Array(hashBuffer));

        const r = ByteUtils.toHex(ByteUtils.slice(ecdsaSignature, 0, coordSize));
        const s = ByteUtils.toHex(ByteUtils.slice(ecdsaSignature, coordSize, coordSize * 2));

        const verified = key.verify(hashArray, { r, s });

        if (!verified) {
            throw new Error('Quote ECDSA signature verification failed');
        }

        console.info('Quote signature verified successfully');

        await verifyQeReportSignature(quoteData, sigData, collateral);

    } catch (error) {
        throw new Error(`Quote signature verification failed: ${error.message}`);
    }
}

/**  
 * 验证QE Report签名
 */
async function verifyQeReportSignature(quoteData, sigData, collateral) {
    // QE Report在签名数据的固定偏移位置
    let offset = 128; // 64 (sig) + 64 (pubkey)
    const qeReportSize = 384;

    if (sigData.length < offset + qeReportSize) {
        throw new Error('QE Report not available in signature data');
    }

    const qeReport = ByteUtils.slice(sigData, offset, offset + qeReportSize);
    offset += qeReportSize;

    const qeReportView = ByteUtils.dataView(qeReport);
    let reportOffset = 0;

    const qeCpuSvn = ByteUtils.slice(qeReport, reportOffset, reportOffset + 16); reportOffset += 16;
    const qeMiscSelect = qeReportView.getUint32(reportOffset, true); reportOffset += 4;
    reportOffset += 28; // reserved
    const qeAttributes = ByteUtils.slice(qeReport, reportOffset, reportOffset + 16); reportOffset += 16;
    const qeMrenclave = ByteUtils.slice(qeReport, reportOffset, reportOffset + 32); reportOffset += 32;
    reportOffset += 32; // reserved
    const qeMrsigner = ByteUtils.slice(qeReport, reportOffset, reportOffset + 32); reportOffset += 32;
    reportOffset += 96; // reserved
    const qeIsvProdId = qeReportView.getUint16(reportOffset, true); reportOffset += 2;
    const qeIsvSvn = qeReportView.getUint16(reportOffset, true); reportOffset += 2;
    reportOffset += 60; // reserved
    const qeReportData = ByteUtils.slice(qeReport, reportOffset, reportOffset + 64);

    // 步骤1: 验证QE Report的report_data包含attestation key的哈希
    const attestationPubKey = ByteUtils.slice(sigData, 64, 128);
    
    let hashBuffer;
    if (isBrowser) {
        hashBuffer = await window.crypto.subtle.digest('SHA-256', attestationPubKey);
    } else {
        const cryptoModule = require('crypto');
        hashBuffer = await cryptoModule.webcrypto.subtle.digest('SHA-256', attestationPubKey);
    }
    const expectedHash = new Uint8Array(hashBuffer);

    const actualHash = ByteUtils.slice(qeReportData, 0, 32);

    if (!ByteUtils.equalBytes(expectedHash, actualHash)) {
        throw new Error('QE Report data mismatch: attestation key hash does not match report_data');
    }

    // 步骤2: 验证QE Report签名
    if (sigData.length < offset + 64) {
        throw new Error('QE Report signature not available');
    }

    const qeReportSignature = ByteUtils.slice(sigData, offset, offset + 64);

    let pckCert;
    if (quoteData.certChain && quoteData.certChain.length > 0) {
        if (quoteData.certChain[0].subject) {
            pckCert = quoteData.certChain[0];
        } else {
            const binaryStr = ByteUtils.toBinaryString(quoteData.certChain[0]);
            pckCert = forge.pki.certificateFromAsn1(
                forge.asn1.fromDer(forge.util.createBuffer(binaryStr))
            );
        }
    } else if (collateral && collateral.pckCertChain && collateral.pckCertChain.length > 0) {
        pckCert = collateral.pckCertChain[0];
    } else {
        throw new Error('No PCK certificate chain available for QE Report verification');
    }

    const pckPubKey = pckCert.publicKey;
    const pckPubKeyAsn1 = forge.pki.publicKeyToAsn1(pckPubKey);
    const pckPubKeyDer = forge.asn1.toDer(pckPubKeyAsn1).getBytes();
    const pubKeyBytes = ByteUtils.fromBinaryString(pckPubKeyDer);

    const uncompressedMarker = pubKeyBytes.indexOf(0x04);
    if (uncompressedMarker === -1) {
        throw new Error('Cannot find uncompressed point marker in PCK public key');
    }

    const coordSize = 32; // P-256
    const coordStart = uncompressedMarker + 1;

    if (pubKeyBytes.length < coordStart + coordSize * 2) {
        throw new Error('Invalid PCK public key length');
    }

    const pckPubKeyX = ByteUtils.slice(pubKeyBytes, coordStart, coordStart + coordSize);
    const pckPubKeyY = ByteUtils.slice(pubKeyBytes, coordStart + coordSize, coordStart + coordSize * 2);

    // 使用elliptic库验证QE Report签名
    const EC = elliptic.ec;
    const ec = new EC('p256');

    try {
        const key = ec.keyFromPublic({
            x: ByteUtils.toHex(pckPubKeyX),
            y: ByteUtils.toHex(pckPubKeyY)
        }, 'hex');

        // 计算QE Report的哈希
        let qeReportHash;
        if (isBrowser) {
            qeReportHash = await window.crypto.subtle.digest('SHA-256', qeReport);
        } else {
            const cryptoModule = require('crypto');
            qeReportHash = await cryptoModule.webcrypto.subtle.digest('SHA-256', qeReport);
        }
        const qeReportHashArray = Array.from(new Uint8Array(qeReportHash));

        // 提取签名的r和s分量
        const r = ByteUtils.toHex(ByteUtils.slice(qeReportSignature, 0, 32));
        const s = ByteUtils.toHex(ByteUtils.slice(qeReportSignature, 32, 64));

        // 验证签名
        const verified = key.verify(qeReportHashArray, { r, s });

        if (!verified) {
            throw new Error('QE Report signature verification failed');
        }

        console.info('QE Report signature verified successfully');

        // 步骤3: 验证QE Identity
        if (collateral && collateral.qeIdentity) {
            await verifyQeIdentity(qeMrenclave, qeMrsigner, qeIsvProdId, qeIsvSvn, collateral.qeIdentity);
        }

    } catch (error) {
        throw new Error(`QE Report signature verification failed: ${error.message}`);
    }
}

/**  
 * 验证QE Identity 
 * 基于Intel发布的QE Identity验证QE的度量值  
 */
async function verifyQeIdentity(qeMrenclave, qeMrsigner, qeIsvProdId, qeIsvSvn, qeIdentity) {
    if (!qeIdentity) {
        console.warn('QE Identity not available, skipping QE identity verification');
        return;
    }

    const qeIdObj = typeof qeIdentity === 'string' ? JSON.parse(qeIdentity) : qeIdentity;

    if (!qeIdObj.enclaveIdentity) {
        throw new Error('Invalid QE Identity structure: missing enclaveIdentity field');
    }

    const enclaveIdentity = qeIdObj.enclaveIdentity;

    // 1. 验证MRSIGNER (必须匹配)
    if (!enclaveIdentity.mrsigner) {
        throw new Error('QE Identity missing mrsigner field');
    }

    const expectedMrsigner = ByteUtils.fromHex(enclaveIdentity.mrsigner);
    const qeMrsignerBytes = ByteUtils.toBytes(qeMrsigner);

    if (!ByteUtils.equalBytes(qeMrsignerBytes, expectedMrsigner)) {
        throw new Error(
            `QE MRSIGNER mismatch: expected ${enclaveIdentity.mrsigner}, ` +
            `got ${ByteUtils.toHex(qeMrsignerBytes)}`
        );
    }

    // 2. 验证ISV_PROD_ID (必须匹配)
    if (enclaveIdentity.isvprodid === undefined) {
        throw new Error('QE Identity missing isvprodid field');
    }

    if (qeIsvProdId !== enclaveIdentity.isvprodid) {
        throw new Error(
            `QE ISV_PROD_ID mismatch: expected ${enclaveIdentity.isvprodid}, ` +
            `got ${qeIsvProdId}`
        );
    }

    // 3. 验证ISV_SVN (QE的版本必须大于等于最小要求)
    if (enclaveIdentity.isvsvn === undefined) {
        throw new Error('QE Identity missing isvsvn field');
    }

    if (qeIsvSvn < enclaveIdentity.isvsvn) {
        throw new Error(
            `QE ISV_SVN too low: minimum required ${enclaveIdentity.isvsvn}, ` +
            `got ${qeIsvSvn}`
        );
    }

    console.info('QE Identity verification successful');
    console.info(`  MRSIGNER: ${ByteUtils.toHex(qeMrsignerBytes)}`);
    console.info(`  ISV_PROD_ID: ${qeIsvProdId}`);
    console.info(`  ISV_SVN: ${qeIsvSvn} (minimum required: ${enclaveIdentity.isvsvn})`);
}

/**
 * 验证测量值策略
 * 基于Gramine的verify_quote_body_against_envvar_measurements逻辑
 */
function verifyMeasurementPolicy(quoteData, policy) {
    const { expectedMrEnclave, expectedMrSigner, expectedIsvProdId, expectedIsvSvn } = policy;
    
    if (expectedMrEnclave) {
        const actualMrEnclave = ByteUtils.toHex(quoteData.mrenclave).toLowerCase();
        const expectedMrEnclaveNorm = expectedMrEnclave.toLowerCase();
        if (actualMrEnclave !== expectedMrEnclaveNorm) {
            throw new Error(
                `MRENCLAVE mismatch: expected ${expectedMrEnclaveNorm}, got ${actualMrEnclave}`
            );
        }
    }
    
    if (expectedMrSigner) {
        const actualMrSigner = ByteUtils.toHex(quoteData.mrsigner).toLowerCase();
        const expectedMrSignerNorm = expectedMrSigner.toLowerCase();
        if (actualMrSigner !== expectedMrSignerNorm) {
            throw new Error(
                `MRSIGNER mismatch: expected ${expectedMrSignerNorm}, got ${actualMrSigner}`
            );
        }
    }
    
    if (expectedIsvProdId !== null && expectedIsvProdId !== undefined) {
        if (quoteData.isvProdId !== expectedIsvProdId) {
            throw new Error(
                `ISV_PROD_ID mismatch: expected ${expectedIsvProdId}, got ${quoteData.isvProdId}`
            );
        }
    }
    
    if (expectedIsvSvn !== null && expectedIsvSvn !== undefined) {
        if (quoteData.isvSvn < expectedIsvSvn) {
            throw new Error(
                `ISV_SVN too low: minimum required ${expectedIsvSvn}, got ${quoteData.isvSvn}`
            );
        }
    }
    
    if (!expectedMrEnclave && !expectedMrSigner) {
        console.warn('WARNING: Neither expectedMrEnclave nor expectedMrSigner are specified. ' +
                     'This will accept any enclave and provides no security whatsoever.');
    }
}

/**  
 * 验证Enclave属性  
 * 基于ra_tls_verify_dcap.c:237-241  
 */
function verifyEnclaveAttributes(quoteData, allowDebugEnclave) {
    const attributes = quoteData.attributes;
    if (!attributes || attributes.length < 16) {
        throw new Error('Invalid enclave attributes');
    }

    const view = ByteUtils.dataView(attributes);

    // Attributes结构: flags(8 bytes) + xfrm(8 bytes)  
    const flags = view.getBigUint64(0, true);
    const xfrm = view.getBigUint64(8, true);

    // 检查关键标志位 (基于sgx_arch.h中的定义)  
    const SGX_FLAGS_INITTED = 0x01n;
    const SGX_FLAGS_DEBUG = 0x02n;
    const SGX_FLAGS_MODE64BIT = 0x04n;

    // INIT标志必须设置  
    if ((flags & SGX_FLAGS_INITTED) === 0n) {
        throw new Error('Enclave not initialized (INIT flag not set)');
    }

    // 64位模式必须设置  
    if ((flags & SGX_FLAGS_MODE64BIT) === 0n) {
        throw new Error('Enclave must be in 64-bit mode');
    }

    // 检查DEBUG标志  
    const isDebug = (flags & SGX_FLAGS_DEBUG) !== 0n;
    if (isDebug && !allowDebugEnclave) {
        throw new Error('Debug enclave not allowed (DEBUG flag is set)');
    }

    // 验证XFRM (扩展特性请求掩码)  
    const SGX_XFRM_LEGACY = 0x03n; // x87 + SSE (必须设置)

    // Legacy特性(x87 + SSE)必须设置  
    if ((xfrm & SGX_XFRM_LEGACY) !== SGX_XFRM_LEGACY) {
        throw new Error('Enclave must have x87 and SSE support (XFRM legacy bits not set)');
    }

    console.info('Enclave attributes verified successfully');
}

/**  
 * 评估TCB状态  
 * 基于ra_tls_verify_dcap.c:182-229  
 */
function evaluateTcbStatus(tcbStatus, allowOutdatedTcb, allowHwConfigNeeded, allowSwHardeningNeeded) {
    const statusMap = {
        'UpToDate': SGX_QL_QV_RESULT.OK,
        'OutOfDate': SGX_QL_QV_RESULT.OUT_OF_DATE,
        'ConfigurationNeeded': SGX_QL_QV_RESULT.CONFIG_NEEDED,
        'OutOfDateConfigurationNeeded': SGX_QL_QV_RESULT.OUT_OF_DATE_CONFIG_NEEDED,
        'SWHardeningNeeded': SGX_QL_QV_RESULT.SW_HARDENING_NEEDED,
        'ConfigurationAndSWHardeningNeeded': SGX_QL_QV_RESULT.CONFIG_AND_SW_HARDENING_NEEDED,
        'Revoked': SGX_QL_QV_RESULT.REVOKED
    };

    const result = statusMap[tcbStatus] || SGX_QL_QV_RESULT.UNSPECIFIED;

    // 检查是否允许该状态  
    switch (result) {
        case SGX_QL_QV_RESULT.OK:
            return result;

        case SGX_QL_QV_RESULT.CONFIG_NEEDED:
            if (!allowHwConfigNeeded) {
                throw new Error(`TCB status ${tcbStatus} not allowed (hardware configuration needed)`);
            }
            return result;

        case SGX_QL_QV_RESULT.OUT_OF_DATE:
            if (!allowOutdatedTcb) {
                throw new Error(`TCB status ${tcbStatus} not allowed (TCB is out of date)`);
            }
            return result;

        case SGX_QL_QV_RESULT.OUT_OF_DATE_CONFIG_NEEDED:
            if (!allowOutdatedTcb || !allowHwConfigNeeded) {
                throw new Error(`TCB status ${tcbStatus} not allowed (out of date and config needed)`);
            }
            return result;

        case SGX_QL_QV_RESULT.SW_HARDENING_NEEDED:
            if (!allowSwHardeningNeeded) {
                throw new Error(`TCB status ${tcbStatus} not allowed (software hardening needed)`);
            }
            return result;

        case SGX_QL_QV_RESULT.CONFIG_AND_SW_HARDENING_NEEDED:
            if (!allowHwConfigNeeded || !allowSwHardeningNeeded) {
                throw new Error(`TCB status ${tcbStatus} not allowed (config and SW hardening needed)`);
            }
            return result;

        case SGX_QL_QV_RESULT.REVOKED:
            throw new Error(`TCB status ${tcbStatus} indicates platform is revoked`);

        case SGX_QL_QV_RESULT.UNSPECIFIED:
        default:
            throw new Error(`TCB status ${tcbStatus} indicates verification failure (unspecified)`);
    }
}

/**  
 * 将TCB状态转换为字符串
 * 基于ra_tls_verify_dcap.c:74-96中的sgx_ql_qv_result_to_str函数  
 */
function tcbStatusToString(tcbStatus) {
    if (typeof tcbStatus === 'string') {
        return tcbStatus;
    }

    if (typeof tcbStatus === 'number') {
        switch (tcbStatus) {
            case SGX_QL_QV_RESULT.OK:
                return 'OK';
            case SGX_QL_QV_RESULT.CONFIG_NEEDED:
                return 'CONFIG_NEEDED';
            case SGX_QL_QV_RESULT.OUT_OF_DATE:
                return 'OUT_OF_DATE';
            case SGX_QL_QV_RESULT.OUT_OF_DATE_CONFIG_NEEDED:
                return 'OUT_OF_DATE_CONFIG_NEEDED';
            case SGX_QL_QV_RESULT.SW_HARDENING_NEEDED:
                return 'SW_HARDENING_NEEDED';
            case SGX_QL_QV_RESULT.CONFIG_AND_SW_HARDENING_NEEDED:
                return 'CONFIG_AND_SW_HARDENING_NEEDED';
            case SGX_QL_QV_RESULT.INVALID_SIGNATURE:
                return 'INVALID_SIGNATURE';
            case SGX_QL_QV_RESULT.REVOKED:
                return 'REVOKED';
            case SGX_QL_QV_RESULT.UNSPECIFIED:
                return 'UNSPECIFIED';
            default:
                return 'UNKNOWN';
        }
    }

    return 'Unknown';
}

// 导出主函数和辅助类型  
if (typeof module !== 'undefined' && module.exports) {
    // Node.js环境  
    module.exports = {
        verifyQuote,
        SGX_QL_QV_RESULT,
        INTEL_SGX_ROOT_CA_CERTS,
        parseQuoteStructure,
        extractQuote,
        ByteUtils
    };
} else {
    // 浏览器环境  
    window.SGXQuoteVerifier = {
        verifyQuote,
        SGX_QL_QV_RESULT,
        INTEL_SGX_ROOT_CA_CERTS,
        parseQuoteStructure,
        extractQuote,
        ByteUtils
    };
}
