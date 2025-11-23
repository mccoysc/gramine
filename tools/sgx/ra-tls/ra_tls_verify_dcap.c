/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Intel Labs */

/*!
 * \file
 *
 * This file contains the implementation of verification callbacks for TLS libraries. The callbacks
 * verify the correctness of a self-signed RA-TLS certificate with an SGX quote embedded in it. The
 * callbacks call into the `libsgx_dcap_quoteverify` DCAP library for ECDSA-based verification. A
 * callback ra_tls_verify_callback() can be used directly in mbedTLS, and a more generic version
 * ra_tls_verify_callback_der() should be used for other TLS libraries.
 *
 * This file is part of the RA-TLS verification library which is typically linked into client
 * applications. This library is *not* thread-safe.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <mbedtls/pk.h>
#include <mbedtls/sha256.h>
#include <mbedtls/x509_crt.h>

#include "quote.h"
#include "util.h"

#include "ra_tls.h"
#include "ra_tls_common.h"

extern verify_measurements_cb_t g_verify_measurements_cb;

/* Maximum platform instance ID length: 64 hex chars for PCK SPKI hash (SHA-256) + null terminator */
#define MAX_PLATFORM_INSTANCE_ID_SIZE 65

/* we cannot include libsgx_dcap_verify headers because they conflict with Gramine SGX headers,
 * so we declare the used types and functions below */

/* QL stands for Quoting Library; QV stands for Quote Verification */
#define SGX_QL_QV_MK_ERROR(x) (0x0000A000 | (x))
typedef enum _sgx_ql_qv_result_t {
    /* quote verification passed and is at the latest TCB level */
    SGX_QL_QV_RESULT_OK = 0x0000,
    /* quote verification passed and the platform is patched to the latest TCB level but additional
     * configuration of the SGX platform may be needed */
    SGX_QL_QV_RESULT_CONFIG_NEEDED = SGX_QL_QV_MK_ERROR(0x0001),
    /* quote is good but TCB level of the platform is out of date; platform needs patching to be at
     * the latest TCB level */
    SGX_QL_QV_RESULT_OUT_OF_DATE = SGX_QL_QV_MK_ERROR(0x0002),
    /* quote is good but the TCB level of the platform is out of date and additional configuration
     * of the SGX platform at its current patching level may be needed; platform needs patching to
     * be at the latest TCB level */
    SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED = SGX_QL_QV_MK_ERROR(0x0003),
    /* signature over the application report is invalid */
    SGX_QL_QV_RESULT_INVALID_SIGNATURE = SGX_QL_QV_MK_ERROR(0x0004),
    /* attestation key or platform has been revoked */
    SGX_QL_QV_RESULT_REVOKED = SGX_QL_QV_MK_ERROR(0x0005),
    /* quote verification failed due to an error in one of the input */
    SGX_QL_QV_RESULT_UNSPECIFIED = SGX_QL_QV_MK_ERROR(0x0006),
    /* TCB level of the platform is up to date, but SGX SW hardening is needed */
    SGX_QL_QV_RESULT_SW_HARDENING_NEEDED = SGX_QL_QV_MK_ERROR(0x0007),
    /* TCB level of the platform is up to date, but additional configuration of the platform at its
     * current patching level may be needed; moreover, SGX SW hardening is also needed */
    SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED = SGX_QL_QV_MK_ERROR(0x0008),
} sgx_ql_qv_result_t;

int sgx_qv_get_quote_supplemental_data_size(uint32_t* p_data_size);
int sgx_qv_verify_quote(const uint8_t* p_quote, uint32_t quote_size, void* p_quote_collateral,
                        const time_t expiration_check_date,
                        uint32_t* p_collateral_expiration_status,
                        sgx_ql_qv_result_t* p_quote_verification_result, void* p_qve_report_info,
                        uint32_t supplemental_data_size, uint8_t* p_supplemental_data);

static const char* sgx_ql_qv_result_to_str(sgx_ql_qv_result_t verification_result) {
    switch (verification_result) {
        case SGX_QL_QV_RESULT_OK:
            return "OK";
        case SGX_QL_QV_RESULT_CONFIG_NEEDED:
            return "CONFIG_NEEDED";
        case SGX_QL_QV_RESULT_OUT_OF_DATE:
            return "OUT_OF_DATE";
        case SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED:
            return "OUT_OF_DATE_CONFIG_NEEDED";
        case SGX_QL_QV_RESULT_SW_HARDENING_NEEDED:
            return "SW_HARDENING_NEEDED";
        case SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED:
            return "CONFIG_AND_SW_HARDENING_NEEDED";
        case SGX_QL_QV_RESULT_INVALID_SIGNATURE:
            return "INVALID_SIGNATURE";
        case SGX_QL_QV_RESULT_REVOKED:
            return "REVOKED";
        case SGX_QL_QV_RESULT_UNSPECIFIED:
            return "UNSPECIFIED";
    }
    return "<unrecognized error>";
}

/*!
 * \brief Extract platform instance ID from SGX quote certification data.
 *
 * \param quote_data  Raw quote bytes.
 * \param quote_size  Size of quote in bytes.
 * \param out_buf     Output buffer for platform instance ID (hex string).
 * \param out_buf_size Size of output buffer (must be at least MAX_PLATFORM_INSTANCE_ID_SIZE).
 *
 * \returns true if platform instance ID was successfully extracted, false otherwise.
 *
 * This function extracts the platform instance identifier from the SGX quote's certification data:
 * - For certification data type 1 (PPID-based): extracts the 16-byte PPID as a 32-char hex string
 * - For certification data type 5 (PCK cert chain): extracts SHA-256 hash of PCK SPKI as 64-char hex
 *
 * The function returns false if the quote is malformed, certification data is unavailable, or the
 * certification data type is not supported.
 */
static bool extract_platform_instance_id_from_quote(const uint8_t* quote_data, size_t quote_size,
                                                     char* out_buf, size_t out_buf_size) {
    if (!quote_data || !out_buf || out_buf_size < MAX_PLATFORM_INSTANCE_ID_SIZE) {
        return false;
    }

    /* Initialize output buffer */
    memset(out_buf, 0, out_buf_size);

    if (quote_size < 48) {
        INFO("Quote too small to parse: %zu bytes\n", quote_size);
        return false;
    }

    /* Parse quote header */
    uint16_t version;
    memcpy(&version, quote_data, 2);

    uint16_t attestation_key_type;
    memcpy(&attestation_key_type, quote_data + 2, 2);

    const size_t quote_header_size = 48;
    const size_t report_body_size  = 384;
    const size_t quote_body_size   = quote_header_size + report_body_size; /* 432 */

    if (quote_size < quote_body_size + 4) {
        INFO("Quote too small for signature: %zu bytes\n", quote_size);
        return false;
    }

    uint32_t signature_size;
    memcpy(&signature_size, quote_data + quote_body_size, 4);

    if (quote_size < quote_body_size + 4 + signature_size) {
        INFO("Quote size mismatch: expected %zu, got %zu\n",
             quote_body_size + 4 + signature_size, quote_size);
        return false;
    }

    /* Only process ECDSA quotes (version 3 or 4) */
    if (version != 3 && version != 4) {
        INFO("Quote version %u not supported for platform instance ID extraction\n", version);
        return false;
    }

    const uint8_t* sig_data = quote_data + quote_body_size + 4;

    /* Parse ECDSA signature data structure */
    size_t coord_size = (attestation_key_type == 3) ? 48 : 32;
    size_t sig_len    = coord_size * 2;
    size_t pubkey_len = coord_size * 2;

    size_t offset = 0;
    offset += sig_len;    /* Skip ECDSA signature */
    offset += pubkey_len; /* Skip attestation public key */
    offset += 384;        /* Skip QE report body */
    offset += sig_len;    /* Skip QE report signature */

    /* Check for auth_data_len */
    if (offset + 2 > signature_size) {
        return false;
    }

    uint16_t auth_data_len;
    memcpy(&auth_data_len, sig_data + offset, 2);
    offset += 2;

    /* Skip auth data if present */
    if (auth_data_len > 0 && offset + auth_data_len <= signature_size) {
        offset += auth_data_len;
    }

    /* Check for cert_data_type and cert_data_size */
    if (offset + 6 > signature_size) {
        return false;
    }

    const uint8_t* cert_data_buffer = sig_data + offset;
    size_t cert_data_buffer_size    = signature_size - offset;

    /* Parse certification data header */
    size_t cert_offset = 0;
    uint16_t cert_data_type;
    memcpy(&cert_data_type, cert_data_buffer + cert_offset, 2);
    cert_offset += 2;

    uint32_t cert_data_size;
    memcpy(&cert_data_size, cert_data_buffer + cert_offset, 4);
    cert_offset += 4;

    /* Clamp cert_data_size to available buffer */
    size_t actual_cert_data_size = cert_data_size;
    if (cert_offset + cert_data_size > cert_data_buffer_size) {
        actual_cert_data_size = cert_data_buffer_size - cert_offset;
    }

    const uint8_t* cert_data = cert_data_buffer + cert_offset;
    uint8_t data_type        = cert_data_type & 0xFF;

    if (data_type == 1) {
        /* PPID-based certification data */
        if (actual_cert_data_size < 36) {
            INFO("PPID-based cert data too small: %zu bytes (expected at least 36)\n",
                 actual_cert_data_size);
            return false;
        }

        /* Extract PPID (first 16 bytes) and convert to hex */
        for (int i = 0; i < 16; i++) {
            sprintf(&out_buf[i * 2], "%02x", cert_data[i]);
        }
        out_buf[32] = '\0';
        INFO("Extracted platform instance ID (PPID): %s\n", out_buf);
        return true;

    } else if (data_type == 5) {
        /* PCK certificate chain - extract SPKI fingerprint from leaf certificate */
        const char* pem_start = memmem(cert_data, actual_cert_data_size,
                                       "-----BEGIN CERTIFICATE-----", 27);
        if (!pem_start) {
            INFO("No PEM certificate found in cert data type 5\n");
            return false;
        }

        size_t remaining_from_start = actual_cert_data_size - (pem_start - (const char*)cert_data);
        const char* pem_end = memmem(pem_start, remaining_from_start,
                                     "-----END CERTIFICATE-----", 25);
        if (!pem_end) {
            INFO("Incomplete PEM certificate in cert data\n");
            return false;
        }

        pem_end += 25;
        size_t pem_len = pem_end - pem_start;

        /* Parse certificate using mbedTLS */
        char* pem_buf = malloc(pem_len + 1);
        if (!pem_buf) {
            ERROR("Failed to allocate memory for PEM buffer\n");
            return false;
        }
        memcpy(pem_buf, pem_start, pem_len);
        pem_buf[pem_len] = '\0';

        mbedtls_x509_crt pck_cert;
        mbedtls_x509_crt_init(&pck_cert);

        int ret = mbedtls_x509_crt_parse(&pck_cert, (const unsigned char*)pem_buf, pem_len + 1);
        free(pem_buf);

        if (ret != 0) {
            ERROR("Failed to parse PCK certificate: %d\n", ret);
            mbedtls_x509_crt_free(&pck_cert);
            return false;
        }

        /* Extract SPKI from certificate */
        unsigned char spki_der[512];
        int spki_len = mbedtls_pk_write_pubkey_der(&pck_cert.pk, spki_der, sizeof(spki_der));

        if (spki_len < 0) {
            ERROR("Failed to write SPKI DER: %d\n", spki_len);
            mbedtls_x509_crt_free(&pck_cert);
            return false;
        }

        /* mbedtls_pk_write_pubkey_der writes from the end of the buffer */
        const unsigned char* spki_start = spki_der + sizeof(spki_der) - spki_len;

        /* Compute SHA-256 hash of SPKI */
        unsigned char sha256_hash[32];
        mbedtls_sha256(spki_start, spki_len, sha256_hash, 0);

        /* Convert to hex string */
        for (int i = 0; i < 32; i++) {
            sprintf(&out_buf[i * 2], "%02x", sha256_hash[i]);
        }
        out_buf[64] = '\0';

        mbedtls_x509_crt_free(&pck_cert);
        INFO("Extracted platform instance ID from PCK SPKI: %s\n", out_buf);
        return true;

    } else {
        INFO("Unsupported certification data type: %u\n", data_type);
        return false;
    }
}

int ra_tls_verify_callback(void* data, mbedtls_x509_crt* crt, int depth, uint32_t* flags) {
    struct ra_tls_verify_callback_results* results = (struct ra_tls_verify_callback_results*)data;

    int ret;
    sgx_quote_t* quote = NULL;

    uint8_t* supplemental_data      = NULL;
    uint32_t supplemental_data_size = 0;

    if (results) {
        results->attestation_scheme = RA_TLS_ATTESTATION_SCHEME_DCAP;
        results->err_loc = AT_INIT;
    }

    if (depth != 0) {
        /* the cert chain in RA-TLS consists of single self-signed cert, so we expect depth 0 */
        return MBEDTLS_ERR_X509_INVALID_FORMAT;
    }

    if (flags) {
        /* mbedTLS sets flags to signal that the cert is not to be trusted (e.g., it is not
         * correctly signed by a trusted CA; since RA-TLS uses self-signed certs, we don't care
         * what mbedTLS thinks and ignore internal cert verification logic of mbedTLS */
        *flags = 0;
    }

    if (results)
        results->err_loc = AT_EXTRACT_QUOTE;

    /* extract SGX quote from "quote" OID extension from crt */
    size_t quote_size;
    ret = extract_quote_and_verify_claims(crt, &quote, &quote_size);
    if (ret < 0) {
        ERROR("extract_quote_and_verify_claims failed: %d\n", ret);
        goto out;
    }

    if (results)
        results->err_loc = AT_VERIFY_EXTERNAL;

    /* prepare user-supplied verification parameters "allow outdated TCB", etc. */
    bool allow_outdated_tcb        = getenv_allow_outdated_tcb();
    bool allow_hw_config_needed    = getenv_allow_hw_config_needed();
    bool allow_sw_hardening_needed = getenv_allow_sw_hardening_needed();
    bool allow_debug_enclave       = getenv_allow_debug_enclave();

    /* call into libsgx_dcap_quoteverify to get supplemental data size */
    ret = sgx_qv_get_quote_supplemental_data_size(&supplemental_data_size);
    if (ret) {
        ERROR("sgx_qv_get_quote_supplemental_data_size failed: %d\n", ret);
        ret = MBEDTLS_ERR_X509_FATAL_ERROR;
        goto out;
    }

    supplemental_data = (uint8_t*)malloc(supplemental_data_size);
    if (!supplemental_data) {
        ret = MBEDTLS_ERR_X509_ALLOC_FAILED;
        goto out;
    }

    time_t current_time = time(NULL);
    if (current_time == ((time_t)-1)) {
        ret = MBEDTLS_ERR_X509_FATAL_ERROR;
        goto out;
    }

    uint32_t collateral_expiration_status  = 1;
    sgx_ql_qv_result_t verification_result = SGX_QL_QV_RESULT_UNSPECIFIED;

    /* call into libsgx_dcap_quoteverify to verify ECDSA-based SGX quote */
    ret = sgx_qv_verify_quote((uint8_t*)quote, (uint32_t)quote_size, /*p_quote_collateral=*/NULL,
                              current_time, &collateral_expiration_status, &verification_result,
                              /*p_qve_report_info=*/NULL, supplemental_data_size,
                              supplemental_data);
    if (results) {
        results->dcap.func_verify_quote_result = ret;
        results->dcap.quote_verification_result = verification_result;
    }
    if (ret) {
        ERROR("sgx_qv_verify_quote failed: %d\n", ret);
        ret = MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;
        goto out;
    }

    switch (verification_result) {
        case SGX_QL_QV_RESULT_OK:
            ret = 0;
            if (collateral_expiration_status != 0) {
                INFO("WARNING: The collateral is out of date.\n");
                if (!allow_outdated_tcb)
                    ret = MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;
            }
            break;
        case SGX_QL_QV_RESULT_CONFIG_NEEDED:
            ret = allow_hw_config_needed ? 0 : MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;
            break;
        case SGX_QL_QV_RESULT_OUT_OF_DATE:
            ret = allow_outdated_tcb ? 0 : MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;
            break;
        case SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED:
            ret = allow_outdated_tcb
                      ? (allow_hw_config_needed ? 0 : MBEDTLS_ERR_X509_CERT_VERIFY_FAILED)
                      : MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;
            break;
        case SGX_QL_QV_RESULT_SW_HARDENING_NEEDED:
            ret = allow_sw_hardening_needed ? 0 : MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;
            break;
        case SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED:
            ret = allow_hw_config_needed
                      ? (allow_sw_hardening_needed ? 0 : MBEDTLS_ERR_X509_CERT_VERIFY_FAILED)
                      : MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;
            break;
        case SGX_QL_QV_RESULT_INVALID_SIGNATURE:
        case SGX_QL_QV_RESULT_REVOKED:
        case SGX_QL_QV_RESULT_UNSPECIFIED:
        default:
            ret = MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;
            break;
    }
    if (ret < 0) {
        if (verification_result == SGX_QL_QV_RESULT_OK) {
            assert(collateral_expiration_status != 0 && !allow_outdated_tcb);
            ERROR("Quote: verification failed because collateral is out of date\n");
        } else {
            ERROR("Quote: verification failed with error %s\n",
                  sgx_ql_qv_result_to_str(verification_result));
        }
        goto out;
    }
    if (verification_result != SGX_QL_QV_RESULT_OK) {
        INFO("Allowing quote status %s\n", sgx_ql_qv_result_to_str(verification_result));
    }

    if (results)
        results->err_loc = AT_VERIFY_ENCLAVE_ATTRS;

    sgx_quote_body_t* quote_body = &quote->body;

    /* verify enclave attributes from the SGX quote body */
    ret = verify_quote_body_enclave_attributes(quote_body, allow_debug_enclave);
    if (ret < 0) {
        ret = MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;
        goto out;
    }

    if (results)
        results->err_loc = AT_VERIFY_ENCLAVE_MEASUREMENTS;

    /* Extract platform instance ID from quote */
    char platform_id[MAX_PLATFORM_INSTANCE_ID_SIZE];
    bool have_platform_id = extract_platform_instance_id_from_quote(
        (const uint8_t*)quote, quote_size,
        platform_id, sizeof(platform_id)
    );
    const char* platform_id_arg = have_platform_id ? platform_id : NULL;

    /* Get certificate DER bytes */
    const uint8_t* cert_der = crt->raw.p;
    size_t cert_der_size = crt->raw.len;

    /* verify other relevant enclave information from the SGX quote */
    if (g_verify_measurements_cb) {
        /* use user-supplied callback to verify measurements */
        ret = g_verify_measurements_cb((const char*)&quote_body->report_body.mr_enclave,
                                       (const char*)&quote_body->report_body.mr_signer,
                                       (const char*)&quote_body->report_body.isv_prod_id,
                                       (const char*)&quote_body->report_body.isv_svn,
                                       platform_id_arg,
                                       cert_der,
                                       cert_der_size);
    } else {
        /* use default logic to verify measurements */
        ret = verify_quote_body_against_envvar_measurements(quote_body);
    }
    if (ret < 0) {
        ret = MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;
        goto out;
    }

    if (results)
        results->err_loc = AT_NONE;
    ret = 0;
out:
    free(quote);
    free(supplemental_data);
    return ret;
}
