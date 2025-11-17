/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2024 Intel Corp. */

/* This mbedTLS config is for v3.6.3 and is used for RA-TLS libraries */

#pragma once

/* Enable PSA Crypto support for PK layer (required for ED25519 via mbedtls_pk_setup_opaque) */
#define MBEDTLS_USE_PSA_CRYPTO

/* Include the default mbedTLS configuration which has been patched to enable PSA Crypto */
#include <mbedtls/mbedtls_config.h>
