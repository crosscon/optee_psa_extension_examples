/*
* Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 *  Example computing a SHA-256 hash using the PSA Crypto API
 *
 *  The example computes the SHA-256 hash of a test string using the
 *  one-shot API call psa_hash_compute() and the using multi-part
 *  operation, which requires psa_hash_setup(), psa_hash_update() and
 *  psa_hash_finish(). The multi-part operation is popular on embedded
 *  devices where a rolling hash needs to be computed.
 *
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include <tee_internal_api.h>
#include <hello_world_ta.h>
#include <tee_api_types.h>
#include <string.h>
#include <include/crypto_types.h>
#include <include/wrapper.h>
#include <include/wrapper.c>
#include <include/crypto_struct.h>


/* Information about hashing with the PSA API can be
 * found here:
 * https://arm-software.github.io/psa-api/crypto/1.1/api/ops/hashes.html
 *
 * The algorithm used by this demo is SHA 256.
 * Please see include/psa/crypto_values.h to see the other
 * algorithms that are supported by Mbed TLS.
 * If you switch to a different algorithm you will need to update
 * the hash data in the EXAMPLE_HASH_VALUE macro below. */

/* Dummy inputs for HMAC */
const unsigned char msg1_part1[] = { 0x01, 0x02 };
const unsigned char msg1_part2[] = { 0x03, 0x04 };
const unsigned char msg2_part1[] = { 0x05, 0x05 };
const unsigned char msg2_part2[] = { 0x06, 0x06 };

/* Dummy key material - never do this in production!
 * This example program uses SHA-256, so a 32-byte key makes sense. */
const unsigned char key_bytes[32] = { 0 };

/* Print the contents of a buffer in hex */
void print_buf(const char *title, uint8_t *buf, size_t len)
{
    printf("%s:", title);
    for (size_t i = 0; i < len; i++) {
        printf(" %02x", buf[i]);
    }
    printf("\n");
}

/* Run a PSA function and bail out if it fails.
 * The symbolic name of the error code can be recovered using:
 * programs/psa/psa_constant_name status <value> */
#define PSA_CHECK(expr)                                       \
    do                                                          \
    {                                                           \
        status = (expr);                                      \
        if (status != PSA_SUCCESS)                             \
        {                                                       \
            printf("Error %d at line %d: %s\n",                \
                   (int) status,                               \
                   __LINE__,                                   \
                   #expr);                                    \
            TEE_Panic(0xdeadbeef);                                          \
        }                                                       \
    }                                                           \
    while (0)

/*
 * This function demonstrates computation of the HMAC of two messages using
 * the multipart API.
 */
psa_status_t hmac_demo(void)
{
    psa_status_t status;
    const psa_algorithm_t alg = PSA_ALG_HMAC(PSA_ALG_SHA_256);
    uint8_t out[32]; // safe but not optimal
    /* PSA_MAC_LENGTH(PSA_KEY_TYPE_HMAC, 8 * sizeof( key_bytes ), alg)
     * should work but see https://github.com/Mbed-TLS/mbedtls/issues/4320 */

    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key = 0;

    /* prepare key */
    // we derive the usage from the key alg, so we don't need this

    // psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_MESSAGE);
    // psa_set_key_algorithm(&attributes, alg);
    // psa_set_key_type(&attributes, PSA_KEY_TYPE_HMAC);
    // psa_set_key_bits(&attributes, 8 * sizeof(key_bytes));     // optional

    status = psa_generate_key(8 * sizeof( key_bytes ), alg, &key);
    if (status != PSA_SUCCESS) {
        return status;
    }

    /* prepare operation */

    // again no initialisation needed
    psa_mac_operation_t* op;
    size_t out_len = 0;

    /* compute HMAC(key, msg1_part1 | msg1_part2) */
    PSA_CHECK(psa_mac_sign_setup(&op, &key, alg));
    PSA_CHECK(psa_mac_update(&op, msg1_part1, sizeof(msg1_part1)));
    PSA_CHECK(psa_mac_update(&op, msg1_part2, sizeof(msg1_part2)));
    PSA_CHECK(psa_mac_sign_finish(&op, out, sizeof(out), &out_len));
    print_buf("msg1", out, out_len);

    /* compute HMAC(key, msg2_part1 | msg2_part2) */
    PSA_CHECK(psa_mac_sign_setup(&op, &key, alg));
    PSA_CHECK(psa_mac_update(&op, msg2_part1, sizeof(msg2_part1)));
    PSA_CHECK(psa_mac_update(&op, msg2_part2, sizeof(msg2_part2)));
    PSA_CHECK(psa_mac_sign_finish(&op, out, sizeof(out), &out_len));
    print_buf("msg2", out, out_len);

exit:
    // not needed, since we clear automatically
    // psa_mac_abort(&op);   // needed on error, harmless on success
    // psa_destroy_key(key);
    mbedtls_platform_zeroize(out, sizeof(out));

    return status;
}

TEE_Result TA_CreateEntryPoint(void) {
    return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void) {}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types, TEE_Param params[4], void **sess_ctx) {
    create_session(sess_ctx);

    return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx) {
    (void) sess_ctx;
}

TEE_Result TA_InvokeCommandEntryPoint(void *session_id,
                                      uint32_t command_id,
                                      uint32_t parameters_type,
                                      TEE_Param parameters[4]) {

    /* Initialize the PSA crypto library. */
    // we don't need this
    psa_status_t status = psa_crypto_init();

     PSA_CHECK(status);

    /* Run the demo */
    hmac_demo();

    /* Deinitialize the PSA crypto library. */
    //we dont need this, since we free resources automatically
    return TEE_SUCCESS;

    exit:
    mbedtls_psa_crypto_free();
}