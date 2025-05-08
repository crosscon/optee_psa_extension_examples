/*
The code for this example is copied from programs/psa/psa_hash.c from https://github.com/Mbed-TLS/TF-PSA-Crypto/
 */

#include <tee_internal_api.h>
#include <string.h>
#include <include/crypto_types.h>
#include <include/crypto_struct.h>
#include <aes_ta.h>
#include <include/wrapper.h>
#include <include/wrapper.c>

/* Information about hashing with the PSA API can be
 * found here:
 * https://arm-software.github.io/psa-api/crypto/1.1/api/ops/hashes.html
 *
 * The algorithm used by this demo is SHA 256.
 * Please see include/psa/crypto_values.h to see the other
 * algorithms that are supported by Mbed TLS.
 * If you switch to a different algorithm you will need to update
 * the hash data in the EXAMPLE_HASH_VALUE macro below. */

TEE_Result TA_CreateEntryPoint(void) {
    return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void) {
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types, TEE_Param params[4], void **sess_ctx) {
    (void) param_types;
    (void) params;
    (void) sess_ctx;
    create_session(sess_ctx);

    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx) {
    (void) sess_ctx;
}

#define HASH_ALG PSA_ALG_SHA_256

const uint8_t sample_message[] = "Hello World!";
/* sample_message is terminated with a null byte which is not part of
 * the message itself so we make sure to subtract it in order to get
 * the message length. */
const size_t sample_message_length = sizeof(sample_message) - 1;

#define EXPECTED_HASH_VALUE {                                                    \
        0x7f, 0x83, 0xb1, 0x65, 0x7f, 0xf1, 0xfc, 0x53, 0xb9, 0x2d, 0xc1, 0x81, \
        0x48, 0xa1, 0xd6, 0x5d, 0xfc, 0x2d, 0x4b, 0x1f, 0xa3, 0xd6, 0x77, 0x28, \
        0x4a, 0xdd, 0xd2, 0x00, 0x12, 0x6d, 0x90, 0x69 \
}

const uint8_t expected_hash[] = EXPECTED_HASH_VALUE;
const size_t expected_hash_len = sizeof(expected_hash);

int hash(void) {
    psa_status_t status;
    uint8_t hash[PSA_HASH_LENGTH(HASH_ALG)];
    size_t hash_length;
    // we don't initialize these operations, since the values are not saved on them
    psa_hash_operation_t *hash_operation;
    // we can't use more than one operation at a time due to limitations of the wrapper
    // so the cloned operation is commented out, but kept in this code since it is in the original code
    // psa_hash_operation_t* cloned_hash_operation;

    mbedtls_printf("PSA Crypto API: SHA-256 example\n\n");

    status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        mbedtls_printf("psa_crypto_init failed\n");
        return EXIT_FAILURE;
    }

    /* Compute hash using multi-part operation */
    status = psa_hash_setup(&hash_operation, HASH_ALG);
    if (status == PSA_ERROR_NOT_SUPPORTED) {
        mbedtls_printf("unknown hash algorithm supplied\n");
        return EXIT_FAILURE;
    } else if (status != PSA_SUCCESS) {
        mbedtls_printf("psa_hash_setup failed\n");
        return EXIT_FAILURE;
    }

    status = psa_hash_update(&hash_operation, sample_message, sample_message_length);
    if (status != PSA_SUCCESS) {
        mbedtls_printf("psa_hash_update failed\n");
        goto cleanup;
    }
    // we can't use more than one operation at a time due to limitations of the wrapper
    // so the cloned operation is commented out, but kept in this code since it is in the original code

    // status = psa_hash_clone(&hash_operation, &cloned_hash_operation);
    // if (status != PSA_SUCCESS) {
    //     mbedtls_printf("PSA hash clone failed\n");
    //     goto cleanup;
    // }

    status = psa_hash_finish(&hash_operation, hash, sizeof(hash), &hash_length);
    if (status != PSA_SUCCESS) {
        mbedtls_printf("psa_hash_finish failed\n");
        goto cleanup;
    }

    /* Check the result of the operation against the sample */
    if (hash_length != expected_hash_len ||
        (memcmp(hash, expected_hash, expected_hash_len) != 0)) {
        mbedtls_printf("Multi-part hash operation gave the wrong result!\n\n");
        TEE_Panic(0xdeadbeef);
    }

    // we can't use more than one operation at a time due to limitations of the wrapper
    // so the cloned operation is commented out, but kept in this code since it is in the original code

    // status =
    //     psa_hash_verify(&cloned_hash_operation, expected_hash,
    //                     expected_hash_len);
    // if (status != PSA_SUCCESS) {
    //     mbedtls_printf("psa_hash_verify failed\n");
    //     goto cleanup;
    // } else {
    //     mbedtls_printf("Multi-part hash operation successful!\n");
    // }

    /* Clear local variables prior to one-shot hash demo */
    memset(hash, 0, sizeof(hash));
    hash_length = 0;

    /* Compute hash using one-shot function call */
    status = psa_hash_compute(HASH_ALG,
                              sample_message, sample_message_length,
                              hash, sizeof(hash),
                              &hash_length);
    if (status != PSA_SUCCESS) {
        mbedtls_printf("psa_hash_compute failed\n");
        TEE_Panic(0xdeadbeef);
    }

    if (hash_length != expected_hash_len ||
        (memcmp(hash, expected_hash, expected_hash_len) != 0)) {
        mbedtls_printf("One-shot hash operation gave the wrong result!\n\n");
        TEE_Panic(0xdeadbeef);
    }

    mbedtls_printf("One-shot hash operation successful!\n\n");

    /* Print out result */
    mbedtls_printf("The SHA-256( '%s' ) is: ", sample_message);

    for (size_t j = 0; j < expected_hash_len; j++) {
        mbedtls_printf("%02x", hash[j]);
    }

    mbedtls_printf("\n");
    // this call is not needed, since we clear the operation handle on completion / start of another operation
    mbedtls_psa_crypto_free();
    return EXIT_SUCCESS;

cleanup:
    // we don't need to abort the operations, since they are aborted automatically on start of a new operation
    // psa_hash_abort(&hash_operation);
    // psa_hash_abort(&cloned_hash_operation);
    return EXIT_FAILURE;
}

TEE_Result TA_InvokeCommandEntryPoint(void *session_id,
                                      uint32_t command_id,
                                      uint32_t parameters_type,
                                      TEE_Param parameters[4]) {
    hash();
    return TEE_SUCCESS;
}
