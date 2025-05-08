// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018, Linaro Limited
 */
/*
The code for this example is copied from programs/psa/crypto_examples.c from https://github.com/Mbed-TLS/TF-PSA-Crypto/
 */

#include <tee_internal_api.h>
#include <string.h>
#include <include/crypto_types.h>
#include <acipher_ta.h>
#include <include/wrapper.h>
#include <include/wrapper.c>
#include <include/crypto_struct.h>

#define ASSERT(predicate)                                                   \
    do                                                                        \
    {                                                                         \
        if (!(predicate))                                                 \
        {                                                                     \
            printf("\tassertion failed at %s:%d - '%s'\r\n",         \
                   __FILE__, __LINE__, #predicate);                  \
            TEE_Panic(0xdeadbeef);                                                        \
        }                                                                     \
    } while (0)

#define ASSERT_STATUS(actual, expected)                                     \
    do                                                                        \
    {                                                                         \
        if ((actual) != (expected))                                      \
        {                                                                     \
            printf("\tassertion failed at %s:%d - "                  \
                   "actual:%d expected:%d\r\n", __FILE__, __LINE__,  \
                   (psa_status_t) actual, (psa_status_t) expected); \
            TEE_Panic(0xdeadbeef);                                                        \
        }                                                                     \
    } while (0)

#define string4 "12345678"

TEE_Result TA_CreateEntryPoint(void) {
    return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void) {}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types, TEE_Param params[4], void **sess_ctx) {
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



static psa_status_t cipher_operation(psa_cipher_operation_t *operation,
                                     const uint8_t *input,
                                     size_t input_size,
                                     size_t part_size,
                                     uint8_t *output,
                                     size_t output_size,
                                     size_t *output_len)
{
    psa_status_t status;
    size_t bytes_to_write = 0, bytes_written = 0, len = 0;
    *output_len = 0;
    while (bytes_written != input_size) {
        bytes_to_write = (input_size - bytes_written > part_size ?
                          part_size :
                          input_size - bytes_written);

        status = psa_cipher_update(operation, input + bytes_written,
                                   bytes_to_write, output + *output_len,
                                   output_size - *output_len, &len);
        ASSERT_STATUS(status, PSA_SUCCESS);
        bytes_written += bytes_to_write;
        *output_len += len;
    }

    status = psa_cipher_finish(operation, output + *output_len,
                               output_size - *output_len, &len);
    ASSERT_STATUS(status, PSA_SUCCESS);
    *output_len += len;

exit:
    return status;
}

static psa_status_t cipher_encrypt(psa_key_id_t key,
                                   psa_algorithm_t alg,
                                   uint8_t *iv,
                                   size_t iv_size,
                                   const uint8_t *input,
                                   size_t input_size,
                                   size_t part_size,
                                   uint8_t *output,
                                   size_t output_size,
                                   size_t *output_len)
{
    psa_status_t status;
    psa_cipher_operation_t* operation;
    size_t iv_len = 0;
    // this call is different, since we dont save data on this variable
    // we allocate memory in the wrapper
    // memset(&operation, 0, sizeof(operation));
    status = psa_cipher_encrypt_setup(operation, key, alg, iv, iv_size);
    ASSERT_STATUS(status, PSA_SUCCESS);

    // status = psa_cipher_generate_iv(&operation, iv, iv_size, &iv_len);
    ASSERT_STATUS(status, PSA_SUCCESS);

    status = cipher_operation(&operation, input, input_size, part_size,
                              output, output_size, output_len);
    printf("cipher_encrypt");
    ASSERT_STATUS(status, PSA_SUCCESS);

exit:
    // we automatically abort operations as soon as a new operations is started
    // psa_cipher_abort(&operation);
    return status;
}

static psa_status_t cipher_decrypt(psa_key_id_t key,
                                   psa_algorithm_t alg,
                                   const uint8_t *iv,
                                   size_t iv_size,
                                   const uint8_t *input,
                                   size_t input_size,
                                   size_t part_size,
                                   uint8_t *output,
                                   size_t output_size,
                                   size_t *output_len)
{
    psa_status_t status;
    // this line is changed, since we don't need to initialize the operation
    psa_cipher_operation_t* operation;
    // we allocate memory in the wrapper
    // memset(&operation, 0, sizeof(operation));
    status = psa_cipher_decrypt_setup(operation, key, alg, iv, iv_size);
    ASSERT_STATUS(status, PSA_SUCCESS);

    // status = psa_cipher_set_iv(&operation, iv, iv_size);
    ASSERT_STATUS(status, PSA_SUCCESS);
    status = cipher_operation(&operation, input, input_size, part_size,
                              output, output_size, output_len);
    printf("cipher_decrypt");
    ASSERT_STATUS(status, PSA_SUCCESS);

exit:
    // we automatically abort operations as soon as a new operations is started
    // psa_cipher_abort(&operation);
    return status;
}

static psa_status_t
cipher_example_encrypt_decrypt_aes_cbc_nopad_1_block(void)
{
    enum {
        block_size = PSA_BLOCK_CIPHER_BLOCK_LENGTH(PSA_KEY_TYPE_AES),
        key_bits = 256,
        part_size = block_size,
    };
    const psa_algorithm_t alg = PSA_ALG_CBC_NO_PADDING;

    psa_status_t status;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key = 0;
    size_t output_len = 0;
    uint8_t iv[block_size];
    uint8_t input[block_size];
    uint8_t encrypt[block_size];
    uint8_t decrypt[block_size];

    status = psa_generate_random(&input, sizeof(input));
    ASSERT_STATUS(status, PSA_SUCCESS);

    // we don't need these usage flags, since we simply pass the options directly to the optee function
    // psa_set_key_usage_flags(&attributes,
    //                         PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    // psa_set_key_algorithm(&attributes, alg);
    // psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    // psa_set_key_bits(&attributes, key_bits);

    // we derive the key type from used algo
    status = psa_generate_key(key_bits, alg, &key);
    ASSERT_STATUS(status, PSA_SUCCESS);
    printf(input);
    status = cipher_encrypt(key, alg, iv, sizeof(iv),
                            input, sizeof(input), part_size,
                            encrypt, sizeof(encrypt), &output_len);
    printf(encrypt);
    ASSERT_STATUS(status, PSA_SUCCESS);

    status = cipher_decrypt(key, alg, iv, sizeof(iv),
                            encrypt, output_len, part_size,
                            decrypt, sizeof(decrypt), &output_len);
    printf(decrypt);
    ASSERT_STATUS(status, PSA_SUCCESS);
    status = memcmp(input, decrypt, sizeof(input));
    ASSERT_STATUS(status, PSA_SUCCESS);

exit:
    // key is overwritten on new keygen
    // psa_destroy_key(key);
    return status;
}

static psa_status_t cipher_example_encrypt_decrypt_aes_cbc_pkcs7_multi(void)
{
    enum {
        block_size = PSA_BLOCK_CIPHER_BLOCK_LENGTH(PSA_KEY_TYPE_AES),
        key_bits = 256,
        input_size = 100,
        part_size = 10,
    };

    const psa_algorithm_t alg = PSA_ALG_CBC_PKCS7;

    psa_status_t status;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key = 0;
    size_t output_len = 0;
    uint8_t iv[block_size], input[input_size],
            encrypt[input_size + block_size], decrypt[input_size + block_size];

    status = psa_generate_random(input, sizeof(input));
    ASSERT_STATUS(status, PSA_SUCCESS);
    // same here
    // psa_set_key_usage_flags(&attributes,
    //                         PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    // psa_set_key_algorithm(&attributes, alg);
    // psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    // psa_set_key_bits(&attributes, key_bits);

    status = psa_generate_key(key_bits, alg, &key);
    ASSERT_STATUS(status, PSA_SUCCESS);

    status = cipher_encrypt(key, alg, iv, sizeof(iv),
                            input, sizeof(input), part_size,
                            encrypt, sizeof(encrypt), &output_len);
    ASSERT_STATUS(status, PSA_SUCCESS);

    status = cipher_decrypt(key, alg, iv, sizeof(iv),
                            encrypt, output_len, part_size,
                            decrypt, sizeof(decrypt), &output_len);
    ASSERT_STATUS(status, PSA_SUCCESS);
    status = memcmp(input, decrypt, sizeof(input));
    ASSERT_STATUS(status, PSA_SUCCESS);

exit:
    // psa_destroy_key(key);
    return status;
}

static psa_status_t cipher_example_encrypt_decrypt_aes_ctr_multi(void)
{
    enum {
        block_size = PSA_BLOCK_CIPHER_BLOCK_LENGTH(PSA_KEY_TYPE_AES),
        key_bits = 256,
        input_size = 100,
        part_size = 10,
    };
    const psa_algorithm_t alg = PSA_ALG_CTR;

    psa_status_t status;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key = 0;
    size_t output_len = 0;
    uint8_t iv[block_size], input[input_size], encrypt[input_size],
            decrypt[input_size];

    status = psa_generate_random(input, sizeof(input));
    printf(input);
    ASSERT_STATUS(status, PSA_SUCCESS);

    // same here
    // psa_set_key_usage_flags(&attributes,
    //                         PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    // psa_set_key_algorithm(&attributes, alg);
    // psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    // psa_set_key_bits(&attributes, key_bits);

    status = psa_generate_key(key_bits, alg, &key);
    ASSERT_STATUS(status, PSA_SUCCESS);

    status = cipher_encrypt(key, alg, iv, sizeof(iv),
                            input, sizeof(input), part_size,
                            encrypt, sizeof(encrypt), &output_len);
    ASSERT_STATUS(status, PSA_SUCCESS);

    status = cipher_decrypt(key, alg, iv, sizeof(iv),
                            encrypt, output_len, part_size,
                            decrypt, sizeof(decrypt), &output_len);
    ASSERT_STATUS(status, PSA_SUCCESS);
    printf(input);
    printf("\n");
    printf(decrypt);
    status = memcmp(input, decrypt, sizeof(input));
    ASSERT_STATUS(status, PSA_SUCCESS);

exit:
    // psa_destroy_key(key);
    return status;
}

static void cipher_examples(void)
{
    psa_status_t status;

    printf("cipher encrypt/decrypt AES CBC no padding:\r\n");
    status = cipher_example_encrypt_decrypt_aes_cbc_nopad_1_block();
    printf("first part finished");
    if (status == PSA_SUCCESS) {
        printf("\tsuccess!\r\n");
    }

    printf("cipher encrypt/decrypt AES CBC PKCS7 multipart:\r\n");
    status = cipher_example_encrypt_decrypt_aes_cbc_pkcs7_multi();
    if (status == PSA_SUCCESS) {
        printf("\tsuccess!\r\n");
    }

    printf("cipher encrypt/decrypt AES CTR multipart:\r\n");
    status = cipher_example_encrypt_decrypt_aes_ctr_multi();
    if (status == PSA_SUCCESS) {
        printf("\tsuccess!\r\n");
    }
}
TEE_Result TA_InvokeCommandEntryPoint(void *session_id,
                                      uint32_t command_id,
                                      uint32_t parameters_type,
                                      TEE_Param parameters[4]) {
    cipher_examples();
    return TEE_SUCCESS;

}
