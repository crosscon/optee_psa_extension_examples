#ifndef OPTEE_WRAPPER_H
#define OPTEE_WRAPPER_H

#include <crypto_types.h>

#include <tee_api_types.h>
#define mbedtls_printf(...) IMSG(__VA_ARGS__)
#define printf(...) IMSG(__VA_ARGS__)
#define EXIT_FAILURE 1
#define EXIT_SUCCESS 0
psa_status_t create_session(void *session);

psa_status_t psa_crypto_init(void);

psa_status_t psa_hash_setup(
        TEE_OperationHandle *operation,
        psa_algorithm_t alg);

psa_status_t psa_hash_compute(psa_algorithm_t alg,
                              const uint8_t *input,
                              size_t input_length,
                              uint8_t *hash,
                              size_t hash_size,
                              size_t *hash_length);

psa_status_t psa_hash_update(TEE_OperationHandle *operationHandle, const uint8_t *input,
                             size_t input_length);

psa_status_t psa_hash_finish(TEE_OperationHandle *operationHandle, uint8_t *hash,
                             size_t hash_size,
                             size_t *hash_length);

TEE_Result psa_alg_to_tee_alg(psa_algorithm_t alg, uint32_t *teeAlgo);

psa_status_t psa_generate_random(void *buffer, size_t bufferSize);

psa_status_t psa_generate_key(int key_bits, psa_algorithm_t psaAlgorithm,
                              TEE_ObjectHandle *key);

psa_status_t psa_cipher_decrypt_setup(TEE_OperationHandle
                                      *operationHandle,
                                      TEE_ObjectHandle *key, psa_algorithm_t
                                      psaAlgorithm,
char *iv,                                      size_t
                                      iv_size);

psa_status_t psa_cipher_encrypt_setup(TEE_OperationHandle
                                      *operationHandle,
                                      TEE_ObjectHandle *key, psa_algorithm_t
                                      psaAlgorithm,
char *iv,                                      size_t
                                      iv_size);

void mbedtls_psa_crypto_free(void);
psa_status_t psa_mac_sign_setup(TEE_OperationHandle *operation, TEE_ObjectHandle *key,
                                psa_algorithm_t alg);
psa_status_t psa_mac_update(TEE_OperationHandle *operation, const void *chunk,
                            size_t chunkSize);
psa_status_t psa_mac_sign_finish(TEE_OperationHandle *operation,void *mac, size_t macLen, size_t* macSize);

#endif //OPTEE_WRAPPER_H
