#include <wrapper.h>
#include <crypto_values.h>
#include <tee_internal_api.h>

#define RETURN_IF_FAIL(res, msg) \
if ((res) != TEE_SUCCESS) { \
EMSG(msg ": 0x%x", res); \
return PSA_ERROR_GENERIC_ERROR; \
}

struct optee_operation_context {
    uint32_t algo;
    uint32_t type;
    uint32_t mode;
    uint32_t key_size;
    TEE_OperationHandle op_handle;
    TEE_ObjectHandle key_handle;
};

struct optee_operation_context *sessionctx;


psa_status_t psa_crypto_init(void) {
    return PSA_SUCCESS;
}

psa_status_t psa_hash_setup(
    TEE_OperationHandle *operation,
    psa_algorithm_t alg) {
    uint32_t teeAlgo;
    psa_status_t res;
    RETURN_IF_FAIL(psa_alg_to_tee_alg(alg, &teeAlgo), "Algo not supported\n");
    sessionctx->algo = teeAlgo;
    sessionctx->op_handle = *operation;
    sessionctx->mode = TEE_MODE_DIGEST;
    IMSG("assigned op to struc");
    TEE_AllocateOperation(&sessionctx->op_handle, sessionctx->algo, sessionctx->mode, 256);
    IMSG("allocated op");
    return PSA_SUCCESS;
}

psa_status_t psa_hash_compute(psa_algorithm_t alg,
                              const uint8_t *input,
                              size_t input_length,
                              uint8_t *hash,
                              size_t hash_size,
                              size_t *hash_length) {
    uint32_t teeAlgo;
    RETURN_IF_FAIL(psa_alg_to_tee_alg(alg, &teeAlgo), "Algo not supported\n");

    sessionctx->algo = teeAlgo;
    sessionctx->mode = TEE_MODE_DIGEST;
    RETURN_IF_FAIL(TEE_AllocateOperation(&sessionctx->op_handle, sessionctx->algo, sessionctx->mode, 0), "Hash Operation Allocation failed\n");
    RETURN_IF_FAIL(TEE_DigestDoFinal(sessionctx->op_handle, input, input_length, hash, &hash_size), "Hash final failed\n");
    TEE_FreeOperation(sessionctx->op_handle);
    *hash_length = hash_size;
    return PSA_SUCCESS;
}

psa_status_t psa_hash_update(TEE_OperationHandle __unused *operationHandle, const uint8_t *input,
                             size_t input_length) {
    TEE_DigestUpdate(sessionctx->op_handle, input, input_length);

    return PSA_SUCCESS;
}

psa_status_t psa_hash_finish(TEE_OperationHandle __unused *operationHandle, uint8_t *hash,
                             size_t hash_size,
                             size_t *hash_length) {
    RETURN_IF_FAIL(TEE_DigestDoFinal(sessionctx->op_handle, NULL, 0, hash, &hash_size), "Hash final failed\n");
    *hash_length = hash_size;
    TEE_FreeOperation(sessionctx->op_handle);
    return PSA_SUCCESS;
}

TEE_Result psa_alg_to_tee_alg(psa_algorithm_t alg, uint32_t *teeAlgo) {
    switch (alg) {
        case PSA_ALG_MD5:
            *teeAlgo = TEE_ALG_MD5;
            break;
        case PSA_ALG_SHA_1:
            *teeAlgo = TEE_ALG_SHA1;
            break;
        case PSA_ALG_SHA_224:
            *teeAlgo = TEE_ALG_SHA224;
            break;
        case PSA_ALG_SHA_256:
            *teeAlgo = TEE_ALG_SHA256;
            break;
        case PSA_ALG_SHA_384:
            *teeAlgo = TEE_ALG_SHA384;
            break;
        case PSA_ALG_SHA_512:
            *teeAlgo = TEE_ALG_SHA512;
            break;
        case PSA_ALG_SHA3_224:
            *teeAlgo = TEE_ALG_SHA3_224;
            break;
        case PSA_ALG_SHA3_256:
            *teeAlgo = TEE_ALG_SHA3_256;
            break;
        case PSA_ALG_SHA3_384:
            *teeAlgo = TEE_ALG_SHA3_384;
            break;
        case PSA_ALG_SHA3_512:
            *teeAlgo = TEE_ALG_SHA3_512;
            break;
        case PSA_ALG_CBC_NO_PADDING:
            *teeAlgo = TEE_ALG_AES_CBC_NOPAD;
            break;
        case PSA_ALG_CTR:
            *teeAlgo = TEE_ALG_AES_CTR;
            break;
        case PSA_ALG_CBC_PKCS7:
            *teeAlgo = TEE_ALG_AES_CTR;
            break;
        case PSA_ALG_HMAC(PSA_ALG_SHA_256):
            *teeAlgo = TEE_ALG_HMAC_SHA256;
        break;


        //            TEE_ALG_AES_ECB_NOPAD
        //             TEE_ALG_AES_ECB_NOPAD
        //             TEE_ALG_AES_CBC_NOPAD
        //             TEE_ALG_AES_CTS
        //             TEE_ALG_AES_GCM
        //             TEE_ALG_AES_CMAC
        //             TEE_ALG_AES_CMAC
        //             TEE_ALG_HMAC_MD5
        //             TEE_ALG_HMAC_SHA1
        //             TEE_ALG_HMAC_SHA224
        //             TEE_ALG_HMAC_SHA256
        //             TEE_ALG_HMAC_SHA384
        //             TEE_ALG_HMAC_SHA512
        //             TEE_ALG_HMAC_MD5
        //            TEE_ALG_HMAC_SHA1
        //             TEE_ALG_HMAC_SHA224
        //             TEE_ALG_HMAC_SHA256
        //             TEE_ALG_HMAC_SHA384
        //             TEE_ALG_HMAC_SHA512


        default:
            return TEE_ERROR_NOT_IMPLEMENTED;
    }
    return TEE_SUCCESS;
}

TEE_Result get_object_type_from_algo(uint32_t teeAlgo, uint32_t *tee_type) {
    switch (teeAlgo) {
        case TEE_ALG_AES_ECB_NOPAD:
        case TEE_ALG_AES_CBC_NOPAD:
        case TEE_ALG_AES_CTR:
        case TEE_ALG_AES_CTS:
        case TEE_ALG_AES_XTS:
        case TEE_ALG_AES_CCM:
        case TEE_ALG_AES_GCM:
        case TEE_ALG_AES_CBC_MAC_NOPAD:
        case TEE_ALG_AES_CBC_MAC_PKCS5:
        case TEE_ALG_AES_CMAC:
            *tee_type = TEE_TYPE_AES;
            break;
        case TEE_ALG_DES_ECB_NOPAD:
        case TEE_ALG_DES_CBC_NOPAD:
        case TEE_ALG_DES_CBC_MAC_NOPAD:
        case TEE_ALG_DES_CBC_MAC_PKCS5:
            *tee_type = TEE_TYPE_DES;
            break;
        case TEE_ALG_DES3_ECB_NOPAD:
        case TEE_ALG_DES3_CBC_NOPAD:
        case TEE_ALG_DES3_CBC_MAC_NOPAD:
        case TEE_ALG_DES3_CBC_MAC_PKCS5:
            *tee_type = TEE_TYPE_DES3;
            break;

        case TEE_ALG_RSASSA_PKCS1_V1_5_MD5:
        case TEE_ALG_RSASSA_PKCS1_V1_5_SHA1:
        case TEE_ALG_RSASSA_PKCS1_V1_5_SHA224:
        case TEE_ALG_RSASSA_PKCS1_V1_5_SHA256:
        case TEE_ALG_RSASSA_PKCS1_V1_5_SHA384:
        case TEE_ALG_RSASSA_PKCS1_V1_5_SHA512:
        case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1:
        case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224:
        case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256:
        case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384:
        case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512:
            *tee_type = TEE_TYPE_RSA_KEYPAIR;
            break;
        case TEE_ALG_HMAC_SHA256:
            *tee_type = TEE_TYPE_HMAC_SHA256;
            break;
        default:
            *tee_type = TEE_TYPE_AES;
            return TEE_ERROR_NOT_IMPLEMENTED;
    }
    return TEE_SUCCESS;
}

TEE_Result verify_key_size_by_type(uint32_t tee_type, int *key_size) {
    bool overwrite_key_size = false;
    int newValue;
    if (key_size == NULL || *key_size == 0) {
        overwrite_key_size = true;
    }
    IMSG("verify_key_size_by_type TEE_Type is: %u", tee_type);
    IMSG("key_size is %d", *key_size);
    switch (tee_type) {
        case TEE_TYPE_AES:
            if (*key_size == 128 || *key_size == 192 || *key_size == 256) {
                return TEE_SUCCESS;
            }
            if (overwrite_key_size) {
                newValue = 256;
            }
            break;
        case TEE_TYPE_RSA_KEYPAIR:
            if (*key_size == 256 || *key_size == 512 || *key_size == 768 || *key_size == 1024 || *key_size == 1536 ||
                *key_size == 2048) {
                return TEE_SUCCESS;
            }
            if (overwrite_key_size) {
                newValue = 2048;
            }
            break;
        case TEE_TYPE_DES3:
            if (*key_size == 128 || *key_size == 192) {
                return TEE_SUCCESS;
            }
            if (overwrite_key_size) {
                newValue = 192;
            }
            break;
        case TEE_TYPE_DES:
            if (*key_size == 64)
                return TEE_SUCCESS;
            if (overwrite_key_size) newValue = 64;
            break;
        case TEE_TYPE_HMAC_SHA256:
            if (*key_size == 128 || *key_size == 192 || *key_size == 256) {
                return TEE_SUCCESS;
            }
            if (overwrite_key_size) newValue = 256;
            break;
    }
    if (overwrite_key_size) {
        *key_size = newValue;
        return TEE_ERROR_BAD_PARAMETERS;
    }
    return TEE_ERROR_NOT_IMPLEMENTED;
}

psa_status_t psa_generate_random(void *buffer, size_t bufferSize) {
    TEE_GenerateRandom(buffer, bufferSize);
    return PSA_SUCCESS;
}

psa_status_t psa_generate_key(int key_bits, psa_algorithm_t psaAlgorithm,
                              TEE_ObjectHandle *key) {
    uint32_t tee_algo;
    uint32_t tee_type;
    RETURN_IF_FAIL(psa_alg_to_tee_alg(psaAlgorithm, &tee_algo), "Algo not supported\n");

    sessionctx->key_handle = TEE_HANDLE_NULL;
    RETURN_IF_FAIL(get_object_type_from_algo(tee_algo, &tee_type), "Key type not present\n");
    RETURN_IF_FAIL(verify_key_size_by_type(tee_type, &key_bits), "wrong key bits ");

    sessionctx->key_size = key_bits;
    switch(tee_type) {
      case TEE_TYPE_HMAC_SHA256 : {
        uint8_t key_data[key_bits / 8];  // 256-bit HMAC key
        TEE_Attribute attr;
        TEE_GenerateRandom(key_data, sizeof(key_data));
        RETURN_IF_FAIL(TEE_AllocateTransientObject(tee_type, sizeof(key_data) * 8, &sessionctx->key_handle), "Failed to allocate Operation\n");

        TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, key_data, sizeof(key_data));
        RETURN_IF_FAIL(TEE_PopulateTransientObject(sessionctx->key_handle, &attr, 1), "Failed to poulate Object");
        break;
        }
      default: {
            RETURN_IF_FAIL(TEE_AllocateTransientObject(tee_type, sessionctx->key_size, &sessionctx->key_handle), "Failed to allocate Operation\n");
            RETURN_IF_FAIL(TEE_GenerateKey(sessionctx->key_handle, sessionctx->key_size, NULL, 0), "failed to generate key");
          }
    }
    return PSA_SUCCESS;
}


psa_status_t psa_cipher_setup(TEE_OperationHandle
                              *__unused operationHandle,
                              TEE_ObjectHandle *key, psa_algorithm_t
                              psaAlgorithm,
                              char *iv,
                              size_t
                              iv_size, uint32_t mode) {
    uint32_t tee_alg;
    RETURN_IF_FAIL(psa_alg_to_tee_alg(psaAlgorithm, &tee_alg), "Algo not supported\n");
    sessionctx->algo = tee_alg;
    sessionctx->mode = mode;

    if (sessionctx->op_handle != TEE_HANDLE_NULL) {
        IMSG("op was not null, clearing operation handle\n");
        TEE_ResetOperation(sessionctx->op_handle);
    }
    RETURN_IF_FAIL(TEE_AllocateOperation(&sessionctx->op_handle,
                                   sessionctx->algo,
                                   sessionctx->mode,
                                   sessionctx->key_size), "Cipher Operation allocation failed\n");
    RETURN_IF_FAIL(TEE_SetOperationKey(sessionctx->op_handle, sessionctx->key_handle), "Failed to set operation key for cipher operation\n");

    TEE_CipherInit(sessionctx->op_handle, iv, iv_size);

    return PSA_SUCCESS;
}

psa_status_t psa_cipher_decrypt_setup(TEE_OperationHandle
                                      *operationHandle,
                                      TEE_ObjectHandle *key, psa_algorithm_t
                                      psaAlgorithm,
                                      char *iv,
                                      size_t iv_size) {
    return psa_cipher_setup(operationHandle, key, psaAlgorithm, iv, iv_size, TEE_MODE_DECRYPT);
}

psa_status_t psa_cipher_encrypt_setup(TEE_OperationHandle
                                      *operationHandle,
                                      TEE_ObjectHandle *key, psa_algorithm_t
                                      psaAlgorithm,
                                      char *iv,
                                      size_t iv_size) {
    return psa_cipher_setup(operationHandle, key, psaAlgorithm, iv, iv_size, TEE_MODE_ENCRYPT);
}

psa_status_t psa_cipher_update(TEE_OperationHandle
                               *operationHandle, const uint8_t *input, size_t input_size,
                               uint8_t *output, size_t output_size, size_t* output_len) {
    if (sessionctx->op_handle == TEE_HANDLE_NULL) {
        IMSG("Cipher operation not initialized, psa_cipher_decrypt_setup / psa_cipher_encrypt_setup needs to be called before psa_cipher_update \n");
        return PSA_ERROR_NOT_SUPPORTED;
    }
    RETURN_IF_FAIL(TEE_CipherUpdate(sessionctx->op_handle, input, input_size, output, &output_size), "Error updating cipher\n");
    *output_len = output_size;
    return PSA_SUCCESS;
}

psa_status_t psa_cipher_finish(TEE_OperationHandle
                               *operationHandle,
                               uint8_t *output, size_t output_size, size_t* output_len) {
    if (sessionctx->op_handle == TEE_HANDLE_NULL) {
        IMSG("Cipher operation not initialized, psa_cipher_decrypt_setup / psa_cipher_encrypt_setup needs to be called before psa_cipher_finish \n");
    }
    RETURN_IF_FAIL(TEE_CipherDoFinal(sessionctx->op_handle, NULL, 0, output, &output_size), "psa_cipher_finish failed\n");

    TEE_FreeOperation(sessionctx->op_handle);
    sessionctx->op_handle = TEE_HANDLE_NULL;
    // this function is only used to finish the cipher, so 0 bytes are written
    *output_len = 0;
    return PSA_SUCCESS;
}


psa_status_t create_session(void *session) {
    struct optee_operation_context *sess;

    /*
     * Allocate and init ciphering materials for the session.
     * The address of the structure is used as session ID for
     * the client.
     */
    sess = TEE_Malloc(sizeof(*sess), 0);
    if (!sess)
        return PSA_ERROR_NOT_SUPPORTED;

    sess->key_handle = TEE_HANDLE_NULL;
    sess->op_handle = TEE_HANDLE_NULL;
    sessionctx = sess;
    session = (void *) sess;
    return PSA_SUCCESS;
}

void mbedtls_psa_crypto_free() {
}

psa_status_t psa_mac_sign_setup(TEE_OperationHandle *operation, TEE_ObjectHandle *key,
                                psa_algorithm_t alg) {
    uint32_t teeAlgo;
    RETURN_IF_FAIL(psa_alg_to_tee_alg(alg, &teeAlgo), "Algo not supported\n");
    sessionctx->algo = teeAlgo;
    TEE_AllocateOperation(&sessionctx->op_handle, sessionctx->algo, TEE_MODE_MAC, sessionctx->key_size);
    RETURN_IF_FAIL(TEE_SetOperationKey(sessionctx->op_handle, sessionctx->key_handle), "Failed to set operation key for MAC sign \n");
    TEE_MACInit(sessionctx->op_handle, NULL, 0);
    return PSA_SUCCESS;
}

psa_status_t psa_mac_update(TEE_OperationHandle *operation, const void *chunk,
                            size_t chunkSize) {
    TEE_MACUpdate(sessionctx->op_handle, chunk, chunkSize);
    return PSA_SUCCESS;
}
psa_status_t psa_mac_sign_finish(TEE_OperationHandle *operation,void *mac, size_t macLen, size_t* macSize) {
    RETURN_IF_FAIL(TEE_MACComputeFinal(sessionctx->op_handle,NULL, 0, mac, &macLen), "Mac sign failed\n");
    TEE_FreeOperation(sessionctx->op_handle);
    sessionctx->op_handle = TEE_HANDLE_NULL;

    *macSize = macLen;

    return PSA_SUCCESS;
}
