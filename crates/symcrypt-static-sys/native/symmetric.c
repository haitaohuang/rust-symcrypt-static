#include <stddef.h>
#include <string.h>
#include "symcrypt.h"

extern void *symcrypt_rs_alloc(size_t size, size_t alignment);
extern void symcrypt_rs_free(void *pointer);
extern int sc_aes_available(void);

typedef struct {
    uint32_t algorithm;
    union {
        SYMCRYPT_HMAC_SHA256_EXPANDED_KEY s256;
        SYMCRYPT_HMAC_SHA384_EXPANDED_KEY s384;
        SYMCRYPT_HMAC_SHA512_EXPANDED_KEY s512;
    } key;
    union {
        SYMCRYPT_HMAC_SHA256_STATE s256;
        SYMCRYPT_HMAC_SHA384_STATE s384;
        SYMCRYPT_HMAC_SHA512_STATE s512;
    } state;
} SC_HMAC;

static PCSYMCRYPT_MAC mac_algorithm(uint32_t algorithm)
{
    switch (algorithm) {
    case 256: return SymCryptHmacSha256Algorithm;
    case 384: return SymCryptHmacSha384Algorithm;
    case 512: return SymCryptHmacSha512Algorithm;
    default: return NULL;
    }
}

SC_HMAC *sc_hmac_new(uint32_t algorithm, const uint8_t *key, size_t length)
{
    if (mac_algorithm(algorithm) == NULL) {
        return NULL;
    }
    SC_HMAC *context = symcrypt_rs_alloc(sizeof(*context), _Alignof(SC_HMAC));
    if (context == NULL) {
        return NULL;
    }
    context->algorithm = algorithm;
    switch (algorithm) {
    case 256:
        SymCryptHmacSha256ExpandKey(&context->key.s256, key, length);
        SymCryptHmacSha256Init(&context->state.s256, &context->key.s256);
        break;
    case 384:
        SymCryptHmacSha384ExpandKey(&context->key.s384, key, length);
        SymCryptHmacSha384Init(&context->state.s384, &context->key.s384);
        break;
    case 512:
        SymCryptHmacSha512ExpandKey(&context->key.s512, key, length);
        SymCryptHmacSha512Init(&context->state.s512, &context->key.s512);
        break;
    }
    return context;
}

void sc_hmac_update(SC_HMAC *context, const uint8_t *data, size_t length)
{
    switch (context->algorithm) {
    case 256: SymCryptHmacSha256Append(&context->state.s256, data, length); break;
    case 384: SymCryptHmacSha384Append(&context->state.s384, data, length); break;
    case 512: SymCryptHmacSha512Append(&context->state.s512, data, length); break;
    }
}

void sc_hmac_finish(SC_HMAC *context, uint8_t *output)
{
    switch (context->algorithm) {
    case 256: SymCryptHmacSha256Result(&context->state.s256, output); break;
    case 384: SymCryptHmacSha384Result(&context->state.s384, output); break;
    case 512: SymCryptHmacSha512Result(&context->state.s512, output); break;
    }
}

void sc_hmac_free(SC_HMAC *context)
{
    if (context != NULL) {
        SymCryptWipe(context, sizeof(*context));
        symcrypt_rs_free(context);
    }
}

uint32_t sc_hkdf_extract(uint32_t algorithm, const uint8_t *salt, size_t salt_length,
                         const uint8_t *input, size_t input_length, uint8_t *output,
                         size_t output_length)
{
    PCSYMCRYPT_MAC mac = mac_algorithm(algorithm);
    if (mac == NULL) {
        return SYMCRYPT_INVALID_ARGUMENT;
    }
    return SymCryptHkdfExtractPrk(mac, input, input_length, salt, salt_length,
                                 output, output_length);
}

uint32_t sc_hkdf_expand(uint32_t algorithm, const uint8_t *prk, size_t prk_length,
                        const uint8_t *info, size_t info_length, uint8_t *output,
                        size_t output_length)
{
    PCSYMCRYPT_MAC mac = mac_algorithm(algorithm);
    if (mac == NULL) {
        return SYMCRYPT_INVALID_ARGUMENT;
    }
    SYMCRYPT_HKDF_EXPANDED_KEY key;
    SYMCRYPT_ERROR status = SymCryptHkdfPrkExpandKey(&key, mac, prk, prk_length);
    if (status == SYMCRYPT_NO_ERROR && output_length != 0) {
        status = SymCryptHkdfDerive(&key, info, info_length, output, output_length);
    }
    SymCryptWipe(&key, sizeof(key));
    return status;
}

typedef struct {
    uint32_t algorithm;
    SYMCRYPT_GCM_EXPANDED_KEY gcm;
    uint8_t chacha[32];
} SC_AEAD;

SC_AEAD *sc_aead_new(uint32_t algorithm, const uint8_t *key, size_t length)
{
    if (!((algorithm == 128 && length == 16) ||
          (algorithm == 256 && length == 32) ||
          (algorithm == 20 && length == 32))) {
        return NULL;
    }
    if (algorithm != 20 && !sc_aes_available()) {
        return NULL;
    }
    SC_AEAD *context = symcrypt_rs_alloc(sizeof(*context), _Alignof(SC_AEAD));
    if (context == NULL) {
        return NULL;
    }
    context->algorithm = algorithm;
    if (algorithm == 20) {
        memcpy(context->chacha, key, length);
    } else {
        SYMCRYPT_ERROR status = SymCryptGcmExpandKey(&context->gcm, SymCryptAesBlockCipher, key, length);
        if (status != SYMCRYPT_NO_ERROR) {
            SymCryptWipe(context, sizeof(*context));
            symcrypt_rs_free(context);
            return NULL;
        }
    }
    return context;
}

void sc_aead_free(SC_AEAD *context)
{
    if (context != NULL) {
        SymCryptWipe(context, sizeof(*context));
        symcrypt_rs_free(context);
    }
}

uint32_t sc_aead_encrypt(const SC_AEAD *key, const uint8_t nonce[12], const uint8_t *aad,
                         size_t aad_length, const uint8_t *input, uint8_t *output,
                         size_t length, uint8_t tag[16])
{
    if (key->algorithm == 20) {
        return SymCryptChaCha20Poly1305Encrypt(key->chacha, 32, nonce, 12, aad, aad_length,
                                             input, output, length, tag, 16);
    }
    SYMCRYPT_ERROR status = SymCryptGcmValidateParameters(SymCryptAesBlockCipher, 12,
                                                        aad_length, length, 16);
    if (status == SYMCRYPT_NO_ERROR) {
        SymCryptGcmEncrypt(&key->gcm, nonce, 12, aad, aad_length, input, output, length, tag, 16);
    }
    return status;
}

uint32_t sc_aead_decrypt(const SC_AEAD *key, const uint8_t nonce[12], const uint8_t *aad,
                         size_t aad_length, const uint8_t *input, uint8_t *output,
                         size_t length, const uint8_t tag[16])
{
    if (key->algorithm == 20) {
        return SymCryptChaCha20Poly1305Decrypt(key->chacha, 32, nonce, 12, aad, aad_length,
                                             input, output, length, tag, 16);
    }
    SYMCRYPT_ERROR status = SymCryptGcmValidateParameters(SymCryptAesBlockCipher, 12,
                                                        aad_length, length, 16);
    if (status == SYMCRYPT_NO_ERROR) {
        status = SymCryptGcmDecrypt(&key->gcm, nonce, 12, aad, aad_length,
                                   input, output, length, tag, 16);
    }
    return status;
}
