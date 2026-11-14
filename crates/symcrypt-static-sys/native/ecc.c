#include <stddef.h>
#include "symcrypt.h"

extern void *symcrypt_rs_alloc(size_t size, size_t alignment);
extern void symcrypt_rs_free(void *pointer);

typedef struct {
    PSYMCRYPT_ECURVE curve;
    PSYMCRYPT_ECKEY key;
    size_t scalar_length;
} SC_EC;

void sc_ec_free(SC_EC *key)
{
    if (key != NULL) {
        if (key->key != NULL) {
            SymCryptEckeyFree(key->key);
        }
        if (key->curve != NULL) {
            SymCryptEcurveFree(key->curve);
        }
        SymCryptWipe(key, sizeof(*key));
        symcrypt_rs_free(key);
    }
}

static SC_EC *ec_new(uint32_t curve)
{
    PCSYMCRYPT_ECURVE_PARAMS parameters;
    switch (curve) {
    case 256: parameters = SymCryptEcurveParamsNistP256; break;
    case 384: parameters = SymCryptEcurveParamsNistP384; break;
    default: return NULL;
    }
    SC_EC *result = symcrypt_rs_alloc(sizeof(*result), _Alignof(SC_EC));
    if (result == NULL) {
        return NULL;
    }
    result->scalar_length = curve / 8;
    result->curve = SymCryptEcurveAllocate(parameters, 0);
    if (result->curve != NULL) {
        result->key = SymCryptEckeyAllocate(result->curve);
    }
    if (result->key == NULL) {
        sc_ec_free(result);
        return NULL;
    }
    return result;
}

uint32_t sc_ec_generate(uint32_t curve, SC_EC **output)
{
    *output = NULL;
    SC_EC *key = ec_new(curve);
    if (key == NULL) {
        return SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
    }
    SYMCRYPT_ERROR status = SymCryptEckeySetRandom(
        SYMCRYPT_FLAG_ECKEY_ECDSA | SYMCRYPT_FLAG_ECKEY_ECDH, key->key);
    if (status != SYMCRYPT_NO_ERROR) {
        sc_ec_free(key);
        return status;
    }
    *output = key;
    return SYMCRYPT_NO_ERROR;
}

uint32_t sc_ec_import(uint32_t curve, const uint8_t *input, size_t length,
                      uint32_t private_key, SC_EC **output)
{
    *output = NULL;
    if ((curve != 256 && curve != 384) ||
        length != (private_key ? curve / 8 : curve / 4)) {
        return SYMCRYPT_INVALID_ARGUMENT;
    }
    SC_EC *key = ec_new(curve);
    if (key == NULL) {
        return SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
    }
    SYMCRYPT_ERROR status = SymCryptEckeySetValue(
        private_key ? input : NULL, private_key ? length : 0,
        private_key ? NULL : input, private_key ? 0 : length,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, SYMCRYPT_ECPOINT_FORMAT_XY,
        SYMCRYPT_FLAG_ECKEY_ECDSA | SYMCRYPT_FLAG_ECKEY_ECDH, key->key);
    if (status == SYMCRYPT_NO_ERROR && private_key) {
        // Native import reduces modulo the group order; the Rust API rejects noncanonical scalars.
        uint8_t canonical[48];
        status = SymCryptEckeyGetValue(key->key, canonical, length, NULL, 0,
                                      SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                                      SYMCRYPT_ECPOINT_FORMAT_XY, 0);
        if (status == SYMCRYPT_NO_ERROR && !SymCryptEqual(input, canonical, length)) {
            status = SYMCRYPT_INVALID_ARGUMENT;
        }
        SymCryptWipe(canonical, sizeof(canonical));
    }
    if (status != SYMCRYPT_NO_ERROR) {
        sc_ec_free(key);
        return status;
    }
    *output = key;
    return SYMCRYPT_NO_ERROR;
}

uint32_t sc_ec_export(const SC_EC *key, uint8_t *output, uint32_t private_key)
{
    return SymCryptEckeyGetValue(
        key->key, private_key ? output : NULL, private_key ? key->scalar_length : 0,
        private_key ? NULL : output, private_key ? 0 : 2 * key->scalar_length,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, SYMCRYPT_ECPOINT_FORMAT_XY, 0);
}

uint32_t sc_ec_sign(const SC_EC *key, const uint8_t *digest, size_t length, uint8_t *signature)
{
    return SymCryptEcDsaSign(key->key, digest, length, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, 0,
                            signature, 2 * key->scalar_length);
}

uint32_t sc_ec_verify(const SC_EC *key, const uint8_t *digest, size_t length,
                      const uint8_t *signature)
{
    return SymCryptEcDsaVerify(key->key, digest, length, signature, 2 * key->scalar_length,
                              SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, 0);
}

uint32_t sc_ec_agree(const SC_EC *key, const SC_EC *peer, uint8_t *output)
{
    if (key->scalar_length != peer->scalar_length) {
        return SYMCRYPT_INVALID_ARGUMENT;
    }
    return SymCryptEcDhSecretAgreement(key->key, peer->key, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                                      0, output, key->scalar_length);
}
