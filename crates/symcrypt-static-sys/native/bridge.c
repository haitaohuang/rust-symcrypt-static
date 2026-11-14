#include <stddef.h>
#include "symcrypt.h"

extern void *symcrypt_rs_alloc(size_t size, size_t alignment);
extern void symcrypt_rs_free(void *pointer);

typedef struct {
    uint32_t algorithm;
    SYMCRYPT_HASH_STATE state;
} SC_HASH;

static PCSYMCRYPT_HASH hash_algorithm(uint32_t algorithm)
{
    switch (algorithm) {
    case 256: return SymCryptSha256Algorithm;
    case 384: return SymCryptSha384Algorithm;
    case 512: return SymCryptSha512Algorithm;
    default: return NULL;
    }
}

int sc_aes_available(void);

void sc_init(void)
{
    SymCryptInit();
    SymCryptSha256Selftest();
    SymCryptSha384Selftest();
    SymCryptSha512Selftest();
    SymCryptHmacSha256Selftest();
    SymCryptHmacSha384Selftest();
    SymCryptHmacSha512Selftest();
    SymCryptHkdfSelfTest();
    SymCryptChaCha20Poly1305Selftest();
    if (sc_aes_available()) {
        SymCryptAesSelftest(SYMCRYPT_AES_SELFTEST_BASE | SYMCRYPT_AES_SELFTEST_CTR);
        SymCryptGcmSelftest();
        SymCryptRngAesGenerateSelftest();
    }
}

int sc_aes_available(void)
{
    return SYMCRYPT_CPU_FEATURES_PRESENT(
        SYMCRYPT_CPU_FEATURE_AESNI | SYMCRYPT_CPU_FEATURE_SSSE3 |
        SYMCRYPT_CPU_FEATURE_PCLMULQDQ);
}

void sc_wipe(uint8_t *data, size_t length)
{
    SymCryptWipe(data, length);
}

int sc_equal(const uint8_t *left, const uint8_t *right, size_t length)
{
    return SymCryptEqual(left, right, length);
}

uint32_t sc_hash(uint32_t algorithm, const uint8_t *data, size_t length, uint8_t *output)
{
    PCSYMCRYPT_HASH hash = hash_algorithm(algorithm);
    if (hash == NULL) {
        return SYMCRYPT_INVALID_ARGUMENT;
    }
    SymCryptHash(hash, data, length, output, SymCryptHashResultSize(hash));
    return SYMCRYPT_NO_ERROR;
}

SC_HASH *sc_hash_new(uint32_t algorithm)
{
    PCSYMCRYPT_HASH hash = hash_algorithm(algorithm);
    if (hash == NULL) {
        return NULL;
    }
    SC_HASH *context = symcrypt_rs_alloc(sizeof(*context), _Alignof(SC_HASH));
    if (context != NULL) {
        context->algorithm = algorithm;
        SymCryptHashInit(hash, &context->state);
    }
    return context;
}

void sc_hash_free(SC_HASH *context)
{
    if (context != NULL) {
        SymCryptWipe(context, sizeof(*context));
        symcrypt_rs_free(context);
    }
}

void sc_hash_update(SC_HASH *context, const uint8_t *data, size_t length)
{
    SymCryptHashAppend(hash_algorithm(context->algorithm), &context->state, data, length);
}

void sc_hash_finish(SC_HASH *context, uint8_t *output)
{
    PCSYMCRYPT_HASH hash = hash_algorithm(context->algorithm);
    SymCryptHashResult(hash, &context->state, output, SymCryptHashResultSize(hash));
}

SC_HASH *sc_hash_copy(const SC_HASH *source)
{
    SC_HASH *destination = symcrypt_rs_alloc(sizeof(*destination), _Alignof(SC_HASH));
    if (destination != NULL) {
        destination->algorithm = source->algorithm;
        SymCryptHashStateCopy(hash_algorithm(source->algorithm), &source->state, &destination->state);
    }
    return destination;
}

size_t sc_hash_export_size(uint32_t algorithm)
{
    switch (algorithm) {
    case 256: return SYMCRYPT_SHA256_STATE_EXPORT_SIZE;
    case 384: return SYMCRYPT_SHA384_STATE_EXPORT_SIZE;
    case 512: return SYMCRYPT_SHA512_STATE_EXPORT_SIZE;
    default: return 0;
    }
}

void sc_hash_export(const SC_HASH *context, uint8_t *output)
{
    switch (context->algorithm) {
    case 256: SymCryptSha256StateExport((PCSYMCRYPT_SHA256_STATE)&context->state, output); break;
    case 384: SymCryptSha384StateExport((PCSYMCRYPT_SHA384_STATE)&context->state, output); break;
    case 512: SymCryptSha512StateExport((PCSYMCRYPT_SHA512_STATE)&context->state, output); break;
    }
}

uint32_t sc_hash_import(SC_HASH *context, const uint8_t *input)
{
    switch (context->algorithm) {
    case 256: return SymCryptSha256StateImport((PSYMCRYPT_SHA256_STATE)&context->state, input);
    case 384: return SymCryptSha384StateImport((PSYMCRYPT_SHA384_STATE)&context->state, input);
    case 512: return SymCryptSha512StateImport((PSYMCRYPT_SHA512_STATE)&context->state, input);
    default: return SYMCRYPT_INVALID_ARGUMENT;
    }
}

uint32_t sc_random(const uint8_t seed[48], uint8_t *output, size_t length)
{
    if (!sc_aes_available()) {
        return SYMCRYPT_NOT_IMPLEMENTED;
    }
    SYMCRYPT_RNG_AES_STATE state;
    SymCryptRngAesInstantiateSelftest();
    SYMCRYPT_ERROR status = SymCryptRngAesInstantiate(&state, seed, 48);
    if (status == SYMCRYPT_NO_ERROR) {
        SymCryptRngAesGenerate(&state, output, length);
        SymCryptRngAesUninstantiate(&state);
    }
    SymCryptWipe(&state, sizeof(state));
    return status;
}
