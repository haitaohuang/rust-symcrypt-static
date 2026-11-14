#include <stddef.h>
#include "symcrypt.h"
#include "symcrypt_low_level.h"

uint32_t sc_rsa_generate(uint32_t bits, PSYMCRYPT_RSAKEY *output)
{
    *output = NULL;
    SYMCRYPT_RSA_PARAMS parameters = {1, bits, 2, 1};
    PSYMCRYPT_RSAKEY key = SymCryptRsakeyAllocate(&parameters, 0);
    if (key == NULL) {
        return SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
    }
    SYMCRYPT_ERROR status = SymCryptRsakeyGenerate(key, NULL, 0, SYMCRYPT_FLAG_RSAKEY_SIGN);
    if (status != SYMCRYPT_NO_ERROR) {
        SymCryptRsakeyFree(key);
        return status;
    }
    *output = key;
    return SYMCRYPT_NO_ERROR;
}

uint32_t sc_rsa_import(const uint8_t *modulus, size_t modulus_length, uint64_t exponent,
                       const uint8_t *p, size_t p_length, const uint8_t *q, size_t q_length,
                       PSYMCRYPT_RSAKEY *output)
{
    *output = NULL;
    if (modulus_length < 256 || modulus_length > 1024 ||
        (p_length == 0) != (q_length == 0)) {
        return SYMCRYPT_INVALID_ARGUMENT;
    }
    UINT32 prime_count = p_length == 0 ? 0 : 2;
    SYMCRYPT_RSA_PARAMS parameters = {1, (UINT32)(modulus_length * 8), prime_count, 1};
    PSYMCRYPT_RSAKEY key = SymCryptRsakeyAllocate(&parameters, 0);
    if (key == NULL) {
        return SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
    }
    PCBYTE primes[] = {p, q};
    SIZE_T lengths[] = {p_length, q_length};
    SYMCRYPT_ERROR status = SymCryptRsakeySetValue(
        modulus, modulus_length, &exponent, 1,
        prime_count ? primes : NULL, prime_count ? lengths : NULL, prime_count,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, SYMCRYPT_FLAG_RSAKEY_SIGN, key);
    if (status != SYMCRYPT_NO_ERROR) {
        SymCryptRsakeyFree(key);
        return status;
    }
    *output = key;
    return SYMCRYPT_NO_ERROR;
}

void sc_rsa_free(PSYMCRYPT_RSAKEY key)
{
    SymCryptRsakeyFree(key);
}

uint32_t sc_rsa_check_private_exponent(PCSYMCRYPT_RSAKEY key, const uint8_t *d, size_t length)
{
    SIZE_T size = SymCryptRsakeySizeofModulus(key);
    if (size > 1024 || length == 0 || length > size) {
        return SYMCRYPT_INVALID_ARGUMENT;
    }
    UINT32 digits = SymCryptDigitsFromBits((UINT32)(size * 8));
    SIZE_T scratch_size = SYMCRYPT_MAX(
        SYMCRYPT_SCRATCH_BYTES_FOR_INT_TO_DIVISOR(digits),
        SYMCRYPT_SCRATCH_BYTES_FOR_INT_DIVMOD(digits, digits));
    PSYMCRYPT_INT input = SymCryptIntAllocate(digits);
    PSYMCRYPT_INT expected = SymCryptIntAllocate(digits);
    PSYMCRYPT_INT remainder = SymCryptIntAllocate(digits);
    PSYMCRYPT_DIVISOR divisor = SymCryptDivisorAllocate(digits);
    PBYTE values = SymCryptCallbackAlloc(5 * size);
    PBYTE scratch = SymCryptCallbackAlloc(scratch_size);
    SYMCRYPT_ERROR status = SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
    if (input == NULL || expected == NULL || remainder == NULL || divisor == NULL ||
        values == NULL || scratch == NULL) {
        goto cleanup;
    }
    PBYTE primes[] = {values + size, values + 2 * size};
    PBYTE exponents[] = {values + 3 * size, values + 4 * size};
    SIZE_T lengths[] = {size, size};
    status = SymCryptRsakeyGetValue(
        key, values, size, NULL, 0, primes, lengths, 2, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, 0);
    if (status != SYMCRYPT_NO_ERROR) { goto cleanup; }
    status = SymCryptRsakeyGetCrtValue(
        key, exponents, lengths, 2, NULL, 0, NULL, 0, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, 0);
    if (status != SYMCRYPT_NO_ERROR) { goto cleanup; }
    status = SymCryptIntSetValue(d, length, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, input);
    if (status != SYMCRYPT_NO_ERROR) { goto cleanup; }
    status = SymCryptIntSetValue(values, size, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, expected);
    if (status != SYMCRYPT_NO_ERROR) { goto cleanup; }
    if (SymCryptIntIsEqualUint32(input, 0) || !SymCryptIntIsLessThan(input, expected)) {
        status = SYMCRYPT_INVALID_ARGUMENT;
        goto cleanup;
    }
    // Check exact congruences, not probabilistic prime recovery from e*d-1.
    for (UINT32 i = 0; i < 2; i++) {
        status = SymCryptIntSetValue(primes[i], size, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, expected);
        if (status != SYMCRYPT_NO_ERROR) { goto cleanup; }
        if (SymCryptIntSubUint32(expected, 1, expected) || SymCryptIntIsEqualUint32(expected, 0)) {
            status = SYMCRYPT_INVALID_ARGUMENT;
            goto cleanup;
        }
        SymCryptIntToDivisor(expected, divisor, 1, 0, scratch, scratch_size);
        SymCryptIntDivMod(input, divisor, NULL, remainder, scratch, scratch_size);
        status = SymCryptIntSetValue(exponents[i], size, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, expected);
        if (status != SYMCRYPT_NO_ERROR) { goto cleanup; }
        if (!SymCryptIntIsEqual(remainder, expected)) {
            status = SYMCRYPT_INVALID_ARGUMENT;
            goto cleanup;
        }
    }
cleanup:
    if (input != NULL) { SymCryptIntFree(input); }
    if (expected != NULL) { SymCryptIntFree(expected); }
    if (remainder != NULL) { SymCryptIntFree(remainder); }
    if (divisor != NULL) { SymCryptDivisorFree(divisor); }
    if (values != NULL) { SymCryptWipe(values, 5 * size); SymCryptCallbackFree(values); }
    if (scratch != NULL) { SymCryptWipe(scratch, scratch_size); SymCryptCallbackFree(scratch); }
    return status;
}

uint32_t sc_rsa_export(PCSYMCRYPT_RSAKEY key, uint8_t *modulus, uint64_t *exponent)
{
    return SymCryptRsakeyGetValue(key, modulus, SymCryptRsakeySizeofModulus(key),
                                  exponent, 1, NULL, NULL, 0,
                                  SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, 0);
}

uint32_t sc_rsa_export_private(PCSYMCRYPT_RSAKEY key, uint8_t *p, uint8_t *q,
                               uint8_t *d, uint8_t *dp, uint8_t *dq, uint8_t *coefficient)
{
    SIZE_T size = SymCryptRsakeySizeofModulus(key);
    SIZE_T p_size = SymCryptRsakeySizeofPrime(key, 0);
    SIZE_T q_size = SymCryptRsakeySizeofPrime(key, 1);
    if (p_size > size || q_size > size) {
        return SYMCRYPT_INVALID_ARGUMENT;
    }
    SymCryptWipe(p, size);
    SymCryptWipe(q, size);
    SymCryptWipe(dp, size);
    SymCryptWipe(dq, size);
    SymCryptWipe(coefficient, size);
    PBYTE primes[] = {p + size - p_size, q + size - q_size};
    PBYTE exponents[] = {dp + size - p_size, dq + size - q_size};
    SIZE_T lengths[] = {p_size, q_size};
    SYMCRYPT_ERROR status = SymCryptRsakeyGetValue(
        key, NULL, 0, NULL, 0, primes, lengths, 2, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, 0);
    if (status == SYMCRYPT_NO_ERROR) {
        status = SymCryptRsakeyGetCrtValue(
            key, exponents, lengths, 2, coefficient + size - p_size, p_size, d, size,
            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, 0);
    }
    return status;
}

static PCSYMCRYPT_HASH rsa_hash(uint32_t algorithm, PCSYMCRYPT_OID *oids, size_t *count)
{
    switch (algorithm) {
    case 256:
        *oids = SymCryptSha256OidList;
        *count = SYMCRYPT_SHA256_OID_COUNT;
        return SymCryptSha256Algorithm;
    case 384:
        *oids = SymCryptSha384OidList;
        *count = SYMCRYPT_SHA384_OID_COUNT;
        return SymCryptSha384Algorithm;
    case 512:
        *oids = SymCryptSha512OidList;
        *count = SYMCRYPT_SHA512_OID_COUNT;
        return SymCryptSha512Algorithm;
    default:
        return NULL;
    }
}

uint32_t sc_rsa_sign(PCSYMCRYPT_RSAKEY key, uint32_t algorithm, uint32_t pss,
                     const uint8_t *digest, size_t digest_length, uint8_t *signature)
{
    PCSYMCRYPT_OID oids;
    SIZE_T count;
    PCSYMCRYPT_HASH hash = rsa_hash(algorithm, &oids, &count);
    if (hash == NULL || digest_length != SymCryptHashResultSize(hash)) {
        return SYMCRYPT_INVALID_ARGUMENT;
    }
    SIZE_T size = SymCryptRsakeySizeofModulus(key);
    SIZE_T written = 0;
    SYMCRYPT_ERROR status = pss
        ? SymCryptRsaPssSign(key, digest, digest_length, hash, digest_length, 0,
                            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, signature, size, &written)
        : SymCryptRsaPkcs1Sign(key, digest, digest_length, oids, count, 0,
                              SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, signature, size, &written);
    return status == SYMCRYPT_NO_ERROR && written != size ? SYMCRYPT_INVALID_ARGUMENT : status;
}

uint32_t sc_rsa_verify(PCSYMCRYPT_RSAKEY key, uint32_t algorithm, uint32_t pss,
                       const uint8_t *digest, size_t digest_length, const uint8_t *signature)
{
    PCSYMCRYPT_OID oids;
    SIZE_T count;
    PCSYMCRYPT_HASH hash = rsa_hash(algorithm, &oids, &count);
    if (hash == NULL || digest_length != SymCryptHashResultSize(hash)) {
        return SYMCRYPT_INVALID_ARGUMENT;
    }
    SIZE_T size = SymCryptRsakeySizeofModulus(key);
    return pss
        ? SymCryptRsaPssVerify(key, digest, digest_length, signature, size,
                              SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, hash, digest_length, 0)
        : SymCryptRsaPkcs1Verify(key, digest, digest_length, signature, size,
                                SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, oids, count, 0);
}
