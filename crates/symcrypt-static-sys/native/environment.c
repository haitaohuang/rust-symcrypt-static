// Adapted from SymCrypt's generic and POSIX environments.
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.

#include "precomp.h"
#include <stdatomic.h>
#include <stdbool.h>

extern void symcrypt_rs_cpuid(uint32_t leaf, uint32_t subleaf, uint32_t result[4]);
extern _Noreturn void symcrypt_rs_fatal(uint32_t code);
extern void *symcrypt_rs_alloc(size_t size, size_t alignment);
extern void symcrypt_rs_free(void *pointer);
extern int symcrypt_rs_random(uint8_t *buffer, size_t length);

SYMCRYPT_ENVIRONMENT_DEFS(RustStatic)

SYMCRYPT_CPU_FEATURES SYMCRYPT_CALL SymCryptCpuFeaturesNeverPresentEnvRustStatic(void)
{
    return ~(SYMCRYPT_CPU_FEATURE_SSSE3 | SYMCRYPT_CPU_FEATURE_AESNI |
             SYMCRYPT_CPU_FEATURE_PCLMULQDQ | SYMCRYPT_CPU_FEATURE_SAVEXMM_NOFAIL);
}

VOID SYMCRYPT_CALL SymCryptInitEnvRustStatic(UINT32 version)
{
    SymCryptDetectCpuFeaturesByCpuid(0);
    g_SymCryptCpuFeaturesNotPresent |= SymCryptCpuFeaturesNeverPresentEnvRustStatic();
    g_SymCryptCpuFeaturesNotPresent &= ~SYMCRYPT_CPU_FEATURE_SAVEXMM_NOFAIL;
    SymCryptInitEnvCommon(version);
}

_Noreturn VOID SYMCRYPT_CALL SymCryptFatalEnvRustStatic(UINT32 code)
{
    symcrypt_rs_fatal(code);
}

SYMCRYPT_ERROR SYMCRYPT_CALL SymCryptSaveXmmEnvRustStatic(PSYMCRYPT_EXTENDED_SAVE_DATA state)
{
    (void)state;
    // The platform contract requires the caller/interrupt ABI to preserve XMM state.
    return SYMCRYPT_NO_ERROR;
}

VOID SYMCRYPT_CALL SymCryptRestoreXmmEnvRustStatic(PSYMCRYPT_EXTENDED_SAVE_DATA state)
{
    (void)state;
}

SYMCRYPT_ERROR SYMCRYPT_CALL SymCryptSaveYmmEnvRustStatic(PSYMCRYPT_EXTENDED_SAVE_DATA state)
{
    (void)state;
    SymCryptFatal(0x79736d6d);
    return SYMCRYPT_NOT_IMPLEMENTED;
}

VOID SYMCRYPT_CALL SymCryptRestoreYmmEnvRustStatic(PSYMCRYPT_EXTENDED_SAVE_DATA state)
{
    (void)state;
    SymCryptFatal(0x79726d6d);
}

SYMCRYPT_ERROR SYMCRYPT_CALL SymCryptSaveZmmEnvRustStatic(PSYMCRYPT_EXTENDED_SAVE_DATA state)
{
    (void)state;
    SymCryptFatal(0x7a736d6d);
    return SYMCRYPT_NOT_IMPLEMENTED;
}

VOID SYMCRYPT_CALL SymCryptRestoreZmmEnvRustStatic(PSYMCRYPT_EXTENDED_SAVE_DATA state)
{
    (void)state;
    SymCryptFatal(0x7a726d6d);
}

VOID SYMCRYPT_CALL SymCryptTestInjectErrorEnvRustStatic(PBYTE buffer, SIZE_T length)
{
    (void)buffer;
    (void)length;
}

VOID SYMCRYPT_CALL SymCryptCpuidExFuncEnvRustStatic(int info[4], int leaf, int subleaf)
{
    uint32_t result[4];
    symcrypt_rs_cpuid((uint32_t)leaf, (uint32_t)subleaf, result);
    memcpy(info, result, sizeof(result));
}

PVOID SYMCRYPT_CALL SymCryptCallbackAlloc(SIZE_T size)
{
    return symcrypt_rs_alloc(size, SYMCRYPT_ASYM_ALIGN_VALUE);
}

VOID SYMCRYPT_CALL SymCryptCallbackFree(PVOID pointer)
{
    symcrypt_rs_free(pointer);
}

SYMCRYPT_ERROR SYMCRYPT_CALL SymCryptCallbackRandom(PBYTE buffer, SIZE_T length)
{
    // Some native modular-arithmetic callers do not inspect this callback's status.
    if (symcrypt_rs_random(buffer, length) != 0) {
        SymCryptFatal(0x726e6766);
    }
    return SYMCRYPT_NO_ERROR;
}

PVOID SYMCRYPT_CALL SymCryptCallbackAllocateMutexFastInproc(void)
{
    atomic_bool *lock = symcrypt_rs_alloc(sizeof(*lock), _Alignof(atomic_bool));
    if (lock != NULL) {
        atomic_init(lock, false);
    }
    return lock;
}

VOID SYMCRYPT_CALL SymCryptCallbackFreeMutexFastInproc(PVOID lock)
{
    symcrypt_rs_free(lock);
}

VOID SYMCRYPT_CALL SymCryptCallbackAcquireMutexFastInproc(PVOID pointer)
{
    atomic_bool *lock = pointer;
    while (atomic_exchange_explicit(lock, true, memory_order_acquire)) {
        _mm_pause();
    }
}

VOID SYMCRYPT_CALL SymCryptCallbackReleaseMutexFastInproc(PVOID pointer)
{
    atomic_store_explicit((atomic_bool *)pointer, false, memory_order_release);
}
