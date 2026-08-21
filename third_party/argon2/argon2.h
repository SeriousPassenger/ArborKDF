/*
 * Argon2 reference source code package - reference C implementations
 *
 * Copyright 2015
 * Daniel Dinu, Dmitry Khovratovich, Jean-Philippe Aumasson, and Samuel Neves
 *
 * You may use this work under the terms of a Creative Commons CC0 1.0
 * License/Waiver or the Apache Public License 2.0, at your option.
 *
 * This is the ABI subset used by ArborKDF, copied from the upstream public
 * header at blob 3980bb352f2312520c9be0fb3f739ced75e2cd33:
 * https://github.com/P-H-C/phc-winner-argon2/blob/master/include/argon2.h
 */

#ifndef ARGON2_H
#define ARGON2_H

#include <stddef.h>
#include <stdint.h>

#if defined(__cplusplus)
extern "C" {
#endif

#define ARGON2_DEFAULT_FLAGS UINT32_C(0)
#define ARGON2_FLAG_CLEAR_PASSWORD (UINT32_C(1) << 0)

typedef enum Argon2_ErrorCodes {
    ARGON2_OK = 0
} argon2_error_codes;

typedef int (*allocate_fptr)(uint8_t** memory, size_t bytes_to_allocate);
typedef void (*deallocate_fptr)(uint8_t* memory, size_t bytes_to_allocate);

typedef struct Argon2_Context {
    uint8_t* out;
    uint32_t outlen;
    uint8_t* pwd;
    uint32_t pwdlen;
    uint8_t* salt;
    uint32_t saltlen;
    uint8_t* secret;
    uint32_t secretlen;
    uint8_t* ad;
    uint32_t adlen;
    uint32_t t_cost;
    uint32_t m_cost;
    uint32_t lanes;
    uint32_t threads;
    uint32_t version;
    allocate_fptr allocate_cbk;
    deallocate_fptr free_cbk;
    uint32_t flags;
} argon2_context;

typedef enum Argon2_type {
    Argon2_d = 0,
    Argon2_i = 1,
    Argon2_id = 2
} argon2_type;

typedef enum Argon2_version {
    ARGON2_VERSION_10 = 0x10,
    ARGON2_VERSION_13 = 0x13,
    ARGON2_VERSION_NUMBER = ARGON2_VERSION_13
} argon2_version;

int argon2_ctx(argon2_context* context, argon2_type type);
const char* argon2_error_message(int error_code);

#if defined(__cplusplus)
}
#endif

#endif
