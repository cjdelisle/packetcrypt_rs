/**
 * (C) Copyright 2019
 * Caleb James DeLisle
 *
 * SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
 */
#ifndef VALIDATE_CTX_H
#define VALIDATE_CTX_H

#include "packetcrypt/PacketCrypt.h"
#include "Vec.h"

#include <stdlib.h>
#include <stdint.h>

struct PacketCrypt_ValidateCtx_s {
    uint32_t* memory;

    uint32_t* hashIn;
    uint32_t* hashOut;

    int progLen;

    int hashctr;

    int loopCycle;
    int varCount;

    uint64_t opCtr;

    Vec vars;
    Vec scopes;

    uint32_t progbuf[2048];
};

#endif