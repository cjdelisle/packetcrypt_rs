/**
 * (C) Copyright 2019
 * Caleb James DeLisle
 *
 * SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
 *
 * This is a Library Header File, it is intended to be included in other projects without
 * affecting the license of those projects.
 */
#ifndef BLOCKMINE_H
#define BLOCKMINE_H

#include "packetcrypt/PacketCrypt.h"

#include <stdint.h>
#include <stdbool.h>

typedef struct BlockMine_Res_s {
    uint32_t high_nonce;
    uint32_t low_nonce;

    // Memory locations of anns
    uint32_t ann_mlocs[4];

    // Logical locatiosn of anns
    uint32_t ann_llocs[4];

    uint32_t job_num;
} BlockMine_Res_t;
_Static_assert(sizeof(BlockMine_Res_t) == 44, "");

typedef struct BlockMine_s {
    uint32_t maxAnns;
} BlockMine_t;

typedef struct BlockMine_Create_s {
    const char* err;
    const char* stage;
    BlockMine_t* miner;
} BlockMine_Create_t;

typedef void (* BlockMine_Callback_t)(BlockMine_Res_t* res, void* ctx);
BlockMine_Create_t BlockMine_create(uint64_t maxmem, int threads, BlockMine_Callback_t cb, void* cbc);

void BlockMine_destroy(BlockMine_t* bm);

void BlockMine_updateAnn(const BlockMine_t* bm, uint32_t mloc, const uint8_t* ann);

void BlockMine_getAnn(const BlockMine_t* bm, uint32_t mloc, uint8_t* annOut);

int64_t BlockMine_getHashesPerSecond(const BlockMine_t* bm);

void BlockMine_mine(BlockMine_t* bm,
    const uint8_t* header,
    uint32_t annCount,
    const uint32_t* annIndexes,
    uint32_t effectiveTarget,
    uint32_t jobNum);

void BlockMine_stop(BlockMine_t* bm);

void BlockMine_fakeMine(BlockMine_t* bm,
    BlockMine_Res_t* resOut,
    const uint8_t* header,
    uint32_t annCount,
    const uint32_t* annIndexes);

#endif