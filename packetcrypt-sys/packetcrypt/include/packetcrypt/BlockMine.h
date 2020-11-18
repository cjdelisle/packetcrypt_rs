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
    uint32_t ann_nums[4];
} BlockMine_Res_t;
_Static_assert(sizeof(BlockMine_Res_t) == 24, "");

typedef struct BlockMine_s {
    uint32_t maxAnns;
} BlockMine_t;

typedef void (* BlockMine_Callback_t)(BlockMine_Res_t* res, void* ctx);
BlockMine_t* BlockMine_create(uint64_t maxmem, int threads, BlockMine_Callback_t cb, void* ctx);

void BlockMine_destroy(BlockMine_t* bm);

void BlockMine_updateAnn(const BlockMine_t* bm, uint32_t index, const PacketCrypt_Announce_t* ann);

int64_t BlockMine_getHashesPerSecond(const BlockMine_t* bm);

void BlockMine_mine(BlockMine_t* bm,
    const PacketCrypt_BlockHeader_t* header,
    uint32_t annCount,
    const uint32_t* annIndexes,
    uint32_t effectiveTarget);

#endif