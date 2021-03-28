/**
 * (C) Copyright 2019
 * Caleb James DeLisle
 *
 * SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
 */
#ifndef PACKETCRYPTPROOF_H
#define PACKETCRYPTPROOF_H
#include "Buf.h"
#include "Hash.h"
#include "packetcrypt/PacketCrypt.h"

#include <stdint.h>


typedef struct {
    Buf32_t hash;
    uint64_t start;
    uint64_t end;
} Entry_t;
_Static_assert(sizeof(Entry_t) == 32+8+8, "");

typedef struct {
    uint64_t totalAnnsZeroIncluded;
    Buf32_t root;
    Entry_t zeroEntry;
    Entry_t entries[];
} PacketCryptProof_Tree_t;
_Static_assert(sizeof(PacketCryptProof_Tree_t) == 8+32+sizeof(Entry_t), "");

typedef struct {
    uint64_t totalAnns;
    Buf32_t root;
    Entry_t entries[];
} PacketCryptProof_Tree2_t;
_Static_assert(sizeof(PacketCryptProof_Tree2_t) == sizeof(PacketCryptProof_Tree_t) - sizeof(Entry_t), "");

uint64_t PacketCryptProof_entryCount(uint64_t totalAnns);

PacketCryptProof_Tree_t* PacketCryptProof_allocTree(uint64_t totalAnns);

void PacketCryptProof_freeTree(PacketCryptProof_Tree_t* bm);

// sizeOut is assigned to the length, freeable using free()
uint8_t* PacketCryptProof_mkProof(
    int* sizeOut,
    const PacketCryptProof_Tree_t* tree,
    const uint64_t annNumbers[static PacketCrypt_NUM_ANNS]
);

// returns zero if the hash is valid
int PacketCryptProof_hashProof(
    Buf32_t* hashOut,
    const Buf32_t annHashes[static PacketCrypt_NUM_ANNS],
    uint64_t totalAnns,
    const uint64_t annIndexes[static PacketCrypt_NUM_ANNS],
    const uint8_t* cpcp, int cpcpSize
);

#endif
