/**
 * (C) Copyright 2020
 * Caleb James DeLisle
 *
 * SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
 *
 * This is a Library Header File, it is intended to be included in other projects without
 * affecting the license of those projects.
 */
#ifndef PROOFTREE_H
#define PROOFTREE_H

#include <stdint.h>

typedef struct {
    uint8_t hash[32];
    uint64_t start;
    uint64_t end;
} ProofTree_Entry_t;
_Static_assert(sizeof(ProofTree_Entry_t) == 32+8+8, "");

typedef struct ProofTree_s ProofTree_t;

ProofTree_t* ProofTree_create(uint32_t maxAnns);
void ProofTree_destroy(ProofTree_t*);

void ProofTree_hashPair(const ProofTree_Entry_t* table, uint64_t odx, uint64_t idx);

uint64_t ProofTree_complete(ProofTree_t* pt, uint8_t* rootHashOut);

void ProofTree_putEntry(ProofTree_t* pt, uint32_t index, const ProofTree_Entry_t* entry);

void ProofTree_prepare2(ProofTree_t* pt, uint64_t totalAnns);

typedef struct ProofTree_Proof_s {
    uint32_t size;
    uint8_t* data;
} ProofTree_Proof_t;
ProofTree_Proof_t* ProofTree_mkProof(
    const ProofTree_Entry_t* table,
    const uint64_t annCount,
    const uint8_t rootHash[32],
    const uint64_t annNumbers[4]
);
void ProofTree_destroyProof(ProofTree_Proof_t*);

ProofTree_Entry_t* ProofTree_getTable(ProofTree_t* pt);
uint64_t ProofTree_capacity(ProofTree_t* pt);

uint64_t PacketCryptProof_entryCount(uint64_t totalAnns);

uint64_t ProofTree_complete2(const ProofTree_Entry_t* table, uint64_t annCountZeroIncl, uint8_t* rootHash);

#endif