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

void ProofTree_clear(ProofTree_t*);

void ProofTree_hashPair(ProofTree_t* pt, uint64_t odx, uint64_t idx);

uint64_t ProofTree_complete(ProofTree_t* pt, uint8_t* rootHashOut);

ProofTree_Entry_t* ProofTree_getEntry(const ProofTree_t* pt, uint32_t index);

void ProofTree_putEntry(ProofTree_t* pt, uint32_t index, const ProofTree_Entry_t* entry);

void ProofTree_setTotalAnnsZeroIncluded(ProofTree_t* pt, uint32_t total);

void ProofTree_compute2(ProofTree_t* pt, uint8_t* hashOut);
uint32_t ProofTree_compute(ProofTree_t*, uint8_t* hashOut, uint32_t* mlocOut);

void ProofTree_prepare2(ProofTree_t* pt, uint64_t totalAnns);

void ProofTree_append(ProofTree_t* pt, const uint8_t* hash, uint32_t mloc);

typedef struct ProofTree_Proof_s {
    uint32_t size;
    uint8_t* data;
} ProofTree_Proof_t;
ProofTree_Proof_t* ProofTree_mkProof(ProofTree_t*, const uint64_t annNumbers[4]);
void ProofTree_destroyProof(ProofTree_Proof_t*);

#endif