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

typedef struct ProofTree_s ProofTree_t;

ProofTree_t* ProofTree_create(uint32_t maxAnns);
void ProofTree_destroy(ProofTree_t*);

void ProofTree_clear(ProofTree_t*);

void ProofTree_append(ProofTree_t*, const uint8_t* hash, uint32_t mloc);

uint32_t ProofTree_compute(ProofTree_t*, uint8_t* hashOut, uint32_t* mlocOut);

typedef struct ProofTree_Proof_s {
    uint32_t size;
    uint8_t* data;
} ProofTree_Proof_t;
ProofTree_Proof_t* ProofTree_mkProof(ProofTree_t*, const uint64_t annNumbers[4]);
void ProofTree_destroyProof(ProofTree_Proof_t*);

#endif