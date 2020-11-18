/**
 * (C) Copyright 2019
 * Caleb James DeLisle
 *
 * SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
 */
#include "packetcrypt/ProofTree.h"
#include "PacketCryptProof.h"

#include <stdint.h>
#include <stdlib.h>
#include <assert.h>

struct ProofTree_s {
    PacketCryptProof_Tree_t tree;
};

ProofTree_t* ProofTree_create(uint32_t maxAnns) {
    return (ProofTree_t*) PacketCryptProof_allocTree(maxAnns);
}
void ProofTree_destroy(ProofTree_t* pt) {
    PacketCryptProof_freeTree(&pt->tree);
}

void ProofTree_clear(ProofTree_t* pt) {
    pt->tree.totalAnnsZeroIncluded = 1;
}

void ProofTree_append(ProofTree_t* pt, const uint8_t* hash, uint32_t mloc) {
    memcpy(pt->tree.entries[pt->tree.totalAnnsZeroIncluded].hash.bytes, hash, 32);
    pt->tree.entries[pt->tree.totalAnnsZeroIncluded].start = mloc;
}

uint32_t ProofTree_compute(ProofTree_t* pt, uint8_t* hashOut, uint32_t* mlocOut) {
    uint64_t count = PacketCryptProof_prepareTree(&pt->tree);
    for (uint32_t i = 0; i < count; i++) {
        mlocOut[i] = pt->tree.entries[i].start;
    }
    PacketCryptProof_computeTree(&pt->tree);
    memcpy(hashOut, pt->tree.root.bytes, 32);
    return count;
}

ProofTree_Proof_t* ProofTree_mkProof(ProofTree_t* pt, const uint64_t annNumbers[4]) {
    ProofTree_Proof_t* out = malloc(sizeof(ProofTree_Proof_t*));
    assert(out);
    int size = 0;
    out->data = PacketCryptProof_mkProof(&size, &pt->tree, annNumbers);
    out->size = size;
    return out;
}
void ProofTree_destroyProof(ProofTree_Proof_t* ptp) {
    free(ptp->data);
    free(ptp);
}
