/**
 * (C) Copyright 2019
 * Caleb James DeLisle
 *
 * SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
 */
#include "packetcrypt/ProofTree.h"
#include "PacketCryptProof.h"
#include "Hash.h"

#include <stdint.h>
#include <stdlib.h>
#include <assert.h>

struct ProofTree_s {
    PacketCryptProof_Tree2_t tree;
};

ProofTree_t* ProofTree_create(uint32_t maxAnns) {
    PacketCryptProof_Tree2_t* tree = PacketCryptProof_allocTree(maxAnns);
    tree->totalAnnsZeroIncluded = 1;
    return (ProofTree_t*) tree;
}
void ProofTree_destroy(ProofTree_t* pt) {
    PacketCryptProof_freeTree(&pt->tree);
}

void ProofTree_clear(ProofTree_t* pt) {
    pt->tree.totalAnnsZeroIncluded = 1;
}

void ProofTree_hashPair(ProofTree_t* pt, uint64_t odx, uint64_t idx)
{
    struct TwoEntries { Entry_t e[2]; };
    Hash_COMPRESS32_OBJ(&pt->tree.entries[odx].hash, (struct TwoEntries*)(&pt->tree.entries[idx]));
    pt->tree.entries[odx].start = pt->tree.entries[idx].start;
    pt->tree.entries[odx].end = pt->tree.entries[idx+1].end;
    assert(pt->tree.entries[idx].end > pt->tree.entries[idx].start);
    assert(pt->tree.entries[idx+1].end > pt->tree.entries[idx+1].start || (
        pt->tree.entries[idx+1].start == UINT64_MAX &&
        pt->tree.entries[idx+1].end == UINT64_MAX));
}

uint64_t ProofTree_complete(ProofTree_t* pt, uint8_t* rootHash)
{
    uint64_t odx = PacketCryptProof_entryCount(pt->tree.totalAnnsZeroIncluded);
    Hash_COMPRESS32_OBJ(&pt->tree.root, &pt->tree.entries[odx - 1]);
    memcpy(rootHash, pt->tree.root.bytes, 32);
    return odx;
}

ProofTree_Entry_t* ProofTree_getEntry(const ProofTree_t* pt, uint32_t index)
{
    return (ProofTree_Entry_t*) &pt->tree.entries[index];
}

void ProofTree_setTotalAnnsZeroIncluded(ProofTree_t* pt, uint32_t total) {
    pt->tree.totalAnnsZeroIncluded = total;
}

uint32_t ProofTree_compute(ProofTree_t* pt, uint8_t* hashOut, uint32_t* mlocOut) {
    printf("Prepare tree\n");
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
