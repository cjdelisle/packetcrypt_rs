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
    PacketCryptProof_Tree_t* tree = PacketCryptProof_allocTree(maxAnns);
    tree->totalAnnsZeroIncluded = 1;
    return (ProofTree_t*) tree;
}
void ProofTree_destroy(ProofTree_t* pt) {
    PacketCryptProof_freeTree(&pt->tree);
}

void ProofTree_prepare2(ProofTree_t* pt, uint64_t totalAnns)
{
    PacketCryptProof_Tree2_t* tree = (PacketCryptProof_Tree2_t*) &pt->tree;
    // setup the start and end fields
    tree->totalAnns = totalAnns;
    Buf_OBJSET(&tree->entries[totalAnns], 0xff);
    for (uint64_t i = 0; i < totalAnns; i++) {
        tree->entries[i].end = tree->entries[i+1].start;
        assert(tree->entries[i].end > tree->entries[i].start);
    }
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

void ProofTree_hashPair(ProofTree_t* pt, uint64_t odx, uint64_t idx)
{
    PacketCryptProof_Tree2_t* tree = (PacketCryptProof_Tree2_t*) &pt->tree;
    struct TwoEntries { Entry_t e[2]; };
    Hash_COMPRESS32_OBJ(&tree->entries[odx].hash, (struct TwoEntries*)(&tree->entries[idx]));
    tree->entries[odx].start = tree->entries[idx].start;
    tree->entries[odx].end = tree->entries[idx+1].end;
    assert(tree->entries[idx].end > tree->entries[idx].start);
    assert(tree->entries[idx+1].end > tree->entries[idx+1].start || (
        tree->entries[idx+1].start == UINT64_MAX &&
        tree->entries[idx+1].end == UINT64_MAX));
}

uint64_t ProofTree_complete(ProofTree_t* pt, uint8_t* rootHash)
{
    uint64_t odx = PacketCryptProof_entryCount(pt->tree.totalAnnsZeroIncluded);
    PacketCryptProof_Tree2_t* tree = (PacketCryptProof_Tree2_t*) &pt->tree;
    Hash_COMPRESS32_OBJ(&tree->root, &tree->entries[odx - 1]);
    memcpy(rootHash, tree->root.bytes, 32);
    return odx;
}

void ProofTree_putEntry(ProofTree_t* pt, uint32_t index, const ProofTree_Entry_t* entry)
{
    Buf_OBJCPY(&pt->tree.entries[index - 1], entry);
}