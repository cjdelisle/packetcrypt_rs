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
#include <stdio.h>

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
    tree->entries[0].end = tree->entries[1].start;
    // for (uint64_t i = 0; i < totalAnns; i++) {
    //     tree->entries[i].end = tree->entries[i+1].start;
    //     assert(tree->entries[i].end > tree->entries[i].start);
    // }
}

ProofTree_Proof_t* ProofTree_mkProof(
    const ProofTree_Entry_t* table,
    const uint64_t annCount,
    const uint8_t rootHash[32],
    const uint64_t annNumbers[4]
) {
    ProofTree_Proof_t* out = malloc(sizeof(ProofTree_Proof_t));
    assert(out);
    int size = 0;
    const Entry_t* et = (const Entry_t*) table;
    Buf32_t rootBuf;
    memcpy(&rootBuf, rootHash, 32);
    out->data = PacketCryptProof_mkProof(&size, et, annCount, &rootBuf, annNumbers);
    out->size = size;
    return out;
}
void ProofTree_destroyProof(ProofTree_Proof_t* ptp) {
    free(ptp->data);
    free(ptp);
}

void ProofTree_hashPair(const ProofTree_Entry_t* table, uint64_t odx, uint64_t idx)
{
    Entry_t* et = (Entry_t*) table;
    struct TwoEntries { Entry_t e[2]; };
    Hash_COMPRESS32_OBJ(&et[odx].hash, (struct TwoEntries*)(&et[idx]));
    et[odx].start = et[idx].start;
    et[odx].end = et[idx+1].end;
    if (__builtin_expect(et[idx].end <= et[idx].start, 0)) {
        printf("idx et[%llu].end <= et[%llu].start (%llx <= %llx)\n",
            (unsigned long long)idx, (unsigned long long)idx,
            (unsigned long long)et[idx].end, (unsigned long long)et[idx].start);
        abort();
    }
    if (__builtin_expect(et[odx].end <= et[odx].start, 0)) {
        printf("odx et[%llu].end <= et[%llu].start (%llx <= %llx)\n",
            (unsigned long long)odx, (unsigned long long)odx,
            (unsigned long long)et[odx].end, (unsigned long long)et[odx].start);
        abort();
    }
}

uint64_t ProofTree_complete2(const ProofTree_Entry_t* table, uint64_t annCountZeroIncl, uint8_t* rootHash)
{
    uint64_t odx = PacketCryptProof_entryCount(annCountZeroIncl);
    Buf32_t b;
    Hash_COMPRESS32_OBJ(&b, &table[odx - 1]);
    memcpy(rootHash, b.bytes, 32);
    return odx;
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

ProofTree_Entry_t* ProofTree_getTable(ProofTree_t* pt)
{
    return (ProofTree_Entry_t*) pt->tree.entries;
}