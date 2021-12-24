/**
 * (C) Copyright 2019
 * Caleb James DeLisle
 *
 * SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
 *
 * This is a Library Header File, it is intended to be included in other projects without
 * affecting the license of those projects.
 */
#include "packetcrypt/PacketCrypt.h"
#include "packetcrypt/BlockMine.h"
#include "CryptoCycle.h"
#include "PTime.h"
#include "Work.h"
#include "Hash.h"

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <pthread.h>
#include <signal.h>
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

typedef struct HeaderAndIndex_s {
    PacketCrypt_BlockHeader_t header;
    const uint32_t* index;
} HeaderAndIndex_t;

typedef struct Worker_s Worker_t;

// Fields shared between threads
typedef struct Global_s {
    // Altered while mining, but should not be altering the *same* anns
    // It's the job of the caller to know which slots are taken and which aren't.
    PacketCrypt_Announce_t* anns;

    // Altered only when workers are stopped
    HeaderAndIndex_t hai;
    uint32_t annCount;
    uint32_t maxAnns;
    uint32_t effectiveTarget;
    uint32_t jobNum;

    // Synchronization
    pthread_mutex_t lock;
    pthread_cond_t cond;

    // Set once and left alone
    BlockMine_Callback_t cb;
    void* cbc;
} Global_t;

typedef struct BlockMine_pvt_s {
    BlockMine_t pub;
    uint64_t maxmem;

    Worker_t* workers;
    int numWorkers;

    Global_t g;
} BlockMine_pvt_t;

#ifndef MAP_ANONYMOUS
    #define MAP_ANONYMOUS MAP_ANON
#endif

#define TRY_MAP(maxmem, flags) do { \
    void* ptr = mmap(NULL, maxmem, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|flags, -1, 0); \
    if (ptr != MAP_FAILED) { return ptr; } \
} while (0)

#if defined(_WIN64) || defined(_WIN32)
#define MAP_FAILED NULL
static void* mapBuf(uint64_t maxmem) {
    return malloc(maxmem);
}
static int munmap(void* buf, uint64_t _len) {
    free(buf);
    return 0;
}
#else
#include <sys/mman.h>
static void* mapBuf(uint64_t maxmem) {
    #ifdef MAP_HUGETLB
        #ifdef MAP_HUGE_1GB
            TRY_MAP(maxmem, MAP_HUGETLB|MAP_HUGE_1GB);
        #endif
        #ifdef MAP_HUGE_2MB
            TRY_MAP(maxmem, MAP_HUGETLB|MAP_HUGE_2MB);
        #endif
    #endif
    TRY_MAP(maxmem, 0);
    return MAP_FAILED;
}
#endif

enum ThreadState {
    ThreadState_STOPPED,
    ThreadState_RUNNING,
    ThreadState_SHUTDOWN,
};

struct Worker_s {
    CryptoCycle_State_t pcState;
    CryptoCycle_State_t pcStates[CryptoCycle_PAR_STATES];

    Global_t* g;
    pthread_t thread;

    uint32_t nonceId;
    uint32_t lowNonce;

    sig_atomic_t hashesPerSecond;

    enum ThreadState reqState;
    enum ThreadState workerState;
};

#define HASHES_PER_CYCLE 2000

#define NOISY_LOG_SHARES 0

// Worker
static void mineOpt(Worker_t* w)
{
    Time t;
    Time_BEGIN(t);

    PacketCrypt_BlockHeader_t hdr;
    Buf_OBJCPY(&hdr, &w->g->hai.header);
    hdr.nonce = w->nonceId;

    uint32_t lowNonce = w->lowNonce;

    Buf32_t hdrHash;
    Hash_COMPRESS32_OBJ(&hdrHash, &hdr);

    for (;;) {
        for (uint32_t i = 0; i < HASHES_PER_CYCLE; i += CryptoCycle_PAR_STATES) {
            BlockMine_Res_t res[CryptoCycle_PAR_STATES];
            CryptoCycle_blockMineMulti(
                w->pcStates,
                &hdrHash,
                lowNonce + i,
                w->g->annCount,
                w->g->hai.index,
                (const CryptoCycle_Item_t *) w->g->anns,
                res
            );
            for (int j = 0; j < CryptoCycle_PAR_STATES; j++) {
                if (!Work_check(w->pcStates[j].bytes, w->g->effectiveTarget)) { continue; }

                if (NOISY_LOG_SHARES) {
                    printf("share / %u / %u\n", hdr.nonce, lowNonce);
                    printf("effective target %x\n", w->g->effectiveTarget);
                    for (int i = 0; i < 80; i++) { printf("%02x", ((uint8_t*)&hdr)[i]); }
                    printf("\n");
                    for (int i = 0; i < 32; i++) { printf("%02x", hdrHash.bytes[i]); }
                    printf("\n");
                    for (int j = 0; j < 4; j++) {
                        uint64_t loc = res[j].ann_mlocs[j];
                        printf("%llu - ", (long long unsigned) loc);
                        for (int i = 0; i < 32; i++) { printf("%02x", ((uint8_t*)&w->g->anns[loc])[i]); }
                        printf("\n");
                    }
                }

                res[j].low_nonce = lowNonce;
                res[j].high_nonce = hdr.nonce;
                //Buf_OBJCPY(&res.hdr, &hdr);
                if (w->g->cb) {
                    w->g->cb(&res[j], w->g->cbc);
                }
                w->lowNonce = lowNonce;
            }
        }
        Time_END(t);
        w->hashesPerSecond = ((HASHES_PER_CYCLE * 1024) / (Time_MICROS(t) / 1024));
        Time_NEXT(t);
        if (w->reqState != ThreadState_RUNNING) {
            w->lowNonce = lowNonce;
            return;
        }
    }
}

// Worker
static void* thread(void* vWorker)
{
    //fprintf(stderr, "Thread [%ld] startup\n", (long)pthread_self());
    Worker_t* w = vWorker;
    pthread_mutex_lock(&w->g->lock);
    for (;;) {
        enum ThreadState rs = w->reqState;
        w->workerState = rs;
        switch (rs) {
            case ThreadState_RUNNING: {
                pthread_mutex_unlock(&w->g->lock);
                mineOpt(w);
                pthread_mutex_lock(&w->g->lock);
                break;
            }
            case ThreadState_STOPPED: {
                pthread_cond_wait(&w->g->cond, &w->g->lock);
                break;
            }
            case ThreadState_SHUTDOWN: {
                pthread_mutex_unlock(&w->g->lock);
                //fprintf(stderr, "Thread [%ld] end\n", (long)pthread_self());
                return NULL;
            }
        }
    }
}

// Main thread
BlockMine_Create_t BlockMine_create(uint64_t maxmem, int threads, BlockMine_Callback_t cb, void* cbc) {
    BlockMine_Create_t bmc = { .miner = NULL, };
    void* ptr = mapBuf(maxmem);
    if (ptr == MAP_FAILED) {
        bmc.stage = "mmap()";
        bmc.err = strerror(errno);
        return bmc;
    }
    BlockMine_pvt_t* out = calloc(sizeof(BlockMine_pvt_t), 1);
    Worker_t* workers = calloc(sizeof(Worker_t), threads);
    if (!out || !workers) {
        bmc.err = strerror(errno);
        bmc.stage = "malloc()";
        assert(!munmap(ptr, maxmem));
        free(out);
        free(workers);
        return bmc;
    }
    uint64_t maxAnns = (maxmem - 80) / 1024;
    while (maxAnns * 1024 + maxAnns * 4 + 80 > maxmem) {
        // make room for the index
        maxAnns--;
    } 

    out->pub.maxAnns = maxAnns;
    out->maxmem = maxmem;
    out->workers = workers;
    out->numWorkers = threads;

    out->g.anns = (PacketCrypt_Announce_t*) ptr;
    out->g.annCount = 0; // set when we begin mining
    out->g.maxAnns = maxAnns;
    out->g.effectiveTarget = 0; // set when we begin mining
    assert(!pthread_mutex_init(&out->g.lock, NULL));
    assert(!pthread_cond_init(&out->g.cond, NULL));
    out->g.cb = cb;
    out->g.cbc = cbc;

    for (int i = 0; i < threads; i++) {
        out->workers[i].g = &out->g;
        out->workers[i].nonceId = i;
        assert(!pthread_create(&out->workers[i].thread, NULL, thread, &out->workers[i]));
    }

    bmc.miner = &out->pub;

    return bmc;
}

// Main thread
static void waitState(BlockMine_pvt_t* ctx, enum ThreadState desiredState) {
    for (int i = 0; i < 100000; i++) {
        enum ThreadState ts = desiredState;
        pthread_mutex_lock(&ctx->g.lock);
        for (int i = 0; i < ctx->numWorkers; i++) {
            ts = ctx->workers[i].workerState;
            if (ts != desiredState) { break; }
        }
        pthread_mutex_unlock(&ctx->g.lock);
        if (ts == desiredState) {
            return;
        }
        Time_nsleep(100000);
    }
    assert(0 && "threads did not stop in 10 secs");
}

// Main thread
static void reqState(BlockMine_pvt_t* ctx, enum ThreadState desiredState) {
    for (int i = 0; i < ctx->numWorkers; i++) {
        ctx->workers[i].reqState = desiredState;
    }
}

// Main thread
void BlockMine_destroy(BlockMine_t* bm) {
    BlockMine_pvt_t* ctx = (BlockMine_pvt_t*) bm;
    pthread_mutex_lock(&ctx->g.lock);
    for (int i = 0; i < ctx->numWorkers; i++) {
        ctx->workers[i].reqState = ThreadState_SHUTDOWN;
    }
    pthread_mutex_unlock(&ctx->g.lock);
    pthread_cond_broadcast(&ctx->g.cond);
    waitState(ctx, ThreadState_SHUTDOWN);
    
    assert(!pthread_cond_destroy(&ctx->g.cond));
    assert(!pthread_mutex_destroy(&ctx->g.lock));
    free(ctx->workers);
    assert(!munmap(ctx->g.anns, ctx->maxmem));
    free(ctx);
}

// Any thread can call this
// But you must not specify an ann index which is currently being mined
void BlockMine_updateAnn(const BlockMine_t* bm, uint32_t index, const uint8_t* ann)
{
    assert(index < bm->maxAnns);
    BlockMine_pvt_t* ctx = (BlockMine_pvt_t*) bm;
    memcpy(&ctx->g.anns[index], ann, 1024);
}

void BlockMine_getAnn(const BlockMine_t* bm, uint32_t index, uint8_t* annOut)
{
    assert(index < bm->maxAnns);
    BlockMine_pvt_t* ctx = (BlockMine_pvt_t*) bm;
    memcpy(annOut, &ctx->g.anns[index], 1024);
}

// Any thread
int64_t BlockMine_getHashesPerSecond(const BlockMine_t* bm) {
    const BlockMine_pvt_t* ctx = (const BlockMine_pvt_t*) bm;
    int64_t out = 0;
    for (int i = 0; i < ctx->numWorkers; i++) {
        out += ctx->workers[i].hashesPerSecond;
    }
    return out;
}

// Main thread
void BlockMine_mine(BlockMine_t* bm,
    const uint8_t* header,
    uint32_t annCount,
    const uint32_t* annIndexes,
    uint32_t effectiveTarget,
    uint32_t jobNum)
{
    BlockMine_pvt_t* ctx = (BlockMine_pvt_t*) bm;
    reqState(ctx, ThreadState_STOPPED);
    waitState(ctx, ThreadState_STOPPED);
    ctx->g.annCount = annCount;
    ctx->g.effectiveTarget = effectiveTarget;
    ctx->g.jobNum = jobNum;
    memcpy(&ctx->g.hai.header, header, sizeof(PacketCrypt_BlockHeader_t));
    ctx->g.hai.index = annIndexes;
    reqState(ctx, ThreadState_RUNNING);
    pthread_cond_broadcast(&ctx->g.cond);
}

void BlockMine_requestStop(BlockMine_t* bm) {
    BlockMine_pvt_t* ctx = (BlockMine_pvt_t*) bm;
    reqState(ctx, ThreadState_STOPPED);
}

void BlockMine_awaitStop(BlockMine_t* bm) {
    BlockMine_pvt_t* ctx = (BlockMine_pvt_t*) bm;
    waitState(ctx, ThreadState_STOPPED);
}

void BlockMine_fakeMine(BlockMine_t* bm,
    BlockMine_Res_t* res,
    const uint8_t* header,
    uint32_t annCount,
    const uint32_t* annIndexes)
{
    BlockMine_pvt_t* ctx = (BlockMine_pvt_t*) bm;
    CryptoCycle_State_t pcState;
    PacketCrypt_BlockHeader_t hdr;
    memcpy(&hdr, header, sizeof(PacketCrypt_BlockHeader_t));
    hdr.nonce = 123;
    uint32_t lowNonce = 456;
    Buf32_t hdrHash;
    Hash_COMPRESS32_OBJ(&hdrHash, &hdr);
    for (;;) {
        CryptoCycle_init(&pcState, &hdrHash, ++lowNonce);
        for (int j = 0; j < 4; j++) {
            uint64_t itnum = res->ann_llocs[j] = CryptoCycle_getItemNo(&pcState) % annCount;
            assert(itnum < annCount);
            uint64_t x = res->ann_mlocs[j] = annIndexes[itnum];
            CryptoCycle_Item_t* it = (CryptoCycle_Item_t*) &ctx->g.anns[x];
            CryptoCycle_update(&pcState, it);
        }
        CryptoCycle_smul(&pcState);
        CryptoCycle_final(&pcState);
        if (!Work_check(pcState.bytes, 0x207fffff)) { continue; }
        break;
    }
    res->high_nonce = hdr.nonce;
    res->low_nonce = lowNonce;
}