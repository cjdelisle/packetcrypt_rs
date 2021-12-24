/**
 * (C) Copyright 2019
 * Caleb James DeLisle
 *
 * SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
 */
#define _POSIX_C_SOURCE 200809L

#include "RandHash.h"
#include "Hash.h"
#include "Buf.h"
#include "CryptoCycle.h"
#include "Work.h"
#include "PTime.h"
#include "Announce.h"
#include "packetcrypt/PacketCrypt.h"
#include "packetcrypt/AnnMiner.h"
#include "Conf.h"
#include "Util.h"
#include "packetcrypt/Validate.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <signal.h>

typedef struct {
    PacketCrypt_AnnounceHdr_t annHdr;
    Buf64_t hash;
} HeaderAndHash_t;

typedef struct {
    CryptoCycle_Item_t table[Announce_TABLE_SZ];

    Announce_Merkle merkle;
    Buf64_t annHash0; // hash(announce || parentBlockHash)
    Buf64_t annHash1; // hash(announce || merkleRoot)

    Buf32_t parentBlockHash;
    char* content;
    HeaderAndHash_t hah;
} Job_t;

typedef struct Worker_s Worker_t;
struct AnnMiner_s {
    int numWorkers;
    Worker_t* workers;

    HeaderAndHash_t hah;

    bool active;
    uint32_t minerId;

    void* callback_ctx;
    AnnMiner_Callback ann_found;

    struct timeval startTime;

    pthread_mutex_t lock;
    pthread_cond_t cond;
};

enum ThreadState {
    ThreadState_STOPPED,
    ThreadState_RUNNING,
    ThreadState_SHUTDOWN
};

struct Worker_s {
    //Job_t* activeJob;
    Job_t job;

    Announce_t ann;
    CryptoCycle_State_t state;
    CryptoCycle_State_t states[CryptoCycle_PAR_STATES];
    PacketCrypt_ValidateCtx_t* vctx;

    AnnMiner_t* ctx;
    pthread_t thread; 

    uint32_t workerNum;

    int softNonce;
    int softNonceMax;

    _Atomic uintptr_t cycles;
    _Atomic enum ThreadState reqState;
    _Atomic enum ThreadState workerState;
};

static inline void setRequestedState(AnnMiner_t* ctx, Worker_t* w, enum ThreadState ts) {
    (void)(ctx);
    w->reqState = ts;
}
static inline enum ThreadState getRequestedState(Worker_t* w) {
    return w->reqState;
}
static inline void setState(Worker_t* w, enum ThreadState ts) {
    w->workerState = ts;
}
static inline enum ThreadState getState(AnnMiner_t* ctx, Worker_t* w) {
    (void)(ctx);
    return w->workerState;
}

static AnnMiner_t* allocCtx(int numWorkers)
{
    AnnMiner_t* ctx = calloc(sizeof(AnnMiner_t), 1);
    assert(ctx);
    assert(!pthread_mutex_init(&ctx->lock, NULL));
    assert(!pthread_cond_init(&ctx->cond, NULL));

    ctx->numWorkers = numWorkers;
    ctx->workers = calloc(sizeof(Worker_t), numWorkers);
    assert(ctx->workers);
    for (int i = 0; i < numWorkers; i++) {
        ctx->workers[i].ctx = ctx;
        ctx->workers[i].vctx = ValidateCtx_create();
    }
    return ctx;
}
static void freeCtx(AnnMiner_t* ctx)
{
    for (int i = 0; i < ctx->numWorkers; i++) {
        ValidateCtx_destroy(ctx->workers[i].vctx);
    }
    assert(!pthread_cond_destroy(&ctx->cond));
    assert(!pthread_mutex_destroy(&ctx->lock));
    free(ctx->workers);
    free(ctx);
}

static void populateTable(CryptoCycle_Item_t* table, Buf64_t* annHash0) {
    for (int i = 0; i < Announce_TABLE_SZ; i++) {
        Announce_mkitem(i, &table[i], &annHash0->thirtytwos[0]);
    }
}

// -1 means try again
static int populateTable2(Worker_t* w, Buf64_t* seed) {
    if (Announce_createProg(w->vctx, &seed->thirtytwos[0])) {
        return -1;
    }
    for (int i = 0; i < Announce_TABLE_SZ; i++) {
        // Allow this to be interrupted in case we should stop
        if (getRequestedState(w) != ThreadState_RUNNING) { return -1; }
        if (Announce_mkitem2(i, &w->job.table[i], &seed->thirtytwos[1], w->vctx)) {
            return -1;
        }
    }
    return 0;
}

#define HASHES_PER_CYCLE 16

__attribute__((always_inline))
static inline void searchOpt(Worker_t* restrict w) {
    int nonce = w->softNonce;
    uint32_t target = w->job.hah.annHdr.workBits;
    for (int i = 0; i < HASHES_PER_CYCLE; i += CryptoCycle_PAR_STATES) {
        int itemNos[CryptoCycle_PAR_STATES] = {0};
        CryptoCycle_annMineMulti(
            w->states,
            &w->job.annHash1.thirtytwos[0],
            nonce,
            w->job.table,
            itemNos
        );
        for (int i = 0; i < CryptoCycle_PAR_STATES; i++) {
            if (!Work_check(w->states[i].bytes, target)) { continue; }
            int n = nonce + i;
            //if (w->ctx->test) { Hash_printHex(w->state.bytes, 32); }

            Buf_OBJCPY(&w->ann.hdr, &w->job.hah.annHdr);
            Buf_OBJCPY_LDST(w->ann.hdr.softNonce, &n);
            Announce_Merkle_getBranch(&w->ann.merkleProof, itemNos[i], &w->job.merkle);
            if (w->job.hah.annHdr.version > 0) {
                Buf_OBJSET(w->ann.lastAnnPfx, 0);
                Announce_crypt(&w->ann, &w->states[i]);
                //Hash_eprintHex((uint8_t*)&w->ann, 1024);
            } else {
                Buf_OBJCPY_LDST(w->ann.lastAnnPfx, &w->job.table[itemNos[i]]);
            }
            w->ctx->ann_found(w->ctx->callback_ctx, (uint8_t*) &w->ann);
        }
        nonce += CryptoCycle_PAR_STATES;
        //printf("itemNo %d\n", itemNo);
    }
    w->cycles++;
    w->softNonce = nonce;
}

// If this returns non-zero then it failed, -1 means try again
static int getNextJob(Worker_t* w) {
    uint32_t hn = w->job.hah.annHdr.hardNonce;
    w->job.hah.annHdr.hardNonce = w->ctx->hah.annHdr.hardNonce;
    if (Buf_OBJCMP(&w->job.hah.annHdr, &w->ctx->hah.annHdr)) {
        Buf_OBJCPY(&w->job.hah, &w->ctx->hah);
        w->job.hah.annHdr.hardNonce += w->workerNum;
    } else {
        // Always put back the hash because it gets mangled during the mining process
        Buf_OBJCPY(&w->job.hah.hash, &w->ctx->hah.hash);
        w->job.hah.annHdr.hardNonce = hn + w->ctx->numWorkers;
    }
    Hash_COMPRESS64_OBJ(&w->job.annHash0, &w->job.hah);

    if (w->job.hah.annHdr.version > 0) {
        int pt = populateTable2(w, &w->job.annHash0);
        if (pt) { return pt; }
    } else {
        populateTable(w->job.table, &w->job.annHash0);
    }
    Announce_Merkle_build(&w->job.merkle, (uint8_t*)w->job.table, sizeof *w->job.table);

    Buf64_t* root = Announce_Merkle_root(&w->job.merkle);
    Buf_OBJCPY(&w->job.parentBlockHash, &w->job.hah.hash.thirtytwos[0]);
    Buf_OBJCPY(&w->job.hah.hash, root);
    Hash_COMPRESS64_OBJ(&w->job.annHash1, &w->job.hah);

    w->softNonceMax = Util_annSoftNonceMax(w->job.hah.annHdr.workBits);
    w->softNonce = 0;
    if (w->job.hah.annHdr.version > 0) {
        Buf64_t b[2];
        Buf_OBJCPY(&b[0], root);
        Buf_OBJCPY(&b[1], &w->job.annHash0);
        Hash_COMPRESS64_OBJ(&b[0], &b);
        int pt = populateTable2(w, &b[0]);
        if (pt) { return pt; }
    }
    return 0;
}

static bool checkStop(Worker_t* worker) {
    if (getRequestedState(worker) == ThreadState_RUNNING) {
        // This is checking a non-atomic memory address without synchronization
        // but if we don't read the most recent data, it doesn't matter, we'll
        // be back in 512 more cycles.
        return false;
    }
    pthread_mutex_lock(&worker->ctx->lock);
    for (;;) {
        enum ThreadState rts = getRequestedState(worker);
        if (rts != ThreadState_STOPPED) {
            setState(worker, rts);
            pthread_mutex_unlock(&worker->ctx->lock);
            if (rts == ThreadState_SHUTDOWN) {
                return true;
            }
            return false;
        }
        setState(worker, rts);
        pthread_cond_wait(&worker->ctx->cond, &worker->ctx->lock);
        worker->cycles = 0;
    }
}

static void* thread(void* vworker) {
    Worker_t* worker = vworker;
    for (;;) {
        if (checkStop(worker)) { return NULL; }
        if (worker->softNonce + HASHES_PER_CYCLE > worker->softNonceMax) {
            int x = 0;
            do {
                x = getNextJob(worker);
                if (checkStop(worker)) { return NULL; }
            } while (x);
        }
        searchOpt(worker);
    }
}

static bool threadsStopped(AnnMiner_t* ctx) {
    for (int i = 0; i < ctx->numWorkers; i++) {
        enum ThreadState ts = getState(ctx, &ctx->workers[i]);
        if (ts == ThreadState_RUNNING) { return false; }
    }
    return true;
}

static void stopThreads(AnnMiner_t* ctx) {
    for (int i = 0; i < ctx->numWorkers; i++) {
        setRequestedState(ctx, &ctx->workers[i], ThreadState_STOPPED);
    }
}

void AnnMiner_start(AnnMiner_t* ctx, AnnMiner_Request_t* req, int version) {
    stopThreads(ctx);
    while (!threadsStopped(ctx)) { Time_nsleep(100000); }
    assert(version == 0 || version == 1);

    HeaderAndHash_t hah;
    Buf_OBJSET(&hah, 0);
    hah.annHdr.version = version;
    hah.annHdr.hardNonce = ctx->minerId;
    hah.annHdr.workBits = req->workTarget;
    hah.annHdr.parentBlockHeight = req->parentBlockHeight;
    hah.annHdr.contentType = req->contentType;
    hah.annHdr.contentLength = req->contentLen;
    Buf_OBJCPY(hah.annHdr.signingKey, req->signingKey);

    Buf_OBJCPY(&hah.hash.thirtytwos[0], req->parentBlockHash);

    // if we're called with identical data, we should not reset the workers
    // because that will cause multiple searches of the same nonce space.
    if (Buf_OBJCMP(&ctx->hah, &hah)) {
        Buf_OBJCPY(&ctx->hah, &hah);
        for (int i = 0; i < ctx->numWorkers; i++) {
            // Trigger the workers to rebuild the work immediately
            ctx->workers[i].softNonceMax = 0;
        }
    }

    for (int i = 0; i < ctx->numWorkers; i++) {
        setRequestedState(ctx, &ctx->workers[i], ThreadState_RUNNING);
    }
    gettimeofday(&ctx->startTime, NULL);
    pthread_cond_broadcast(&ctx->cond);

    ctx->active = true;
    return;
}

AnnMiner_t* AnnMiner_create(
    uint32_t minerId,
    int threads,
    void* callback_ctx,
    AnnMiner_Callback ann_found)
{
    assert(threads);
    AnnMiner_t* ctx = allocCtx(threads);
    ctx->minerId = minerId;
    ctx->ann_found = ann_found;
    ctx->callback_ctx = callback_ctx;

    for (int i = 0; i < threads; i++) {
        ctx->workers[i].workerNum = i;
        assert(!pthread_create(&ctx->workers[i].thread, NULL, thread, &ctx->workers[i]));
    }
    return ctx;
}

void AnnMiner_stop(AnnMiner_t* ctx)
{
    ctx->active = false;
    stopThreads(ctx);
    while (!threadsStopped(ctx)) { Time_nsleep(100000); }
}

void AnnMiner_free(AnnMiner_t* ctx)
{
    for (int i = 0; i < ctx->numWorkers; i++) {
        setRequestedState(ctx, &ctx->workers[i], ThreadState_SHUTDOWN);
    }
    pthread_cond_broadcast(&ctx->cond);
    while (!threadsStopped(ctx)) { Time_nsleep(100000); }

    for (int i = 0; i < ctx->numWorkers; i++) {
        assert(!pthread_join(ctx->workers[i].thread, NULL));
    }

    freeCtx(ctx);
}

double AnnMiner_hashesPerSecond(AnnMiner_t* ctx)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct timeval tv0 = ctx->startTime;
    uint64_t micros = ((uint64_t)tv.tv_sec - tv0.tv_sec) * 1000000ull + tv.tv_usec - tv0.tv_usec;
    ctx->startTime = tv;

    uint64_t totalCycles = 0;
    for (int i = 0; i < ctx->numWorkers; i++) {
        totalCycles += ctx->workers[i].cycles;
        ctx->workers[i].cycles = 0;
    }
    double hashes = (double) (totalCycles * HASHES_PER_CYCLE); // total hashes done
    hashes /= (double) micros;
    hashes *= 1000000.0;
    return hashes;
}