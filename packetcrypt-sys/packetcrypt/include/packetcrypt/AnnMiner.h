/**
 * (C) Copyright 2019
 * Caleb James DeLisle
 *
 * SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
 *
 * This is a Library Header File, it is intended to be included in other projects without
 * affecting the license of those projects.
 */
#ifndef ANNMINER_H
#define ANNMINER_H

#include "packetcrypt/PacketCrypt.h"

typedef struct AnnMiner_s AnnMiner_t;

typedef void (* AnnMiner_Callback)(void* callback_ctx, uint8_t* ann_buf);

typedef struct AnnMiner_Request_s {
    // the bitcoin format hash target which must be beaten in order to
    // output the resulting announcement.
    uint32_t workTarget;

    // the block number of the most recent block
    uint32_t parentBlockHeight;

    // the hash of the most recent block (for proving the time when the ann was created)
    uint8_t parentBlockHash[32];

    // a 32 byte pubkey, if all zeros then it is considered that the ann need not be signed
    uint8_t signingKey[32];

    // the type of the announcement content
    uint32_t contentType;

    // the length of the content
    uint32_t contentLen;
} AnnMiner_Request_t;
_Static_assert(sizeof(AnnMiner_Request_t) == 80, "");

AnnMiner_t* AnnMiner_create(
    uint32_t minerId,
    int threads,
    void* callback_ctx,
    AnnMiner_Callback ann_found);

/**
 * Begin mining announcements with a particular hash and content type.
 * If the miner is currently mining, it will stop and begin mining the new parameters.
 * Every time an announcement is found, every time an announcement is found, it will
 * be written to fileNo
 *
 * @param ctx the annMiner.
 * @param req a request for mining.
 */
void AnnMiner_start(AnnMiner_t* ctx, AnnMiner_Request_t* req, int version);

/**
 * Stops the announcement miner.
 */
void AnnMiner_stop(AnnMiner_t* miner);

/**
 * Stops the announcement miner (if necessary) and frees relevant resources.
 */
void AnnMiner_free(AnnMiner_t* miner);

#endif
