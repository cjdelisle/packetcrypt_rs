/**
 * (C) Copyright 2019
 * Caleb James DeLisle
 *
 * SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
 */
#include "CryptoCycle.h"
#include "RandHash.h"
#include "RandGen.h"
#include "Hash.h"
#include "Announce.h"

#include "sodium/crypto_onetimeauth_poly1305.h"
#include "sodium/utils.h"
#include "sodium/crypto_stream_chacha20.h"
#include "sodium/crypto_scalarmult_curve25519.h"

#include <string.h>
#include <assert.h>

__attribute__((always_inline))
static inline void makeFuzzable(CryptoCycle_Header_t* restrict hdr)
{
    memcpy(&hdr->data, hdr->key_high_or_auth, 4);

    CryptoCycle_setVersion(hdr, 0);
    CryptoCycle_setFailed(hdr, 0);

    assert(CryptoCycle_isFailed(hdr) == 0);
    assert(CryptoCycle_getVersion(hdr) == 0);

    // Length must be at least 32 blocks (512 bytes) long
    CryptoCycle_setLength(hdr, CryptoCycle_getLength(hdr) | 32);
}
void CryptoCycle_makeFuzzable(CryptoCycle_Header_t* restrict hdr)
{
    makeFuzzable(hdr);
}

__attribute__((always_inline))
static inline int getLengthAndTruncate(CryptoCycle_Header_t* restrict hdr)
{
    int len = CryptoCycle_getLength(hdr);
    int maxLen = 125 - CryptoCycle_getAddLen(hdr);
    int finalLen = (len > maxLen) ? maxLen : len;
    CryptoCycle_setTruncated(hdr, (finalLen != len));
    CryptoCycle_setLength(hdr, finalLen);
    return finalLen;
}

__attribute__((always_inline))
static inline void crypt(CryptoCycle_State_t* restrict msg)
{
    if (CryptoCycle_getVersion(&msg->hdr) != 0 || CryptoCycle_isFailed(&msg->hdr)) {
        CryptoCycle_setFailed(&msg->hdr, 1);
        return;
    }

    crypto_onetimeauth_poly1305_state state;
    {
        Buf64_t block0 = { .bytes = 0 };
        crypto_stream_chacha20_ietf(block0.bytes, sizeof block0, msg->hdr.nonce, msg->hdr.key_high_or_auth);
        crypto_onetimeauth_poly1305_init(&state, block0.bytes);
        //sodium_memzero(block0, sizeof block0);  
    }

    uint8_t* aead = &((uint8_t*)msg)[sizeof msg->hdr];
    uint64_t aeadLen = CryptoCycle_getAddLen(&msg->hdr) * 16;
    uint64_t msgLen = getLengthAndTruncate(&msg->hdr) * 16;
    int tzc = CryptoCycle_getTrailingZeros(&msg->hdr);
    int azc = CryptoCycle_getAdditionalZeros(&msg->hdr);
    uint8_t* msgContent = &aead[aeadLen];

    int decrypt = CryptoCycle_isDecrypt(&msg->hdr);
    if (decrypt) {
        crypto_onetimeauth_poly1305_update(&state, aead, aeadLen+msgLen);
    }

    crypto_stream_chacha20_ietf_xor_ic(
        msgContent, msgContent, msgLen, msg->hdr.nonce, 1U, msg->hdr.key_high_or_auth);

    if (!decrypt) {
        if (tzc) { memset(&msgContent[msgLen-tzc], 0, tzc); }
        crypto_onetimeauth_poly1305_update(&state, aead, aeadLen+msgLen);
    }

    {
        uint64_t slen[2] = {0};
        slen[0] = ((uint64_t)aeadLen) - azc;
        slen[1] = ((uint64_t)msgLen) - tzc;
        crypto_onetimeauth_poly1305_update(&state, (uint8_t*) slen, 16);
    }
    crypto_onetimeauth_poly1305_final(&state, msg->hdr.key_high_or_auth);
}
void CryptoCycle_crypt(CryptoCycle_State_t* restrict msg)
{
    crypt(msg);
}

__attribute__((always_inline))
static inline void init(
    CryptoCycle_State_t* restrict state,
    const Buf32_t* restrict seed,
    uint64_t nonce)
{
    Hash_expand(state->bytes, sizeof(CryptoCycle_State_t), seed->bytes, 0);
    memcpy(state->hdr.nonce, &nonce, 8);
    makeFuzzable(&state->hdr);
}
void CryptoCycle_init(
    CryptoCycle_State_t* restrict state,
    const Buf32_t* restrict seed,
    uint64_t nonce)
{
    init(state, seed, nonce);
}

__attribute__((always_inline))
static inline void update(
    CryptoCycle_State_t* restrict state,
    const CryptoCycle_Item_t* restrict item)
{
    memcpy(state->sixteens[2].bytes, item, sizeof *item);
    makeFuzzable(&state->hdr);
    crypt(state);
    assert(!CryptoCycle_isFailed(&state->hdr));
}
void CryptoCycle_update(
    CryptoCycle_State_t* restrict state,
    const CryptoCycle_Item_t* restrict item)
{
    update(state, item);
}

__attribute__((always_inline))
static inline void smul(CryptoCycle_State_t* restrict state) {
    uint8_t pubkey[crypto_scalarmult_curve25519_BYTES];
    assert(!crypto_scalarmult_curve25519_base(pubkey, state->thirtytwos[1].bytes));
    assert(!crypto_scalarmult_curve25519(
        state->thirtytwos[2].bytes, state->thirtytwos[0].bytes, pubkey));
}
void CryptoCycle_smul(CryptoCycle_State_t* restrict state) {
    smul(state);
}

__attribute__((always_inline))
static inline void final(CryptoCycle_State_t* restrict state) {
    Hash_compress32(state->bytes, state->bytes, sizeof *state);
}
void CryptoCycle_final(CryptoCycle_State_t* restrict state) {
    final(state);
}

void CryptoCycle_blockMineMulti(
    CryptoCycle_State_t* pcStates,
    const Buf32_t* hdrHash,
    uint32_t nonceBase,
    uint64_t annCount,
    const uint32_t* annIndexes,
    const CryptoCycle_Item_t* anns,
    BlockMine_Res_t* res
) {
    for (int k = 0; k < CryptoCycle_PAR_STATES; k++) {
        init(&pcStates[k], hdrHash, nonceBase + k);
    }
    for (int j = 0; j < 4; j++) {
        for (int k = 0; k < CryptoCycle_PAR_STATES; k++) {
            uint64_t itnum = res[k].ann_llocs[j] = CryptoCycle_getItemNo(&pcStates[k]) % annCount;
            __builtin_prefetch(&annIndexes[itnum]);
        }
        CryptoCycle_Item_t* it[CryptoCycle_PAR_STATES];
        for (int k = 0; k < CryptoCycle_PAR_STATES; k++) {
            uint64_t x = res[k].ann_mlocs[j] = annIndexes[res[k].ann_llocs[j]];
            it[k] = (CryptoCycle_Item_t*) &anns[x];
            __builtin_prefetch(it[k]);
        }
        for (int k = 0; k < CryptoCycle_PAR_STATES; k++) {
            update(&pcStates[k], it[k]);
        }
    }
    CryptoCycle_smul(pcState);
    for (int k = 0; k < CryptoCycle_PAR_STATES; k++) {
        final(&pcStates[k]);
    }
}

void CryptoCycle_annMineMulti(
    CryptoCycle_State_t* pcStates,
    const Buf32_t* hdrHash,
    uint32_t nonceBase,
    const CryptoCycle_Item_t* table,
    int* itemNos
) {
    for (int k = 0; k < CryptoCycle_PAR_STATES; k++) {
        init(&pcStates[k], hdrHash, nonceBase + k);
    }
    for (int i = 0; i < 4; i++) {
        const CryptoCycle_Item_t* it[CryptoCycle_PAR_STATES];
        for (int k = 0; k < CryptoCycle_PAR_STATES; k++) {
            int itemNo = CryptoCycle_getItemNo(&pcStates[k]) % Announce_TABLE_SZ;
            it[k] = &table[itemNo];
            __builtin_prefetch(&table[itemNo]);
            if (i == 3) {
                itemNos[k] = itemNo;
            }
        }
        for (int k = 0; k < CryptoCycle_PAR_STATES; k++) {
            update(&pcStates[k], it[k]);
        }
    }
    for (int k = 0; k < CryptoCycle_PAR_STATES; k++) {
        final(&pcStates[k]);
    }
}