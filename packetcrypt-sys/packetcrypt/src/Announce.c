/**
 * (C) Copyright 2019
 * Caleb James DeLisle
 *
 * SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
 */
#include "Announce.h"
#include "Conf.h"
#include "Hash.h"
#include "RandGen.h"
#include "RandHash.h"
#include "ValidateCtx.h"

#include <assert.h>

static inline void memocycle(Buf64_t* buf, int bufcount, int cycles) {
    Buf64_t tmpbuf[2];
    for (int cycle = 0; cycle < cycles; cycle++) {
        for (int i = 0; i < bufcount; i++) {
            int p = (i - 1 + bufcount) % bufcount;
            uint32_t q = buf[p].ints[0] % (bufcount - 1);
            int j = (i + q) % bufcount;
            Buf64_t* mP = &buf[p];
            Buf64_t* mJ = &buf[j];
            for (int k = 0; k < 8; k++) { tmpbuf[0].longs[k] = mP->longs[k]; }
            for (int k = 0; k < 8; k++) { tmpbuf[1].longs[k] = mJ->longs[k]; }
            Hash_compress64(buf[i].bytes, tmpbuf[0].bytes, sizeof tmpbuf);
        }
    }
}
void Announce_mkitem(uint64_t num, CryptoCycle_Item_t* item, Buf32_t* seed) {
    Hash_expand(item->bytes, 64, seed->bytes, num);
    for (uint32_t i = 1; i < Announce_ITEM_HASHCOUNT; i++) {
        Hash_compress64(item->sixtyfours[i].bytes, item->sixtyfours[i-1].bytes, 64);
    }
    memocycle(item->sixtyfours, Announce_ITEM_HASHCOUNT, Conf_AnnHash_MEMOHASH_CYCLES);
}

int Announce_createProg(PacketCrypt_ValidateCtx_t* prog, Buf32_t* seed) {
    Hash_expand((uint8_t*)prog->progbuf, sizeof prog->progbuf, seed->bytes, 0);
    int len = RandGen_generate(prog->progbuf, seed, &prog->vars);
    if (len < 0) {
        return len;
    }
    prog->progLen = len;
    return 0;
}

int Announce_mkitem2(uint64_t num, CryptoCycle_Item_t* item,
    Buf32_t* seed, PacketCrypt_ValidateCtx_t* prog)
{
    CryptoCycle_State_t state;
    CryptoCycle_init(&state, seed, num);
    if (RandHash_interpret(prog, num, &state, 2)) { return -1; }
    CryptoCycle_makeFuzzable(&state.hdr);
    CryptoCycle_crypt(&state);
    assert(!CryptoCycle_isFailed(&state.hdr));
    Buf_OBJCPY_LDST(item, &state);
    return 0;
}

void rh_make_item(uint64_t num, CryptoCycle_Item_t* item, PacketCrypt_ValidateCtx_t* ctx, Buf32_t* seed, rh_jit_program_t* program) {
  CryptoCycle_State_t state; // Working on a buffer of 2048 bytes
  CryptoCycle_init(&state, seed, num);

  rh_run(ctx->progbuf, num, state.sixtyfours[0].ints, state.sixtyfours[16].ints, program);

  CryptoCycle_makeFuzzable(&state.hdr);
  CryptoCycle_crypt(&state);

  Buf_OBJCPY_LDST(item, &state); // Only copy first 1024 bytes of the state to the returned item
}


