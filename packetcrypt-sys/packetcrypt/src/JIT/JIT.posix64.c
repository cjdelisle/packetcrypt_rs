/*
** This file has been pre-processed with DynASM.
** https://luajit.org/dynasm.html
** DynASM version 1.3.0, DynASM x64 version 1.3.0
** DO NOT EDIT! The original file is in "packetcrypt-sys/packetcrypt/src/JIT/JIT.c".
*/

#line 1 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
#if ((defined(_M_X64) || defined(__amd64__)) != 1)
#error "Wrong DynASM flags used: pass `-D X64` to dynasm.lua as appropriate"
#endif

// RandGen.xyz  - JIT - 2021
// Michel Blanc - contact@randgen.xyz

#include "JIT.h"

#include <string.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/mman.h>
#include <linux/mman.h>

#include "luajit-vendored/dynasm/dasm_proto.h"
#include "luajit-vendored/dynasm/dasm_x86.h"

#include "RandHash.h"

#if !defined(MAP_ANONYMOUS) && defined(MAP_ANON)
#define MAP_ANONYMOUS MAP_ANON
#endif

enum OpCodes {
  OpCode_INVALID_ZERO,

  OpCode_POPCNT8, OpCode_POPCNT16, OpCode_POPCNT32,
  OpCode_CLZ8, OpCode_CLZ16, OpCode_CLZ32,
  OpCode_CTZ8, OpCode_CTZ16, OpCode_CTZ32,

  OpCode_BSWAP16, OpCode_BSWAP32,

  OpCode_ADD8, OpCode_ADD16, OpCode_ADD32,
  OpCode_SUB8, OpCode_SUB16, OpCode_SUB32,
  OpCode_SHLL8, OpCode_SHLL16, OpCode_SHLL32,
  OpCode_SHRL8, OpCode_SHRL16, OpCode_SHRL32,
  OpCode_SHRA8, OpCode_SHRA16, OpCode_SHRA32,
  OpCode_ROTL8, OpCode_ROTL16, OpCode_ROTL32,
  OpCode_MUL8, OpCode_MUL16, OpCode_MUL32,

  OpCode_AND, OpCode_OR, OpCode_XOR,

  OpCode_ADD8C, OpCode_ADD16C, OpCode_ADD32C,
  OpCode_SUB8C, OpCode_SUB16C, OpCode_SUB32C,
  OpCode_MUL8C, OpCode_MUL16C, OpCode_MUL32C,
  OpCode_MULSU8C, OpCode_MULSU16C, OpCode_MULSU32C,
  OpCode_MULU8C, OpCode_MULU16C, OpCode_MULU32C,

  OpCode_ADD64,
  OpCode_SUB64,
  OpCode_SHLL64,
  OpCode_SHRL64,
  OpCode_SHRA64,
  OpCode_ROTL64,
  OpCode_ROTR64,
  OpCode_MUL64,

  OpCode_ADD64C,
  OpCode_SUB64C,
  OpCode_MUL64C,
  OpCode_MULSU64C,
  OpCode_MULU64C,

  OpCode_IN,
  OpCode_MEMORY,

  OpCode_LOOP,
  OpCode_IF_LIKELY,
  OpCode_IF_RANDOM,
  OpCode_JMP,
  OpCode_END,
};

// Setup code sections and init the DynASM state, we're compiling only for x64 CPU arch
//| .arch x64
#if DASM_VERSION != 10300
#error "Version mismatch between DynASM and included encoding engine"
#endif
#line 79 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
//| .section code, imports
#define DASM_SECTION_CODE	0
#define DASM_SECTION_IMPORTS	1
#define DASM_MAXSECTION		2
#line 80 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
//| .globals lbl_
enum {
  lbl_rh_entry,
  lbl_rh_exit,
  lbl_rh_main,
  lbl__MAX
};
#line 81 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"

// Setup shortcuts for x64 calling conventions
//| .define return1, rax
//| .define return2, rdx
//| .define param1,  rdi
//| .define param2,  rsi
//| .define param3,  rdx
//| .define param4,  rcx
//| .define param5,  r8
//| .define param6,  r9

// Main JIT callee-saved registers (we must restore those before exiting the program)
//| .define rhMemory,  r12
//| .define rhHashIn,  r13
//| .define rhHashOut, r14

// Setup stack frame
//| .macro prologue
//|   push rhMemory
//|   push rhHashIn
//|   push rhHashOut
//|   push rax
//|   push rbp
//|   mov  rbp,  rsp
//|   sub  rsp,  stackSize
//|   mov  qword [rbp-scopeCountOffset],    0
//|   mov  qword [rbp-varsCountOffset],     0
//|   mov  qword [rbp-scopeVarCountOffset], 0
//|   mov  qword [rbp-loopCycleOffset],     0
//| .endmacro

// Tear down stack frame
//| .macro epilogue
//|   add rsp, stackSize
//|   leave
//|   pop rax
//|   pop rhHashOut
//|   pop rhHashIn
//|   pop rhMemory
//|   ret
//| .endmacro

typedef struct rh_state_compile
{
    dasm_State* dynasm_state;
    void* labels[lbl__MAX];
    int npc;
    int nextpc;

    uint32_t* tape;
    uint32_t  tapeLength;
} rh_state_compile_t;

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                  MEMORY LAYOUT                                                    //
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                    +----------+---------------------+------+                                      //
//                                    |  INDEX   |         VAR         | SIZE |                                      //
//                                    +----------+---------------------+------+                                      //
//                                    | rbp-8    | scopeCountOffset    |    8 |                                      //
//                                    | rbp-264  | scopeBufferOffset   |  256 |                                      //
//                                    | rbp-272  | varsCountOffset     |    8 |                                      //
//                                    | rbp-2320 | varsBufferOffset    | 2048 |                                      //
//                                    | rbp-2328 | scopeVarCountOffset |    8 |                                      //
//                                    | rbp-2336 | loopCycleOffset     |    8 |                                      //
//                                    | rbp-2344 | hashCountOffset     |    8 |                                      //
//                                    +----------+---------------------+------+                                      //
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

const int scopeCountOffset    = 8;
const int scopeBufferOffset   = 8 + 256;
const int varsCountOffset     = 8 + 256 + 8;
const int varsBufferOffset    = 8 + 256 + 8 + 2048;
const int scopeVarCountOffset = 8 + 256 + 8 + 2048 + 8;
const int loopCycleOffset     = 8 + 256 + 8 + 2048 + 8 + 8;
const int hashCountOffset     = 8 + 256 + 8 + 2048 + 8 + 8 + 8;
const int stackSize           = 8 + 256 + 8 + 2048 + 8 + 8 + 8;

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                INSTRUCTION DECODING                                               //
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#define DecodeInsn_REGA(insn)    (((insn) >>  9) & 0x1ff)
#define DecodeInsn_REGB(insn)    (((insn) >> 20) & 0x1ff)
#define DecodeInsn_HAS_IMM(insn) (((insn) >> 18) & 1)

#define DecodeInsn_MEMORY_CARRY(insn)             (((insn) >> 9) & 15)
#define DecodeInsn_MEMORY_WITH_CARRY(insn, carry) (((insn) & ~(15 << 9)) | (((carry) & 15) << 9))

#define DecodeInsn_MEMORY_STEP(insn) (((insn) >> 13) & 15)
#define DecodeInsn_MEMORY_BASE(insn) ((insn) >> 17)

#define DecodeInsn_OP(insn) ((insn) & 0xff)

static inline int64_t rh_decode_instruction_immediate(uint32_t instruction) {
  if (instruction & (1<<19)) {
    //     1 1
    //     1 0 9 8 7 6 5 4 3 2 1 0
    //    +-+-+-+-+-+-+-+-+-+-+-+-+
    //  0 |S|I|    B    |    A    |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+
    int imm = instruction >> 20;
    int a = imm & ((1<<5)-1); imm >>= 5;
    int b = imm & ((1<<5)-1); imm >>= 5;
    int i = imm & 1;          imm >>= 1;
    int s = imm;

    int64_t big1 = 1;
    uint64_t out = ((((uint64_t)i) << 63) - 1) ^ (big1 << b) ^ (big1 << a);

    // Drop the top bit
    imm <<= 1; imm >>= 1;

    big1 &= s;
    out |= big1 << 63;
    return (int64_t) out;
  }

  return (int64_t)( ((int32_t) instruction) >> 20 );
}

static inline int32_t rh_decode_instruction_immediateLo(uint32_t instruction) {
  return (int32_t) rh_decode_instruction_immediate(instruction);
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                   MEMORY ACCESS                                                   //
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static inline void rh_get_a(rh_state_compile_t* state, uint32_t instruction) {
  dasm_State** Dst = &state->dynasm_state;
  //| lea param1, [rbp-varsBufferOffset]
  dasm_put(Dst, 0, -varsBufferOffset);
#line 215 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"

  // GET A
  //| mov param1, [param1 + (DecodeInsn_REGA(instruction) * 4)]
  dasm_put(Dst, 5, (DecodeInsn_REGA(instruction) * 4));
#line 218 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
}

static inline void rh_get_ab(rh_state_compile_t* state, uint32_t instruction) {
  dasm_State** Dst = &state->dynasm_state;
  //| lea param3, [rbp-varsBufferOffset]
  dasm_put(Dst, 10, -varsBufferOffset);
#line 223 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"

  // GET A
  //| mov param1, [param3 + (DecodeInsn_REGA(instruction) * 4)]
  dasm_put(Dst, 15, (DecodeInsn_REGA(instruction) * 4));
#line 226 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"

  // GET B
  if (DecodeInsn_HAS_IMM(instruction)) {
    //| mov param2, rh_decode_instruction_immediateLo(instruction);
    dasm_put(Dst, 20, rh_decode_instruction_immediateLo(instruction));
#line 230 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
  } else {
    //| mov param2, [param3 + (DecodeInsn_REGB(instruction) * 4)]
    dasm_put(Dst, 25, (DecodeInsn_REGB(instruction) * 4));
#line 232 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
  }
}

static inline void rh_get_a2b2(rh_state_compile_t* state, uint32_t instruction) {
  dasm_State** Dst = &state->dynasm_state;
  //| lea param3, [rbp-varsBufferOffset]
  dasm_put(Dst, 10, -varsBufferOffset);
#line 238 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"

  // GET A2
  //| mov param1, [param3 + (DecodeInsn_REGA(instruction) * 4)]
  //| shl param1, 32
  //| or  param1, [param3 + ((DecodeInsn_REGA(instruction) - 1) * 4)]
  dasm_put(Dst, 30, (DecodeInsn_REGA(instruction) * 4), ((DecodeInsn_REGA(instruction) - 1) * 4));
#line 243 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"

  // GET B2
  if (DecodeInsn_HAS_IMM(instruction)) {
    //| mov param2, rh_decode_instruction_immediate(instruction)
    dasm_put(Dst, 20, rh_decode_instruction_immediate(instruction));
#line 247 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
  } else {
    //| mov param2, [param3 + (DecodeInsn_REGB(instruction) * 4)]
    //| shl param2, 32
    //| or  param2, [param3 + ((DecodeInsn_REGB(instruction) - 1) * 4)]
    dasm_put(Dst, 43, (DecodeInsn_REGB(instruction) * 4), ((DecodeInsn_REGB(instruction) - 1) * 4));
#line 251 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
  }
}

static inline void rh_out_1_var(rh_state_compile_t* state) {
    dasm_State** Dst = &state->dynasm_state;
    //| lea param1, [rbp-varsBufferOffset]
    //| mov param2, [rbp-varsCountOffset]
    dasm_put(Dst, 56, -varsBufferOffset, -varsCountOffset);
#line 258 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"

    //| mov [param1 + param2 * 4], rax
    //| inc qword [rbp-varsCountOffset]
    dasm_put(Dst, 65, -varsCountOffset);
#line 261 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"

    //| inc qword [rbp-scopeVarCountOffset]
    dasm_put(Dst, 69, -scopeVarCountOffset);
#line 263 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
}

static inline void rh_out_2_var(rh_state_compile_t* state) {
    dasm_State** Dst = &state->dynasm_state;
    //| lea param1, [rbp-varsBufferOffset]
    //| mov param2, [rbp-varsCountOffset]
    dasm_put(Dst, 56, -varsBufferOffset, -varsCountOffset);
#line 269 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"

    //| mov [param1 + param2 * 4], r0d
    //| inc param2
    dasm_put(Dst, 75);
#line 272 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"

    //| shr rax, 32
    //| mov [param1 + param2 * 4], rax
    //| inc param2
    dasm_put(Dst, 83);
#line 276 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"

    //| mov [rbp-varsCountOffset], param2
    //| add qword [rbp-scopeVarCountOffset], 2
    dasm_put(Dst, 96, -varsCountOffset, -scopeVarCountOffset);
#line 279 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
}

static inline void rh_out_4_var(rh_state_compile_t* state) {
    dasm_State** Dst = &state->dynasm_state;
    // rdx, rax arrive here
    // return2, return1
    // uint128 [rax, rdx]
    // rax[:4] rax[4:] rdx[:4] rdx[:4]
    //| lea param1, [rbp-varsBufferOffset]
    //| mov param2, [rbp-varsCountOffset]
    dasm_put(Dst, 56, -varsBufferOffset, -varsCountOffset);
#line 289 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"

    //| mov [param1 + param2 * 4], r0d
    //| inc param2
    dasm_put(Dst, 75);
#line 292 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"

    //| shr rax, 32
    //| mov [param1 + param2 * 4], rax
    //| inc param2
    dasm_put(Dst, 83);
#line 296 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"

    //| mov [param1 + param2 * 4], r2d
    //| inc param2
    dasm_put(Dst, 106);
#line 299 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"

    //| shr rdx, 32
    //| mov [param1 + param2 * 4], rdx
    //| inc param2
    dasm_put(Dst, 114);
#line 303 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"

    //| mov [rbp-varsCountOffset], param2
    //| add qword [rbp-scopeVarCountOffset], 4
    dasm_put(Dst, 128, -varsCountOffset, -scopeVarCountOffset);
#line 306 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                 CONTROL STRUCTURES                                                //
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static int rh_main_loop(int pc, rh_state_compile_t* state);

static inline uint32_t rh_branch(int pc, rh_state_compile_t* state) {
  dasm_State** Dst = &state->dynasm_state;

  if(state->nextpc >= state->npc) { // No dynamic label left, increase the amount
    state->npc *= 2;
    dasm_growpc(&state->dynasm_state, state->npc);
  }

  int localPc = state->nextpc;
  state->nextpc += 2;

  //| cmp rax, 0
  //| jz =>localPc
  dasm_put(Dst, 138, localPc);
#line 327 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"

  // Branching
  rh_main_loop(pc + 2, state); // Compute branch at +2 instructions
  //| jmp =>localPc+1
  dasm_put(Dst, 147, localPc+1);
#line 331 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"

  // Not branching
  //| =>localPc:
  dasm_put(Dst, 151, localPc);
#line 334 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
  int ret = rh_main_loop(pc + 1, state); // Compute branch at +1 instruction

  // Exit
  //| =>localPc+1:
  dasm_put(Dst, 151, localPc+1);
#line 338 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
  return ret;
}

static int rh_main_loop(int pc, rh_state_compile_t* state)
{
  dasm_State** Dst = &state->dynasm_state;

  if (pc != 0) {
    //| lea param1, [rbp-varsBufferOffset]
    //| mov param2, [rbp-varsCountOffset]
    //| mov qword   [param1 + param2 * 4], 0
    //| inc qword   [rbp-varsCountOffset]
    dasm_put(Dst, 153, -varsBufferOffset, -varsCountOffset, -varsCountOffset);
#line 350 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"

    //| lea param1, [rbp-scopeBufferOffset]
    //| mov param2, [rbp-scopeCountOffset]
    //| mov param3, [rbp-scopeVarCountOffset]
    //| mov [param1 + param2 * 4], param3
    //| inc qword [rbp-scopeCountOffset]
    dasm_put(Dst, 175, -scopeBufferOffset, -scopeCountOffset, -scopeVarCountOffset, -scopeCountOffset);
#line 356 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"

    //| mov qword [rbp-scopeVarCountOffset], 0
    dasm_put(Dst, 197, -scopeVarCountOffset);
#line 358 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
  }

  for (;; pc++) {
    uint32_t insn = state->tape[pc]; // Fetch instruction to interpret (4 bytes)

    // Interpret the instruction
    switch (DecodeInsn_OP(insn)) { // Last byte is the OpCode
      case OpCode_MEMORY: {
        int base  = DecodeInsn_MEMORY_BASE(insn);  // bits [0-14]  == base
        int step  = DecodeInsn_MEMORY_STEP(insn);  // bits [15-18] == step
        int carry = DecodeInsn_MEMORY_CARRY(insn); // bits [19-22] == carry

        // memoryIndex = (base + ((ctx->loopCycle + carry) * step)) & (RandHash_MEMORY_SZ - 1);
        //| mov  param3, [rbp-loopCycleOffset]
        //| add  param3, carry
        //| imul param3, step
        //| add  param3, base
        //| and  param3, (RandHash_MEMORY_SZ - 1)
        dasm_put(Dst, 206, -loopCycleOffset, carry, step, base, (RandHash_MEMORY_SZ - 1));
#line 376 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"

        //| lea param1, [rbp-varsBufferOffset]
        //| mov param2, [rbp-varsCountOffset]
        dasm_put(Dst, 56, -varsBufferOffset, -varsCountOffset);
#line 379 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"

        //| mov rax, [rhMemory + param3 * 4]
        //| mov [param1 + param2 * 4], rax
        dasm_put(Dst, 227);
#line 382 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"

        //| inc qword [rbp-varsCountOffset]
        //| inc qword [rbp-scopeVarCountOffset]
        dasm_put(Dst, 236, -varsCountOffset, -scopeVarCountOffset);
#line 385 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
        break;
      }

      case OpCode_IN: {
        int index = ((uint32_t)rh_decode_instruction_immediate(insn)) % RandHash_INOUT_SZ;
        //| lea param1, [rbp-varsBufferOffset]
        //| mov param2, [rbp-varsCountOffset]
        dasm_put(Dst, 56, -varsBufferOffset, -varsCountOffset);
#line 392 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"

        //| mov rax, [rhHashIn + index * 4]
        //| mov [param1 + param2 * 4], rax
        dasm_put(Dst, 247, index * 4);
#line 395 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"

        //| inc qword [rbp-varsCountOffset]
        //| inc qword [rbp-scopeVarCountOffset]
        dasm_put(Dst, 236, -varsCountOffset, -scopeVarCountOffset);
#line 398 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
        break;
      }

      case OpCode_LOOP: {
        const int count = rh_decode_instruction_immediate(insn); // Retrieve immediate value from instruction
        int ret = pc;

        // Repeat next instructions on tape "count" times
        int localPc = state->nextpc;
        state->nextpc += 1;

        //| mov cl, count
        dasm_put(Dst, 256, count);
#line 410 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"

        //| =>localPc:
        //| mov qword [rbp-loopCycleOffset], count
        //| sub [rbp-loopCycleOffset], cl
        dasm_put(Dst, 259, localPc, -loopCycleOffset, count, -loopCycleOffset);
#line 414 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"

        //| push cx
        dasm_put(Dst, 269);
#line 416 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
        ret = rh_main_loop(pc + 1, state); // Call interpret on next instruction
        //| pop cx
        //| dec cl
        dasm_put(Dst, 272);
#line 419 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"

        //| jnz =>localPc
        dasm_put(Dst, 278, localPc);
#line 421 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"

        pc = ret; // Set new current instruction position on the tape

        if (pc == (int)(state->tapeLength) - 1) {
          return pc;
        }
        break;
      }

      case OpCode_IF_LIKELY:
        //| lea param1, [rbp-varsBufferOffset]
        //| mov rax, [param1 + (DecodeInsn_REGA(insn) * 4)]
        //| and rax, 7
        dasm_put(Dst, 282, -varsBufferOffset, (DecodeInsn_REGA(insn) * 4));
#line 434 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
        pc = rh_branch(pc, state); // 1 out of 7 chances of not branching
        break;

      case OpCode_IF_RANDOM:
        //| lea param1, [rbp-varsBufferOffset]
        //| mov rax, [param1 + (DecodeInsn_REGA(insn) * 4)]
        //| and rax, 1
        dasm_put(Dst, 295, -varsBufferOffset, (DecodeInsn_REGA(insn) * 4));
#line 441 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
        pc = rh_branch(pc, state); // 1 out of 2 chances of not branching
        break;

      case OpCode_JMP: {
        pc += (insn >> 8); // Jump on the tape by moving the instruction pointer
        break;
      }

      case OpCode_END: {
        // int i = ctx->vars.count - ctx->varCount
        //| mov param1, [rbp-scopeVarCountOffset]
        //| mov param2, [rbp-varsCountOffset]
        //| sub param2, param1
        dasm_put(Dst, 308, -scopeVarCountOffset, -varsCountOffset);
#line 454 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"

        //| mov param3, [rbp-varsCountOffset]
        dasm_put(Dst, 321, -varsCountOffset);
#line 456 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
        // param1 -> varCount
        // param2 -> i (buffer_count - varCount)
        // param3 -> buffer_count
        //| 1:
        dasm_put(Dst, 326);
#line 460 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"

        //| cmp param2, param3
        //| jge >2 // Exit if i >= buffer_count (aka continue while i < buffer_count)
        dasm_put(Dst, 329);
#line 463 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"

        // param6 -> hashOut[ctx->hashctr]
        //| mov param5, [rbp-hashCountOffset]
        //| mov param6, [rhHashOut + param5 * 4]
        dasm_put(Dst, 337, -hashCountOffset);
#line 467 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"

        // param1 -> ctx->vars.elems[i]
        //| lea param1, [rbp-varsBufferOffset]
        //| mov param1, [param1 + param2 * 4]
        dasm_put(Dst, 346, -varsBufferOffset);
#line 471 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"

        // hashOut[ctx->hashctr] += ctx->vars.elems[i];
        //| add param6, param1
        //| mov [rhHashOut + param5 * 4], r9d
        dasm_put(Dst, 355);
#line 475 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"

        // ctx->hashctr = (ctx->hashctr + 1) % RandHash_INOUT_SZ;
        //| add param5, 1
        //| and param5, (RandHash_INOUT_SZ - 1) // modulo RandHash_INOUT_SZ which is a power of 2
        //| mov [rbp-hashCountOffset], param5
        dasm_put(Dst, 364, (RandHash_INOUT_SZ - 1), -hashCountOffset);
#line 480 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"

        //| inc param2 // i++
        //| jmp <1
        dasm_put(Dst, 377);
#line 483 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"

        //| 2:
        dasm_put(Dst, 386);
#line 485 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"

        //ctx->vars.count -= ctx->varCount;
        //ctx->varCount = Vec_pop(&ctx->scopes);

        //| mov param1, [rbp-scopeVarCountOffset]
        //| mov param2, [rbp-varsCountOffset]
        dasm_put(Dst, 389, -scopeVarCountOffset, -varsCountOffset);
#line 491 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"

        //| sub param2, param1
        //| dec param2
        dasm_put(Dst, 398);
#line 494 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"

        //| mov [rbp-varsCountOffset], param2
        dasm_put(Dst, 407, -varsCountOffset);
#line 496 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"

        //| mov param2, [rbp-scopeCountOffset]
        //| lea param1, [rbp-scopeBufferOffset]
        dasm_put(Dst, 412, -scopeCountOffset, -scopeBufferOffset);
#line 499 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"

        //| dec param2
        //| mov [rbp-scopeCountOffset], param2
        dasm_put(Dst, 421, -scopeCountOffset);
#line 502 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"

        //| mov param6, [param1 + param2 * 4]
        //| mov [rbp-scopeVarCountOffset], r9d
        dasm_put(Dst, 430, -scopeVarCountOffset);
#line 505 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
        return pc;
      }

      case OpCode_POPCNT8 : {
        rh_get_a(state, insn);
        //| mov     esi, edi
        //| mov     eax, edi
        //| mov     edx, edi
        //| shr     esi, 16
        //| shr     eax, 24
        //| movzx   ecx, dh
        //| popcnt  eax, eax
        //| movzx   esi, r6b
        //| sal     eax, 8
        //| movzx   edx, r7b
        //| popcnt  esi, esi
        //| popcnt  ecx, ecx
        //| or      eax, esi
        //| sal     ecx, 8
        //| sal     eax, 16
        //| popcnt  edx, edx
        //| or      edx, ecx
        //| or      eax, edx
        dasm_put(Dst, 439);
#line 528 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
        rh_out_1_var(state);
      break; }
      case OpCode_POPCNT16 : {
        rh_get_a(state, insn);
        //| mov     eax, edi
        //| shr     eax, 16
        //| popcnt  eax, eax
        //| popcnt  di, di
        //| sal     eax, 16
        //| movzx   edi, di
        //| or      eax, edi
        dasm_put(Dst, 505);
#line 539 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
        rh_out_1_var(state);
      break; }
      case OpCode_POPCNT32 : {
        rh_get_a(state, insn);
        //| popcnt r0d, r7d
        dasm_put(Dst, 534);
#line 544 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
        rh_out_1_var(state);
      break; }

      case OpCode_CLZ8 : {
        rh_get_a(state, insn);
        //| mov     edx, edi
        //| shr     edx, 16
        //| mov     esi, edi
        //| shr     esi, 24
        //| mov     cl, 8
        //| mov     al, 8
        //| je      >1
        //| movzx   eax, r6b
        //| bsr     eax, eax
        //| xor     eax, 7
        //| 1:
        //| movzx   eax, al
        //| test    dl, dl
        //| je      >2
        //| movzx   ecx, dl
        //| bsr     ecx, ecx
        //| xor     ecx, 7
        //| 2:
        //| movzx   edx, cl
        //| shl     eax, 24
        //| shl     edx, 16
        //| mov     ecx, edi
        //| shr     ecx, 8
        //| mov     r8b, 8
        //| mov     r6b, 8
        //| test    cl, cl
        //| je      >3
        //| movzx   ecx, cl
        //| bsr     esi, ecx
        //| xor     esi, 7
        //| 3:
        //| or      eax, edx
        //| movzx   edx, r6b
        //| shl     edx, 8
        //| test    r7b , r7b
        //| je      >4
        //| movzx   ecx, r7b
        //| bsr     r8d, ecx
        //| xor     r8d, 7
        //| 4:
        //| movzx   ecx, r8b
        //| or      edx, ecx
        //| or      eax, edx
        dasm_put(Dst, 540);
#line 592 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
        rh_out_1_var(state);
      break; }
      case OpCode_CLZ16 : {
        rh_get_a(state, insn);
        //| mov     edx, edi
        //| shr     edx, 16
        //| mov     cx, 16
        //| mov     ax, 16
        //| je      >1
        //| bsr     ax, dx
        //| xor     eax, 15
        //| 1:
        //| shl     eax, 16
        //| test    di, di
        //| je      >2
        //| bsr     cx, di
        //| xor     ecx, 15
        //| 2:
        //| movzx   ecx, cx
        //| or      eax, ecx
        dasm_put(Dst, 678);
#line 612 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
        rh_out_1_var(state);
      break; }
      case OpCode_CLZ32 : {
        rh_get_a(state, insn);
        //| mov     eax, 32
        //| test    edi, edi
        //| je      >1
        //| bsr     eax, edi
        //| xor     eax, 31
        //| 1:
        dasm_put(Dst, 734);
#line 622 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
        rh_out_1_var(state);
      break; }

      case OpCode_CTZ8 : {
        rh_get_a(state, insn);
        //| mov     ecx, edi
        //| shr     ecx, 16
        //| mov     eax, edi
        //| shr     eax, 24
        //| mov     dl,  8
        //| mov     r6b, 8
        //| je      >1
        //| movzx   eax, al
        //| bsf     esi, eax
        //| 1:
        //| movzx   eax, r6b
        //| test    cl,  cl
        //| je      >2
        //| movzx   ecx, cl
        //| bsf     edx, ecx
        //| 2:
        //| movzx   edx, dl
        //| shl     eax, 24
        //| shl     edx, 16
        //| mov     ecx, edi
        //| shr     ecx, 8
        //| mov     r8b, 8
        //| mov     r6b, 8
        //| test    cl,  cl
        //| je      >3
        //| movzx   ecx, cl
        //| bsf     esi, ecx
        //| 3:
        //| or      eax, edx
        //| movzx   edx, r6b
        //| shl     edx, 8
        //| test    r7b, r7b
        //| je      >4
        //| movzx   ecx, r7b
        //| bsf     r8d, ecx
        //| 4:
        //| movzx   ecx, r8b
        //| or      edx, ecx
        //| or      eax, edx
        dasm_put(Dst, 756);
#line 666 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
        rh_out_1_var(state);
      break; }
      case OpCode_CTZ16 : {
        rh_get_a(state, insn);
        //| mov     edx, edi
        //| shr     edx, 16
        //| mov     cx, 16
        //| mov     ax, 16
        //| je      >1
        //| bsf     ax, dx
        //| 1:
        //| shl     eax, 16
        //| test    di, di
        //| je      >2
        //| bsf     cx, di
        //| 2:
        //| movzx   ecx, cx
        //| or      eax, ecx
        dasm_put(Dst, 878);
#line 684 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
        rh_out_1_var(state);
      break; }
      case OpCode_CTZ32 : {
        rh_get_a(state, insn);
        //| mov     eax, 32
        //| test    edi, edi
        //| je      >1
        //| bsf     eax, edi
        //| 1:
        dasm_put(Dst, 926);
#line 693 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
        rh_out_1_var(state);
      break; }

      case OpCode_BSWAP16 : {
        rh_get_a(state, insn);
        //| mov     eax, edi
        //| rol     eax, 16
        //| bswap   eax
        dasm_put(Dst, 944);
#line 701 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
        rh_out_1_var(state);
      break; }

      case OpCode_BSWAP32 : {
        rh_get_a(state, insn);
        //| bswap r7d
        //| mov eax, r7d
        dasm_put(Dst, 953);
#line 708 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
        rh_out_1_var(state);
      break; }

      //////////////////////////////////////////////////////////////////////

      case OpCode_ADD8 : {
        rh_get_ab(state, insn);
        //| mov     eax, esi
        //| mov     ecx, esi
        //| and     ecx, 65280
        //| add     ecx, edi
        //| add     esi, edi
        //| shr     edi, 16
        //| shr     eax, 16
        //| mov     edx, eax
        //| and     edx, 65280
        //| add     edx, edi
        //| and     edx, 65280
        //| add     eax, edi
        //| movzx   edi, al
        //| or      edi, edx
        //| shl     edi, 16
        //| and     ecx, 65280
        //| movzx   eax, r6b
        //| or      eax, ecx
        //| or      eax, edi
        dasm_put(Dst, 959);
#line 734 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
        rh_out_1_var(state);
      break; }
      case OpCode_ADD16 : {
        rh_get_ab(state, insn);
        //| mov     ecx, esi
        //| and     ecx, -65536
        //| add     ecx, edi
        //| and     ecx, -65536
        //| add     esi, edi
        //| movzx   eax, si
        //| or      eax, ecx
        dasm_put(Dst, 1033);
#line 745 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
        rh_out_1_var(state);
      break; }
      case OpCode_ADD32 : {
        rh_get_ab(state, insn);
        //| add r7d, r6d
        //| mov r0d, r7d
        dasm_put(Dst, 1064);
#line 751 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
        rh_out_1_var(state);
      break; }

      case OpCode_SUB8 : {
        rh_get_ab(state, insn);
        //| mov     ecx, edi
        //| shr     ecx, 16
        //| mov     r8d, esi
        //| mov     edx, edi
        //| sub     edi, esi
        //| shr     esi, 16
        //| mov     eax, ecx
        //| sub     ecx, esi
        //| and     esi, 65280
        //| sub     eax, esi
        //| and     eax, 65280
        //| movzx   ecx, cl
        //| or      ecx, eax
        //| shl     ecx, 16
        //| and     r8d, 65280
        //| sub     edx, r8d
        //| and     edx, 65280
        //| movzx   eax, r7b
        //| or      eax, edx
        //| or      eax, ecx
        dasm_put(Dst, 1071);
#line 776 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
        rh_out_1_var(state);
      break; }
      case OpCode_SUB16 : {
        rh_get_ab(state, insn);
        //| mov     ecx, edi
        //| sub     edi, esi
        //| and     esi, -65536
        //| sub     ecx, esi
        //| and     ecx, -65536
        //| movzx   eax, di
        //| or      eax, ecx
        dasm_put(Dst, 1148);
#line 787 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
        rh_out_1_var(state);
      break; }
      case OpCode_SUB32 : {
        rh_get_ab(state, insn);
        //| sub r7d, r6d
        //| mov eax, r7d
        dasm_put(Dst, 1179);
#line 793 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
        rh_out_1_var(state);
      break; }

      case OpCode_SHLL8 : {
        rh_get_ab(state, insn);
        //| mov     r8d, esi
        //| mov     edx, edi
        //| shr     edx, 16
        //| mov     eax, esi
        //| shr     eax, 16
        //| mov     esi, edi
        //| shr     esi, 24
        //| mov     ecx, r8d
        //| shr     ecx, 24
        //| and     cl, 7
        //| shl     r6b, cl
        //| and     al, 7
        //| mov     ecx, eax
        //| shl     dl, cl
        //| movzx   eax, r6b
        //| movzx   edx, dl
        //| shl     eax, 24
        //| shl     edx, 16
        //| or      edx, eax
        //| mov     eax, edi
        //| shr     eax, 8
        //| mov     ecx, r8d
        //| shr     ecx, 8
        //| and     cl, 7
        //| shl     al, cl
        //| movzx   esi, al
        //| and     r8b, 7
        //| mov     ecx, r8d
        //| shl     r7b, cl
        //| shl     esi, 8
        //| movzx   eax, r7b
        //| or      eax, esi
        //| or      eax, edx
        dasm_put(Dst, 1186);
#line 831 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
        rh_out_1_var(state);
      break; }
      case OpCode_SHLL16 : {
        rh_get_ab(state, insn);
        //| mov     edx, edi
        //| shr     edx, 16
        //| mov     ecx, esi
        //| shr     ecx, 16
        //| and     cl,  15
        //| shl     edx, cl
        //| and     r6b, 15
        //| mov     ecx, esi
        //| shl     edi, cl
        //| shl     edx, 16
        //| movzx   eax, di
        //| or      eax, edx
        dasm_put(Dst, 1289);
#line 847 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
        rh_out_1_var(state);
      break; }
      case OpCode_SHLL32 : {
        rh_get_ab(state, insn);
        //| mov cl, r6b
        //| sal r7d, cl
        //| mov r0d, r7d
        dasm_put(Dst, 1326);
#line 854 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
        rh_out_1_var(state);
      break; }

      case OpCode_SHRL8 : {
        rh_get_ab(state, insn);
        //| mov     r8d, esi
        //| mov     edx, edi
        //| shr     edx, 16
        //| mov     eax, esi
        //| shr     eax, 16
        //| mov     esi, edi
        //| shr     esi, 24
        //| mov     ecx, r8d
        //| shr     ecx, 24
        //| and     cl,  7
        //| shr     r6b, cl
        //| and     al,  7
        //| mov     ecx, eax
        //| shr     dl,  cl
        //| movzx   eax, r6b
        //| movzx   edx, dl
        //| shl     eax, 24
        //| shl     edx, 16
        //| or      edx, eax
        //| mov     eax, edi
        //| shr     eax, 8
        //| mov     ecx, r8d
        //| shr     ecx, 8
        //| and     cl,  7
        //| shr     al,  cl
        //| movzx   esi, al
        //| and     r8b, 7
        //| mov     ecx, r8d
        //| shr     r7b, cl
        //| shl     esi, 8
        //| movzx   eax, r7b
        //| or      eax, esi
        //| or      eax, edx
        dasm_put(Dst, 1336);
#line 892 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
        rh_out_1_var(state);
      break; }
      case OpCode_SHRL16 : {
        rh_get_ab(state, insn);
        //| mov     edx, edi
        //| shr     edx, 16
        //| mov     ecx, esi
        //| shr     ecx, 16
        //| and     cl, 15
        //| shr     edx, cl
        //| movzx   eax, di
        //| shl     edx, 16
        //| and     r6b, 15
        //| mov     ecx, esi
        //| shr     eax, cl
        //| or      eax, edx
        dasm_put(Dst, 1442);
#line 908 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
        rh_out_1_var(state);
      break; }
      case OpCode_SHRL32 : {
        rh_get_ab(state, insn);
        //| mov cl, r6b
        //| shr r7d, cl
        //| mov r0d, r7d
        dasm_put(Dst, 1480);
#line 915 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
        rh_out_1_var(state);
      break; }

      case OpCode_SHRA8 : {
        rh_get_ab(state, insn);
        //| mov     r8d, esi
        //| mov     edx, edi
        //| shr     edx, 16
        //| mov     eax, esi
        //| shr     eax, 16
        //| mov     esi, edi
        //| shr     esi, 24
        //| mov     ecx, r8d
        //| shr     ecx, 24
        //| and     cl, 7
        //| sar     r6b, cl
        //| and     al, 7
        //| mov     ecx, eax
        //| sar     dl, cl
        //| movzx   eax, r6b
        //| movzx   edx, dl
        //| shl     eax, 24
        //| shl     edx, 16
        //| or      edx, eax
        //| mov     eax, edi
        //| shr     eax, 8
        //| mov     ecx, r8d
        //| shr     ecx, 8
        //| and     cl, 7
        //| sar     al, cl
        //| movzx   esi, al
        //| and     r8b, 7
        //| mov     ecx, r8d
        //| sar     r7b, cl
        //| shl     esi, 8
        //| movzx   eax, r7b
        //| or      eax, esi
        //| or      eax, edx
        dasm_put(Dst, 1491);
#line 953 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
        rh_out_1_var(state);
      break; }
      case OpCode_SHRA16 : {
        rh_get_ab(state, insn);
        //| movsx   eax, di
        //| sar     edi, 16
        //| mov     ecx, esi
        //| shr     ecx, 16
        //| and     cl, 15
        //| sar     edi, cl
        //| and     r6d, 15
        //| mov     ecx, esi
        //| sar     eax, cl
        //| shl     edi, 16
        //| movzx   eax, ax
        //| or      eax, edi
        dasm_put(Dst, 1598);
#line 969 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
        rh_out_1_var(state);
      break; }
      case OpCode_SHRA32 : {
        rh_get_ab(state, insn);
        //| mov cl, r6b
        //| sar r7d, cl
        //| mov r0d, r7d
        dasm_put(Dst, 1637);
#line 976 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
        rh_out_1_var(state);
      break; }

      case OpCode_ROTL8 : {
        rh_get_ab(state, insn);
        //| mov     r8d, esi
        //| mov     edx, edi
        //| shr     edx, 16
        //| mov     eax, esi
        //| shr     eax, 16
        //| mov     esi, edi
        //| shr     esi, 24
        //| mov     ecx, r8d
        //| shr     ecx, 24
        //| rol     r6b, cl
        //| movzx   esi, r6b
        //| mov     ecx, eax
        //| rol     dl, cl
        //| movzx   edx, dl
        //| shl     esi, 24
        //| shl     edx, 16
        //| or      edx, esi
        //| mov     eax, edi
        //| shr     eax, 8
        //| mov     ecx, r8d
        //| shr     ecx, 8
        //| rol     al, cl
        //| movzx   esi, al
        //| mov     ecx, r8d
        //| rol     r7b, cl
        //| shl     esi, 8
        //| movzx   eax, r7b
        //| or      eax, esi
        //| or      eax, edx
        dasm_put(Dst, 1648);
#line 1010 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
        rh_out_1_var(state);
      break; }
      case OpCode_ROTL16 : {
        rh_get_ab(state, insn);
        //| mov     edx, edi
        //| shr     edx, 16
        //| mov     ecx, esi
        //| shr     ecx, 16
        //| rol     dx, cl
        //| mov     ecx, esi
        //| rol     di, cl
        //| shl     edx, 16
        //| movzx   eax, di
        //| or      eax, edx
        dasm_put(Dst, 1741);
#line 1024 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
        rh_out_1_var(state);
      break; }
      case OpCode_ROTL32 : {
        rh_get_ab(state, insn);
        //| mov cl, r6b
        //| rol r7d, cl
        //| mov r0d, r7d
        dasm_put(Dst, 1773);
#line 1031 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
        rh_out_1_var(state);
      break; }

      case OpCode_MUL8 : {
        rh_get_ab(state, insn);
        //| push    rbx
        //| mov     eax, esi
        //| mov     ecx, esi
        //| mov     edx, esi
        //| mov     esi, edi
        //| movzx   ebx, ah
        //| imul    eax, edi
        //| shr     edi, 16
        //| shr     ecx, 16
        //| imul    ecx, edi
        //| and     edi, 65280
        //| shr     edx, 24
        //| imul    edx, edi
        //| movzx   ecx, cl
        //| or      ecx, edx
        //| shl     ecx, 16
        //| and     esi, -256
        //| imul    ebx, esi
        //| movzx   eax, al
        //| or      eax, ebx
        //| movzx   eax, ax
        //| or      eax, ecx
        //| pop     rbx
        dasm_put(Dst, 1783);
#line 1059 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
        rh_out_1_var(state);
      break; }
      case OpCode_MUL16 : {
        rh_get_ab(state, insn);
        //| mov     ecx, esi
        //| imul    esi, edi
        //| and     edi, -65536
        //| shr     ecx, 16
        //| imul    ecx, edi
        //| movzx   eax, si
        //| or      eax, ecx
        dasm_put(Dst, 1859);
#line 1070 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
        rh_out_1_var(state);
      break; }

      case OpCode_MUL32 : {
        rh_get_ab(state, insn);
        //| imul r7d, r6d
        //| mov  r0d, r7d
        dasm_put(Dst, 1887);
#line 1077 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
        rh_out_1_var(state);
      break; }

      case OpCode_AND : {
        rh_get_ab(state, insn);
        //| and r7d, r6d
        //| mov r0d, r7d
        dasm_put(Dst, 1895);
#line 1084 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
        rh_out_1_var(state);
      break; }
      case OpCode_OR : {
        rh_get_ab(state, insn);
        //| or  r7d, r6d
        //| mov r0d, r7d
        dasm_put(Dst, 1902);
#line 1090 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
        rh_out_1_var(state);
      break; }
      case OpCode_XOR : {
        rh_get_ab(state, insn);
        //| xor r7d, r6d
        //| mov r0d, r7d
        dasm_put(Dst, 1909);
#line 1096 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
        rh_out_1_var(state);
      break; }

      //////////////////////////////////////////////////////////////////////

      case OpCode_ADD8C : {
       rh_get_ab(state, insn);
       //| push    rbp
       //| push    rbx
       //| mov     ecx, esi
       //| mov     eax, edi
       //| mov     edx, edi
       //| movzx   ebp, ah
       //| movzx   edi, al
       //| mov     esi, eax
       //| shr     esi, 16
       //| shr     edx, 24
       //| mov     ebx, ecx
       //| shr     ebx, 24
       //| add     ebx, edx
       //| movzx   edx, ch
       //| movzx   eax, cl
       //| shr     ecx, 16
       //| movzx   esi, r6b
       //| movzx   ecx, cl
       //| add     ecx, esi
       //| shl     ebx, 16
       //| or      ecx, ebx
       //| shl     rcx, 32
       //| add     edx, ebp
       //| shl     edx, 16
       //| add     eax, edi
       //| or      eax, edx
       //| or      rax, rcx
       //| pop     rbx
       //| pop     rbp
       dasm_put(Dst, 1916);
#line 1132 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
       rh_out_2_var(state);
      break; }
      case OpCode_ADD16C : {
        rh_get_ab(state, insn);
        //| movzx   ecx, di
        //| shr     edi, 16
        //| movzx   eax, si
        //| mov     edx, esi
        //| shr     edx, 16
        //| add     edx, edi
        //| shl     rdx, 32
        //| add     eax, ecx
        //| or      rax, rdx
        dasm_put(Dst, 2000);
#line 1145 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
        rh_out_2_var(state);
      break; }
      case OpCode_ADD32C : {
        rh_get_ab(state, insn);
        //| mov eax, r7d
        //| mov edx, r6d
        //| add rax, rdx
        dasm_put(Dst, 2030);
#line 1152 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
        rh_out_2_var(state);
      break; }
      case OpCode_SUB8C : {
        rh_get_ab(state, insn);
        //| push    rbx
        //| mov     eax, esi
        //| mov     edx, edi
        //| mov     ecx, edi
        //| movzx   esi, dh
        //| movzx   edi, dl
        //| shr     edx, 16
        //| shr     ecx, 24
        //| mov     ebx, eax
        //| shr     ebx, 24
        //| sub     ecx, ebx
        //| movzx   ebx, ah
        //| movzx   r8d, al
        //| shr     eax, 16
        //| movzx   edx, dl
        //| movzx   eax, al
        //| sub     edx, eax
        //| shl     ecx, 16
        //| movzx   edx, dx
        //| or      edx, ecx
        //| shl     rdx, 32
        //| sub     esi, ebx
        //| shl     esi, 16
        //| sub     edi, r8d
        //| movzx   eax, di
        //| or      eax, esi
        //| or      rax, rdx
        //| pop     rbx
        dasm_put(Dst, 2040);
#line 1184 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
        rh_out_2_var(state);
      break; }
      case OpCode_SUB16C : {
        rh_get_ab(state, insn);
        //| movzx   eax, di
        //| mov     ecx, edi
        //| shr     ecx, 16
        //| movzx   edx, si
        //| shr     esi, 16
        //| sub     ecx, esi
        //| shl     rcx, 32
        //| sub     eax, edx
        //| or      rax, rcx
        dasm_put(Dst, 2123);
#line 1197 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
        rh_out_2_var(state);
      break; }
      case OpCode_SUB32C : {
        rh_get_ab(state, insn);
        //| mov eax, r7d
        //| mov edx, r6d
        //| sub rax, rdx
        dasm_put(Dst, 2153);
#line 1204 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
        rh_out_2_var(state);
      break; }
      case OpCode_MUL8C : {
        rh_get_ab(state, insn);
        //| mov     eax, edi
        //| movsx   ecx, di
        //| shr     edi, 16
        //| mov     edx, esi
        //| movsx   r8d, si
        //| shr     esi, 16
        //| sar     eax, 24
        //| sar     edx, 24
        //| imul    edx, eax
        //| movsx   eax, r7b
        //| movsx   esi, r6b
        //| imul    esi, eax
        //| movzx   esi, si
        //| shl     rdx, 48
        //| shl     rsi, 32
        //| or      rsi, rdx
        //| movsx   eax, cl
        //| sar     ecx, 8
        //| movsx   edx, r8b
        //| mov     edi, r8d
        //| sar     edi, 8
        //| imul    edi, ecx
        //| movzx   ecx, di
        //| shl     rcx, 16
        //| imul    edx, eax
        //| movzx   eax, dx
        //| or      rax, rcx
        //| or      rax, rsi
        dasm_put(Dst, 2163);
#line 1236 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
        rh_out_2_var(state);
      break; }
      case OpCode_MUL16C : {
        rh_get_ab(state, insn);
        //| movsx   ecx, di
        //| sar     edi, 16
        //| movsx   eax, si
        //| mov     edx, esi
        //| sar     edx, 16
        //| imul    edx, edi
        //| shl     rdx, 32
        //| imul    eax, ecx
        //| or      rax, rdx
        dasm_put(Dst, 2266);
#line 1249 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
        rh_out_2_var(state);
      break; }
      case OpCode_MUL32C : {
        rh_get_ab(state, insn);
        //|  movsxd rax, r7d
        //|  movsxd rsi, r6d
        //|  imul   rax, rsi
        dasm_put(Dst, 2297);
#line 1256 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
        rh_out_2_var(state);
      break; }
      case OpCode_MULSU8C : {
        rh_get_ab(state, insn);
        //| push    rbx
        //| mov     eax, esi
        //| mov     ecx, edi
        //| movsx   esi, di
        //| shr     edi, 16
        //| mov     edx, eax
        //| shr     edx, 24
        //| sar     ecx, 24
        //| imul    ecx, edx
        //| movzx   ebx, ah
        //| movzx   edx, al
        //| shr     eax, 16
        //| movsx   edi, r7b
        //| movzx   eax, al
        //| imul    eax, edi
        //| movzx   edi, ax
        //| shl     rcx, 48
        //| shl     rdi, 32
        //| or      rdi, rcx
        //| movsx   eax, r6b
        //| mov     ecx, esi
        //| sar     ecx, 8
        //| imul    ecx, ebx
        //| movzx   ecx, cx
        //| shl     rcx, 16
        //| imul    edx, eax
        //| movzx   eax, dx
        //| or      rax, rcx
        //| or      rax, rdi
        //| pop     rbx
        dasm_put(Dst, 2309);
#line 1290 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
        rh_out_2_var(state);
      break; }
      case OpCode_MULSU16C : {
        rh_get_ab(state, insn);
        //| movzx   eax, si
        //| shr     esi, 16
        //| movsx   ecx, di
        //| mov     edx, edi
        //| sar     edx, 16
        //| imul    edx, esi
        //| shl     rdx, 32
        //| imul    eax, ecx
        //| or      rax, rdx
        dasm_put(Dst, 2408);
#line 1303 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
        rh_out_2_var(state);
      break; }
      case OpCode_MULSU32C : {
        rh_get_ab(state, insn);
        //| movsxd rdx, r7d
        //| mov    r0d, r6d
        //| imul   rax, rdx
        dasm_put(Dst, 2439);
#line 1310 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
        rh_out_2_var(state);
      break; }
      case OpCode_MULU8C : {
        rh_get_ab(state, insn);
        //| push    rbp
        //| push    rbx
        //| mov     ecx, esi
        //| mov     eax, edi
        //| mov     edx, edi
        //| movzx   ebx, ah
        //| movzx   edi, al
        //| mov     esi, eax
        //| shr     esi, 16
        //| mov     eax, ecx
        //| shr     eax, 24
        //| shr     edx, 8
        //| and     edx, 16711680
        //| imul    edx, eax
        //| movzx   ebp, ch
        //| movzx   eax, cl
        //| shr     ecx, 16
        //| movzx   esi, r6b
        //| movzx   ecx, cl
        //| imul    ecx, esi
        //| or      ecx, edx
        //| shl     rcx, 32
        //| imul    ebp, ebx
        //| shl     ebp, 16
        //| imul    eax, edi
        //| or      eax, ebp
        //| or      rax, rcx
        //| pop     rbx
        //| pop     rbp
        dasm_put(Dst, 2450);
#line 1343 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
        rh_out_2_var(state);
      break; }
      case OpCode_MULU16C : {
        rh_get_ab(state, insn);
        //| movzx   ecx, di
        //| shr     edi, 16
        //| movzx   eax, si
        //| mov     edx, esi
        //| shr     edx, 16
        //| imul    edx, edi
        //| shl     rdx, 32
        //| imul    eax, ecx
        //| or      rax, rdx
        dasm_put(Dst, 2539);
#line 1356 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
        rh_out_2_var(state);
      break; }
      case OpCode_MULU32C : {
        rh_get_ab(state, insn);
        //| mov  r0d, r7d
        //| mov  r2d, r6d
        //| imul rax, rdx
        dasm_put(Dst, 2570);
#line 1363 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
        rh_out_2_var(state);
      break; }

      //////////////////////////////////////////////////////////////////////

      case OpCode_ADD64 : {
        rh_get_a2b2(state, insn);
        //| add r7, r6
        //| mov r0, r7
        dasm_put(Dst, 2581);
#line 1372 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
        rh_out_2_var(state);
      break; }
      case OpCode_SUB64 : {
        rh_get_a2b2(state, insn);
        //| sub r7, r6
        //| mov r0, r7
        dasm_put(Dst, 2590);
#line 1378 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
        rh_out_2_var(state);
      break; }
      case OpCode_SHLL64 : {
        rh_get_a2b2(state, insn);
        //| mov cl, r6b
        //| shl r7, cl
        //| mov r0, r7
        dasm_put(Dst, 2599);
#line 1385 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
        rh_out_2_var(state);
      break; }
      case OpCode_SHRL64 : {
        rh_get_a2b2(state, insn);
        //| mov cl, r6b
        //| shr r7, cl
        //| mov r0, r7
        dasm_put(Dst, 2611);
#line 1392 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
        rh_out_2_var(state);
      break; }
      case OpCode_SHRA64 : {
        rh_get_a2b2(state, insn);
        //| mov rax, rdi
        //| mov ecx, esi
        //| sar rax, cl
        dasm_put(Dst, 2624);
#line 1399 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
        rh_out_2_var(state);
      break; }
      case OpCode_ROTL64 : {
        rh_get_a2b2(state, insn);
        //| mov cl, r6b
        //| rol r7, cl
        //| mov r0, r7
        dasm_put(Dst, 2636);
#line 1406 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
        rh_out_2_var(state);
      break; }
      case OpCode_ROTR64 : {
        rh_get_a2b2(state, insn);
        //| mov cl, r6b
        //| ror r7, cl
        //| mov r0, r7
        dasm_put(Dst, 2648);
#line 1413 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
        rh_out_2_var(state);
      break; }
      case OpCode_MUL64 : {
        rh_get_a2b2(state, insn);
        //| imul r7, r6
        //| mov  r0, r7
        dasm_put(Dst, 2660);
#line 1419 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
        rh_out_2_var(state);
      break; }

      //////////////////////////////////////////////////////////////////////

      case OpCode_ADD64C : {
        rh_get_a2b2(state, insn);
        //| mov  rax, r7
        //| xor  edx, edx
        //| add  rax, r6
        //| setc dl
        dasm_put(Dst, 2670);
#line 1430 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
        rh_out_4_var(state);
      break; }
      case OpCode_SUB64C : {
        rh_get_a2b2(state, insn);
        //| mov rax, r7
        //| sub rax, r6
        //| cmp r7,  r6
        //| sbb rdx, rdx
        dasm_put(Dst, 2684);
#line 1438 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
        rh_out_4_var(state);
      break; }
      case OpCode_MUL64C : {
        rh_get_a2b2(state, insn);
        //| mov     rcx, rsi
        //| mov     rax, rdi
        //| mov     rsi, rdi
        //| imul    rsi, rcx
        //| mov     r9,  rcx
        //| neg     rax
        //| cmovs   rax, rdi
        //| neg     r9
        //| cmovs   r9,  rcx
        //| mov     r8,  rax
        //| mov     eax, eax
        //| mov     r11, r9
        //| shr     r8,  32
        //| mov     r9d, r9d
        //| shr     r11, 32
        //| mov     r10, r8
        //| mov     rdx, r11
        //| imul    r10, r9
        //| imul    rdx, rax
        //| imul    rax, r9
        //| imul    r8, r11
        //| mov     r9d, edx
        //| shr     rdx, 32
        //| shr     rax, 32
        //| add     rax, r9
        //| mov     r9d, r10d
        //| shr     r10, 32
        //| add     rax, r9
        //| add     rdx, r10
        //| mov     r9d, r8d
        //| shr     r8,  32
        //| add     rdx, r9
        //| shr     rax, 32
        //| add     rax, rdx
        //| mov     rdx, rax
        //| mov     eax, eax
        //| shr     rdx, 32
        //| add     edx, r8d
        //| mov     edx, edx
        //| sal     rdx, 32
        //| or      rdx, rax
        //| xor     rcx, rdi
        //| jns     >1
        //| mov     rax, rdx
        //| neg     rdx
        //| test    rsi, rsi
        //| not     rax
        //| cmovne  rdx, rax
        //| 1:
        //| mov     rax, rsi
        dasm_put(Dst, 2700);
#line 1492 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
        rh_out_4_var(state);
      break; }
      case OpCode_MULSU64C : {
        rh_get_a2b2(state, insn);
        //| mov     rcx, rdi
        //| mov     rax, rdi
        //| mov     r8,  rdi
        //| mov     r10, rsi
        //| imul    rcx, rsi
        //| neg     rax
        //| mov     esi, esi
        //| cmovns  rdi, rax
        //| shr     r10, 32
        //| mov     rax, r10
        //| mov     rdx, rdi
        //| mov     edi, edi
        //| shr     rdx, 32
        //| imul    rax, rdi
        //| mov     r9,  rdx
        //| imul    rdi, rsi
        //| imul    r9,  rsi
        //| imul    rdx, r10
        //| mov     esi, eax
        //| shr     rax, 32
        //| shr     rdi, 32
        //| add     rdi, rsi
        //| mov     esi, r9d
        //| shr     r9,  32
        //| add     rdi, rsi
        //| add     rax, r9
        //| mov     esi, edx
        //| shr     rdx, 32
        //| add     rax, rsi
        //| shr     rdi, 32
        //| add     rax, rdi
        //| mov     rsi, rax
        //| mov     eax, eax
        //| shr     rsi, 32
        //| add     edx, esi
        //| mov     edx, edx
        //| sal     rdx, 32
        //| or      rdx, rax
        //| test    r8,  r8
        //| jns     >1
        //| mov     rax, rdx
        //| neg     rdx
        //| test    rcx, rcx
        //| not     rax
        //| cmovne  rdx, rax
        //| 1:
        //| mov     rax, rcx
        dasm_put(Dst, 2880);
#line 1543 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
        rh_out_4_var(state);
      break; }
      case OpCode_MULU64C : {
        rh_get_a2b2(state, insn);
        //| mov     r9,  rsi
        //| mov     rcx, rdi
        //| mov     rdx, rdi
        //| mov     edi, edi
        //| shr     r9,  32
        //| imul    rcx, rsi
        //| shr     rdx, 32
        //| mov     esi, esi
        //| mov     rax, r9
        //| mov     r8,  rdx
        //| imul    rax, rdi
        //| imul    rdi, rsi
        //| imul    r8,  rsi
        //| imul    rdx, r9
        //| mov     esi, eax
        //| shr     rax, 32
        //| shr     rdi, 32
        //| add     rdi, rsi
        //| mov     esi, r8d
        //| shr     r8,  32
        //| add     rdi, rsi
        //| add     rax, r8
        //| mov     esi, edx
        //| shr     rdx, 32
        //| add     rax, rsi
        //| shr     rdi, 32
        //| add     rax, rdi
        //| mov     rsi, rax
        //| mov     eax, eax
        //| shr     rsi, 32
        //| add     edx, esi
        //| mov     edx, edx
        //| sal     rdx, 32
        //| or      rdx, rax
        //| mov     rax, rcx
        dasm_put(Dst, 3055);
#line 1582 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
        rh_out_4_var(state);
      break; }
  
      default: printf("JIT: unimplemented OP %d\n", DecodeInsn_OP(insn)); abort();
    }
  }
}

// Unroll the RandHash program and generate its associated ASM instructions
static void rh_unroll(rh_state_compile_t* state)
{
  dasm_State** Dst = &state->dynasm_state;

  // Consensus specifies the entire program shall be run twice with an inversion of the hashIn and hashOut in-between

  //| mov param2, 1              // Used as a flag to specify if we should exit the program or not (0 means yes)
  //| ->rh_entry:                // Entry to the program
  dasm_put(Dst, 3185);
#line 1599 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"

  //| push param2                // Save the exit flag before calling any function
  //| mov qword [rbp-hashCountOffset], 0
  dasm_put(Dst, 3195, -hashCountOffset);
#line 1602 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"

  rh_main_loop(0, state);      // Generate the JIT code starting at instruction 0 on the tape
  //| pop param2                 // Restore the exit flag
  dasm_put(Dst, 3205);
#line 1605 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"

  //| xchg rhHashIn, rhHashOut   // Swap hashIn and hashOut
  dasm_put(Dst, 3207);
#line 1607 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"

  //| cmp param2, 0              // Check if exit flag is set
  //| je ->rh_exit               // If exit flag is set, exit the program
  dasm_put(Dst, 3212);
#line 1610 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"

  //| mov param2, 0              // If exit flag was not set, set the exit flag so that next run exits
  //| jmp ->rh_entry             // Rerun the program once more
  dasm_put(Dst, 3222);
#line 1613 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"

  //| ->rh_exit:                 // Jump to this global flag to exit the program
  dasm_put(Dst, 3234);
#line 1615 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
}

// Start the JIT process for the RandHash program
static inline void rh_jit(rh_state_compile_t* state)
{
  // Subsequent asm lines are rewritten to dasm_put(Dst, ...), we need this variable to reference the state
  dasm_State** Dst = &state->dynasm_state;

  // Start code section and write the main for our program
  //| .code
  dasm_put(Dst, 3215);
#line 1625 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
  //| ->rh_main:
  dasm_put(Dst, 3237);
#line 1626 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"

  // SYSTEM V ABI forces us to save callee-save registers to avoid stack corruption
  //| prologue
  dasm_put(Dst, 3240, stackSize, -scopeCountOffset, -varsCountOffset, -scopeVarCountOffset, -loopCycleOffset);
#line 1629 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"

  // Shortcut registers for frequently used addresses, so we don't have to go to the cache all the time
  //| mov rhMemory,  param1
  //| mov rhHashIn,  param2
  //| mov rhHashOut, param3
  dasm_put(Dst, 3289);
#line 1634 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"

  // Align memory to 8 bytes as this program is only expected to run on x86_64
  //| .align qword
  dasm_put(Dst, 3301);
#line 1637 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"

  // Start unrolling and generating the ASM associated with the RandHash program
  rh_unroll(state);

  // Restore the registers we saved at the start of the program to avoid stack corruption
  //| epilogue
  dasm_put(Dst, 3304, stackSize);
#line 1643 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                    JIT UTILITIES                                                  //
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Allocate a memory buffer and store the JITed executable program inside
static inline rh_jit_program_t* rh_link_and_encode(dasm_State** state)
{
  size_t size; void* buffer;
  dasm_link(state, &size);

  buffer = mmap(0, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (buffer == MAP_FAILED) {
     fprintf(stderr, "JIT: error allocating memory during encoding: %s\n", strerror(errno));
     exit(1);
  }

  dasm_encode(state, buffer);
  mprotect(buffer, size, PROT_READ | PROT_EXEC);

  rh_jit_program_t* program = calloc(1, sizeof(rh_jit_program_t));
  program->programBuffer    = buffer;
  program->length           = size;

  return program;
}

// Initialize RandHash and DynASM state and declare helpers functions
static inline void rh_init(rh_state_compile_t* state, uint32_t* tape, uint32_t tapeLength)
{
  state->npc    = 1024;
  state->nextpc = 0;

  state->tape       = tape;       // Set the tape of instructions making up the program
  state->tapeLength = tapeLength; // Set the number of instructions contained in the program

  dasm_init(&state->dynasm_state, DASM_MAXSECTION);
  dasm_setupglobal(&state->dynasm_state, state->labels, lbl__MAX);

  //| .actionlist rh_actions
static const unsigned char rh_actions[3318] = {
  72,141,189,233,255,72,139,191,233,255,72,141,149,233,255,72,139,186,233,255,
  72,199,198,237,255,72,139,178,233,255,72,139,186,233,72,193,231,32,72,11,
  186,233,255,72,139,178,233,72,193,230,32,72,11,178,233,255,72,141,189,233,
  72,139,181,233,255,72,137,4,183,72,252,255,133,233,255,137,4,183,72,252,255,
  198,255,72,193,232,32,72,137,4,183,72,252,255,198,255,72,137,181,233,72,131,
  133,233,2,255,137,20,183,72,252,255,198,255,72,193,252,234,32,72,137,20,183,
  72,252,255,198,255,72,137,181,233,72,131,133,233,4,255,72,131,252,248,0,15,
  132,245,255,252,233,245,255,249,255,72,141,189,233,72,139,181,233,72,199,
  4,183,0,0,0,0,72,252,255,133,233,255,72,141,189,233,72,139,181,233,72,139,
  149,233,72,137,20,183,72,252,255,133,233,255,72,199,133,233,0,0,0,0,255,72,
  139,149,233,72,129,194,239,72,105,210,239,72,129,194,239,72,129,226,239,255,
  73,139,4,148,72,137,4,183,255,72,252,255,133,233,72,252,255,133,233,255,73,
  139,133,233,72,137,4,183,255,177,235,255,249,72,199,133,233,237,40,141,233,
  255,102,81,255,102,89,252,254,201,255,15,133,245,255,72,141,189,233,72,139,
  135,233,72,131,224,7,255,72,141,189,233,72,139,135,233,72,131,224,1,255,72,
  139,189,233,72,139,181,233,72,41,252,254,255,72,139,149,233,255,248,1,255,
  72,57,214,15,141,244,248,255,76,139,133,233,79,139,12,134,255,72,141,189,
  233,72,139,60,183,255,73,1,252,249,71,137,12,134,255,73,131,192,1,73,129,
  224,239,76,137,133,233,255,72,252,255,198,252,233,244,1,255,248,2,255,72,
  139,189,233,72,139,181,233,255,72,41,252,254,72,252,255,206,255,72,137,181,
  233,255,72,139,181,233,72,141,189,233,255,72,252,255,206,72,137,181,233,255,
  76,139,12,183,68,137,141,233,255,137,252,254,137,252,248,137,252,250,193,
  252,238,16,193,232,24,15,182,206,252,243,15,184,192,64,15,182,252,246,193,
  224,8,64,15,182,215,252,243,15,184,252,246,252,243,15,184,201,9,252,240,193,
  225,8,193,224,16,252,243,15,184,210,9,202,9,208,255,137,252,248,193,232,16,
  252,243,15,184,192,102,252,243,15,184,252,255,193,224,16,15,183,252,255,9,
  252,248,255,252,243,15,184,199,255,137,252,250,193,252,234,16,137,252,254,
  193,252,238,24,177,8,176,8,15,132,244,247,64,15,182,198,15,189,192,131,252,
  240,7,248,1,15,182,192,132,210,15,132,244,248,15,182,202,15,189,201,131,252,
  241,7,248,2,15,182,209,193,224,24,193,226,16,137,252,249,193,252,233,8,65,
  176,8,64,182,8,132,201,15,132,244,249,15,182,201,15,189,252,241,131,252,246,
  7,248,3,9,208,64,15,182,214,193,226,8,64,132,252,255,15,132,244,250,64,15,
  182,207,68,15,189,193,65,131,252,240,7,248,4,65,15,182,200,9,202,9,208,255,
  137,252,250,193,252,234,16,102,185,16,0,102,184,16,0,15,132,244,247,102,15,
  189,194,131,252,240,15,248,1,193,224,16,102,133,252,255,15,132,244,248,102,
  15,189,207,131,252,241,15,248,2,15,183,201,9,200,255,184,32,0,0,0,133,252,
  255,15,132,244,247,15,189,199,131,252,240,31,248,1,255,137,252,249,193,252,
  233,16,137,252,248,193,232,24,178,8,64,182,8,15,132,244,247,15,182,192,15,
  188,252,240,248,1,64,15,182,198,132,201,15,132,244,248,15,182,201,15,188,
  209,248,2,15,182,210,193,224,24,193,226,16,137,252,249,193,252,233,8,65,176,
  8,64,182,8,132,201,15,132,244,249,15,182,201,15,188,252,241,248,3,9,208,64,
  15,182,214,193,226,8,64,132,252,255,15,132,244,250,64,15,182,207,68,15,188,
  193,248,4,65,15,182,200,9,202,9,208,255,137,252,250,193,252,234,16,102,185,
  16,0,102,184,16,0,15,132,244,247,102,15,188,194,248,1,193,224,16,102,133,
  252,255,15,132,244,248,102,15,188,207,248,2,15,183,201,9,200,255,184,32,0,
  0,0,133,252,255,15,132,244,247,15,188,199,248,1,255,137,252,248,193,192,16,
  15,200,255,15,207,137,252,248,255,137,252,240,137,252,241,129,225,0,252,255,
  0,0,1,252,249,1,252,254,193,252,239,16,193,232,16,137,194,129,226,0,252,255,
  0,0,1,252,250,129,226,0,252,255,0,0,1,252,248,15,182,252,248,9,215,193,231,
  16,129,225,0,252,255,0,0,64,15,182,198,9,200,9,252,248,255,137,252,241,129,
  225,0,0,252,255,252,255,1,252,249,129,225,0,0,252,255,252,255,1,252,254,15,
  183,198,9,200,255,1,252,247,137,252,248,255,137,252,249,193,252,233,16,65,
  137,252,240,137,252,250,41,252,247,193,252,238,16,137,200,41,252,241,129,
  230,0,252,255,0,0,41,252,240,37,0,252,255,0,0,15,182,201,9,193,193,225,16,
  65,129,224,0,252,255,0,0,68,41,194,129,226,0,252,255,0,0,64,15,182,199,9,
  208,9,200,255,137,252,249,41,252,247,129,230,0,0,252,255,252,255,41,252,241,
  129,225,0,0,252,255,252,255,15,183,199,9,200,255,41,252,247,137,252,248,255,
  65,137,252,240,137,252,250,193,252,234,16,137,252,240,193,232,16,137,252,
  254,193,252,238,24,68,137,193,193,252,233,24,128,225,7,64,210,230,36,7,137,
  193,210,226,64,15,182,198,15,182,210,193,224,24,193,226,16,9,194,137,252,
  248,193,232,8,68,137,193,193,252,233,8,128,225,7,210,224,15,182,252,240,65,
  128,224,7,68,137,193,64,210,231,193,230,8,64,15,182,199,9,252,240,9,208,255,
  137,252,250,193,252,234,16,137,252,241,193,252,233,16,128,225,15,211,226,
  64,128,230,15,137,252,241,211,231,193,226,16,15,183,199,9,208,255,64,136,
  252,241,211,231,137,252,248,255,65,137,252,240,137,252,250,193,252,234,16,
  137,252,240,193,232,16,137,252,254,193,252,238,24,68,137,193,193,252,233,
  24,128,225,7,64,210,252,238,36,7,137,193,210,252,234,64,15,182,198,15,182,
  210,193,224,24,193,226,16,9,194,137,252,248,193,232,8,68,137,193,193,252,
  233,8,128,225,7,210,232,15,182,252,240,65,128,224,7,68,137,193,64,210,252,
  239,193,230,8,64,15,182,199,9,252,240,9,208,255,137,252,250,193,252,234,16,
  137,252,241,193,252,233,16,128,225,15,211,252,234,15,183,199,193,226,16,64,
  128,230,15,137,252,241,211,232,9,208,255,64,136,252,241,211,252,239,137,252,
  248,255,65,137,252,240,137,252,250,193,252,234,16,137,252,240,193,232,16,
  137,252,254,193,252,238,24,68,137,193,193,252,233,24,128,225,7,64,210,252,
  254,36,7,137,193,210,252,250,64,15,182,198,15,182,210,193,224,24,193,226,
  16,9,194,137,252,248,193,232,8,68,137,193,193,252,233,8,128,225,7,210,252,
  248,15,182,252,240,65,128,224,7,68,137,193,64,210,252,255,193,230,8,64,15,
  182,199,9,252,240,9,208,255,15,191,199,193,252,255,16,137,252,241,193,252,
  233,16,128,225,15,211,252,255,131,230,15,137,252,241,211,252,248,193,231,
  16,15,183,192,9,252,248,255,64,136,252,241,211,252,255,137,252,248,255,65,
  137,252,240,137,252,250,193,252,234,16,137,252,240,193,232,16,137,252,254,
  193,252,238,24,68,137,193,193,252,233,24,64,210,198,64,15,182,252,246,137,
  193,210,194,15,182,210,193,230,24,193,226,16,9,252,242,137,252,248,193,232,
  8,68,137,193,193,252,233,8,210,192,15,182,252,240,68,137,193,64,210,199,193,
  230,8,64,15,182,199,9,252,240,9,208,255,137,252,250,193,252,234,16,137,252,
  241,193,252,233,16,102,211,194,137,252,241,102,211,199,193,226,16,15,183,
  199,9,208,255,64,136,252,241,211,199,137,252,248,255,83,137,252,240,137,252,
  241,137,252,242,137,252,254,15,182,220,15,175,199,193,252,239,16,193,252,
  233,16,15,175,207,129,231,0,252,255,0,0,193,252,234,24,15,175,215,15,182,
  201,9,209,193,225,16,129,230,0,252,255,252,255,252,255,15,175,222,15,182,
  192,9,216,15,183,192,9,200,91,255,137,252,241,15,175,252,247,129,231,0,0,
  252,255,252,255,193,252,233,16,15,175,207,15,183,198,9,200,255,15,175,252,
  254,137,252,248,255,33,252,247,137,252,248,255,9,252,247,137,252,248,255,
  49,252,247,137,252,248,255,85,83,137,252,241,137,252,248,137,252,250,15,182,
  252,236,15,182,252,248,137,198,193,252,238,16,193,252,234,24,137,203,193,
  252,235,24,1,211,15,182,213,15,182,193,193,252,233,16,64,15,182,252,246,15,
  182,201,1,252,241,193,227,16,9,217,72,193,225,32,1,252,234,193,226,16,1,252,
  248,9,208,72,9,200,91,93,255,15,183,207,193,252,239,16,15,183,198,137,252,
  242,193,252,234,16,1,252,250,72,193,226,32,1,200,72,9,208,255,137,252,248,
  137,252,242,72,1,208,255,83,137,252,240,137,252,250,137,252,249,15,182,252,
  246,15,182,252,250,193,252,234,16,193,252,233,24,137,195,193,252,235,24,41,
  217,15,182,220,68,15,182,192,193,232,16,15,182,210,15,182,192,41,194,193,
  225,16,15,183,210,9,202,72,193,226,32,41,222,193,230,16,68,41,199,15,183,
  199,9,252,240,72,9,208,91,255,15,183,199,137,252,249,193,252,233,16,15,183,
  214,193,252,238,16,41,252,241,72,193,225,32,41,208,72,9,200,255,137,252,248,
  137,252,242,72,41,208,255,137,252,248,15,191,207,193,252,239,16,137,252,242,
  68,15,191,198,193,252,238,16,193,252,248,24,193,252,250,24,15,175,208,64,
  15,190,199,64,15,190,252,246,15,175,252,240,15,183,252,246,72,193,226,48,
  72,193,230,32,72,9,214,15,190,193,193,252,249,8,65,15,190,208,68,137,199,
  193,252,255,8,15,175,252,249,15,183,207,72,193,225,16,15,175,208,15,183,194,
  72,9,200,72,9,252,240,255,15,191,207,193,252,255,16,15,191,198,137,252,242,
  193,252,250,16,15,175,215,72,193,226,32,15,175,193,72,9,208,255,72,99,199,
  72,99,252,246,72,15,175,198,255,83,137,252,240,137,252,249,15,191,252,247,
  193,252,239,16,137,194,193,252,234,24,193,252,249,24,15,175,202,15,182,220,
  15,182,208,193,232,16,64,15,190,252,255,15,182,192,15,175,199,15,183,252,
  248,72,193,225,48,72,193,231,32,72,9,207,64,15,190,198,137,252,241,193,252,
  249,8,15,175,203,15,183,201,72,193,225,16,15,175,208,15,183,194,72,9,200,
  72,9,252,248,91,255,15,183,198,193,252,238,16,15,191,207,137,252,250,193,
  252,250,16,15,175,214,72,193,226,32,15,175,193,72,9,208,255,72,99,215,137,
  252,240,72,15,175,194,255,85,83,137,252,241,137,252,248,137,252,250,15,182,
  220,15,182,252,248,137,198,193,252,238,16,137,200,193,232,24,193,252,234,
  8,129,226,0,0,252,255,0,15,175,208,15,182,252,237,15,182,193,193,252,233,
  16,64,15,182,252,246,15,182,201,15,175,206,9,209,72,193,225,32,15,175,252,
  235,193,229,16,15,175,199,9,232,72,9,200,91,93,255,15,183,207,193,252,239,
  16,15,183,198,137,252,242,193,252,234,16,15,175,215,72,193,226,32,15,175,
  193,72,9,208,255,137,252,248,137,252,242,72,15,175,194,255,72,1,252,247,72,
  137,252,248,255,72,41,252,247,72,137,252,248,255,64,136,252,241,72,211,231,
  72,137,252,248,255,64,136,252,241,72,211,252,239,72,137,252,248,255,72,137,
  252,248,137,252,241,72,211,252,248,255,64,136,252,241,72,211,199,72,137,252,
  248,255,64,136,252,241,72,211,207,72,137,252,248,255,72,15,175,252,254,72,
  137,252,248,255,72,137,252,248,49,210,72,1,252,240,15,146,210,255,72,137,
  252,248,72,41,252,240,72,57,252,247,72,25,210,255,72,137,252,241,72,137,252,
  248,72,137,252,254,72,15,175,252,241,73,137,201,72,252,247,216,72,15,72,199,
  73,252,247,217,76,15,72,201,73,137,192,137,192,77,137,203,73,193,232,32,69,
  137,201,73,193,252,235,32,77,137,194,76,137,218,77,15,175,209,72,15,175,208,
  73,15,175,193,77,15,175,195,65,137,209,72,193,252,234,32,72,193,232,32,76,
  1,200,69,137,209,73,193,252,234,32,76,1,200,76,1,210,69,137,193,73,193,232,
  32,76,1,202,72,193,232,32,72,1,208,72,137,194,137,192,72,193,252,234,32,68,
  1,194,137,210,72,193,226,32,72,9,194,72,49,252,249,15,137,244,247,72,137,
  208,72,252,247,218,72,133,252,246,72,252,247,208,72,15,69,208,248,1,72,137,
  252,240,255,72,137,252,249,72,137,252,248,73,137,252,248,73,137,252,242,72,
  15,175,206,72,252,247,216,137,252,246,72,15,73,252,248,73,193,252,234,32,
  76,137,208,72,137,252,250,137,252,255,72,193,252,234,32,72,15,175,199,73,
  137,209,72,15,175,252,254,76,15,175,206,73,15,175,210,137,198,72,193,232,
  32,72,193,252,239,32,72,1,252,247,68,137,206,73,193,252,233,32,72,1,252,247,
  76,1,200,137,214,72,193,252,234,32,72,1,252,240,72,193,252,239,32,72,1,252,
  248,72,137,198,137,192,72,193,252,238,32,1,252,242,137,210,72,193,226,32,
  72,9,194,77,133,192,15,137,244,247,72,137,208,72,252,247,218,72,133,201,72,
  252,247,208,72,15,69,208,248,1,72,137,200,255,73,137,252,241,72,137,252,249,
  72,137,252,250,137,252,255,73,193,252,233,32,72,15,175,206,72,193,252,234,
  32,137,252,246,76,137,200,73,137,208,72,15,175,199,72,15,175,252,254,76,15,
  175,198,73,15,175,209,137,198,72,193,232,32,72,193,252,239,32,72,1,252,247,
  68,137,198,73,193,232,32,72,1,252,247,76,1,192,137,214,72,193,252,234,32,
  72,1,252,240,72,193,252,239,32,72,1,252,248,72,137,198,137,192,72,193,252,
  238,32,1,252,242,137,210,72,193,226,32,72,9,194,72,137,200,255,72,199,198,
  1,0,0,0,248,10,255,86,72,199,133,233,0,0,0,0,255,94,255,77,135,252,238,255,
  72,131,252,254,0,15,132,244,11,255,72,199,198,0,0,0,0,252,233,244,10,255,
  248,11,255,248,12,255,65,84,65,85,65,86,80,85,72,137,229,72,129,252,236,239,
  72,199,133,233,0,0,0,0,72,199,133,233,0,0,0,0,72,199,133,233,0,0,0,0,72,199,
  133,233,0,0,0,0,255,73,137,252,252,73,137,252,245,73,137,214,255,250,7,255,
  72,129,196,239,201,88,65,94,65,93,65,92,195,255
};

#line 1684 "packetcrypt-sys/packetcrypt/src/JIT/JIT.c"
  dasm_setup(&state->dynasm_state, rh_actions);
  dasm_growpc(&state->dynasm_state, state->npc);
}

// Compile the JIT program and return a function pointer to call the JITed program
static inline rh_jit_program_t* rh_compile(rh_state_compile_t* state)
{
  rh_jit_program_t* program = rh_link_and_encode(&state->dynasm_state);
  dasm_free(&state->dynasm_state);

  program->exec = (void(*)(void*, void*, void*))state->labels[lbl_rh_main];
  return program;
}

// Generates the JITed program based on a RandHash set of instructions
rh_jit_program_t* rh_generate_program(uint32_t* programBuffer, uint32_t programLength)
{
  rh_state_compile_t state;                       // JIT compile-time state containing variables used during ASM generation
  rh_init(&state, programBuffer, programLength);  // Init the JIT compile-time state variables to their default values
  rh_jit(&state);                                 // Generate the JITed ASM for the RandHash program

  rh_jit_program_t* program = rh_compile(&state); // Compile the program
  return program;
}

// Free the JITed program from memory
inline void rh_free_program(rh_jit_program_t* program) {
  munmap(program->programBuffer, program->length);
  free(program);
}

// Run the JITed program at a specific index
inline void rh_run(uint32_t* programBuffer, int index, void* hashIn, void* hashOut, rh_jit_program_t* program) {
  program->exec(&programBuffer[index % (2048 - RandHash_MEMORY_SZ)], hashIn, hashOut);
}
