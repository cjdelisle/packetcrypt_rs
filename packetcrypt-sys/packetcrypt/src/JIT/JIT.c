||#if ((defined(_M_X64) || defined(__amd64__)) != X64)
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
| .arch x64
| .section code, imports
| .globals lbl_

// Setup shortcuts for x64 calling conventions
| .define return1, rax
| .define return2, rdx
| .define param1,  rdi
| .define param2,  rsi
| .define param3,  rdx
| .define param4,  rcx
| .define param5,  r8
| .define param6,  r9

// Main JIT callee-saved registers (we must restore those before exiting the program)
| .define rhMemory,  r12
| .define rhHashIn,  r13
| .define rhHashOut, r14

// Setup stack frame
| .macro prologue
|   push rhMemory
|   push rhHashIn
|   push rhHashOut
|   push rax
|   push rbp
|   mov  rbp,  rsp
|   sub  rsp,  stackSize
|   mov  qword [rbp-scopeCountOffset],    0
|   mov  qword [rbp-varsCountOffset],     0
|   mov  qword [rbp-scopeVarCountOffset], 0
|   mov  qword [rbp-loopCycleOffset],     0
| .endmacro

// Tear down stack frame
| .macro epilogue
|   add rsp, stackSize
|   leave
|   pop rax
|   pop rhHashOut
|   pop rhHashIn
|   pop rhMemory
|   ret
| .endmacro

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

#define RandHash_MEMORY_SZ 256
#define RandHash_INOUT_SZ  256

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
  | lea param1, [rbp-varsBufferOffset]

  // GET A
  | mov param1, [param1 + (DecodeInsn_REGA(instruction) * 4)]
}

static inline void rh_get_ab(rh_state_compile_t* state, uint32_t instruction) {
  dasm_State** Dst = &state->dynasm_state;
  | lea param3, [rbp-varsBufferOffset]

  // GET A
  | mov param1, [param3 + (DecodeInsn_REGA(instruction) * 4)]

  // GET B
  if (DecodeInsn_HAS_IMM(instruction)) {
    | mov param2, rh_decode_instruction_immediateLo(instruction);
  } else {
    | mov param2, [param3 + (DecodeInsn_REGB(instruction) * 4)]
  }
}

static inline void rh_get_a2b2(rh_state_compile_t* state, uint32_t instruction) {
  dasm_State** Dst = &state->dynasm_state;
  | lea param3, [rbp-varsBufferOffset]

  // GET A2
  | mov param1, [param3 + (DecodeInsn_REGA(instruction) * 4)]
  | shl param1, 32
  | or  param1, [param3 + ((DecodeInsn_REGA(instruction) - 1) * 4)]

  // GET B2
  if (DecodeInsn_HAS_IMM(instruction)) {
    | mov param2, rh_decode_instruction_immediate(instruction)
  } else {
    | mov param2, [param3 + (DecodeInsn_REGB(instruction) * 4)]
    | shl param2, 32
    | or  param2, [param3 + ((DecodeInsn_REGB(instruction) - 1) * 4)]
  }
}

static inline void rh_out_1_var(rh_state_compile_t* state) {
    dasm_State** Dst = &state->dynasm_state;
    | lea param1, [rbp-varsBufferOffset]
    | mov param2, [rbp-varsCountOffset]

    | mov [param1 + param2 * 4], rax
    | inc qword [rbp-varsCountOffset]

    | inc qword [rbp-scopeVarCountOffset]
}

static inline void rh_out_2_var(rh_state_compile_t* state) {
    dasm_State** Dst = &state->dynasm_state;
    | lea param1, [rbp-varsBufferOffset]
    | mov param2, [rbp-varsCountOffset]

    | mov [param1 + param2 * 4], r0d
    | inc param2

    | shr rax, 32
    | mov [param1 + param2 * 4], rax
    | inc param2

    | mov [rbp-varsCountOffset], param2
    | add qword [rbp-scopeVarCountOffset], 2
}

static inline void rh_out_4_var(rh_state_compile_t* state) {
    dasm_State** Dst = &state->dynasm_state;
    // rdx, rax arrive here
    // return2, return1
    // uint128 [rax, rdx]
    // rax[:4] rax[4:] rdx[:4] rdx[:4]
    | lea param1, [rbp-varsBufferOffset]
    | mov param2, [rbp-varsCountOffset]

    | mov [param1 + param2 * 4], r0d
    | inc param2

    | shr rax, 32
    | mov [param1 + param2 * 4], rax
    | inc param2

    | mov [param1 + param2 * 4], r2d
    | inc param2

    | shr rdx, 32
    | mov [param1 + param2 * 4], rdx
    | inc param2

    | mov [rbp-varsCountOffset], param2
    | add qword [rbp-scopeVarCountOffset], 4
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

  | cmp rax, 0
  | jz =>localPc

  // Branching
  rh_main_loop(pc + 2, state); // Compute branch at +2 instructions
  | jmp =>localPc+1

  // Not branching
  | =>localPc:
  int ret = rh_main_loop(pc + 1, state); // Compute branch at +1 instruction

  // Exit
  | =>localPc+1:
  return ret;
}

static int rh_main_loop(int pc, rh_state_compile_t* state)
{
  dasm_State** Dst = &state->dynasm_state;

  if (pc != 0) {
    | lea param1, [rbp-varsBufferOffset]
    | mov param2, [rbp-varsCountOffset]
    | mov qword   [param1 + param2 * 4], 0
    | inc qword   [rbp-varsCountOffset]

    | lea param1, [rbp-scopeBufferOffset]
    | mov param2, [rbp-scopeCountOffset]
    | mov param3, [rbp-scopeVarCountOffset]
    | mov [param1 + param2 * 4], param3
    | inc qword [rbp-scopeCountOffset]

    | mov qword [rbp-scopeVarCountOffset], 0
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
        | mov  param3, [rbp-loopCycleOffset]
        | add  param3, carry
        | imul param3, step
        | add  param3, base
        | and  param3, (RandHash_MEMORY_SZ - 1)

        | lea param1, [rbp-varsBufferOffset]
        | mov param2, [rbp-varsCountOffset]

        | mov rax, [rhMemory + param3 * 4]
        | mov [param1 + param2 * 4], rax

        | inc qword [rbp-varsCountOffset]
        | inc qword [rbp-scopeVarCountOffset]
        break;
      }

      case OpCode_IN: {
        int index = ((uint32_t)rh_decode_instruction_immediate(insn)) % RandHash_INOUT_SZ;
        | lea param1, [rbp-varsBufferOffset]
        | mov param2, [rbp-varsCountOffset]

        | mov rax, [rhHashIn + index * 4]
        | mov [param1 + param2 * 4], rax

        | inc qword [rbp-varsCountOffset]
        | inc qword [rbp-scopeVarCountOffset]
        break;
      }

      case OpCode_LOOP: {
        const int count = rh_decode_instruction_immediate(insn); // Retrieve immediate value from instruction
        int ret = pc;

        // Repeat next instructions on tape "count" times
        int localPc = state->nextpc;
        state->nextpc += 1;

        | mov cl, count

        | =>localPc:
        | mov qword [rbp-loopCycleOffset], count
        | sub [rbp-loopCycleOffset], cl

        | push cx
        ret = rh_main_loop(pc + 1, state); // Call interpret on next instruction
        | pop cx
        | dec cl

        | jnz =>localPc

        pc = ret; // Set new current instruction position on the tape

        if (pc == (int)(state->tapeLength) - 1) {
          return pc;
        }
        break;
      }

      case OpCode_IF_LIKELY:
        | lea param1, [rbp-varsBufferOffset]
        | mov rax, [param1 + (DecodeInsn_REGA(insn) * 4)]
        | and rax, 7
        pc = rh_branch(pc, state); // 1 out of 7 chances of not branching
        break;

      case OpCode_IF_RANDOM:
        | lea param1, [rbp-varsBufferOffset]
        | mov rax, [param1 + (DecodeInsn_REGA(insn) * 4)]
        | and rax, 1
        pc = rh_branch(pc, state); // 1 out of 2 chances of not branching
        break;

      case OpCode_JMP: {
        pc += (insn >> 8); // Jump on the tape by moving the instruction pointer
        break;
      }

      case OpCode_END: {
        // int i = ctx->vars.count - ctx->varCount
        | mov param1, [rbp-scopeVarCountOffset]
        | mov param2, [rbp-varsCountOffset]
        | sub param2, param1

        | mov param3, [rbp-varsCountOffset]
        // param1 -> varCount
        // param2 -> i (buffer_count - varCount)
        // param3 -> buffer_count
        | 1:

        | cmp param2, param3
        | jge >2 // Exit if i >= buffer_count (aka continue while i < buffer_count)

        // param6 -> hashOut[ctx->hashctr]
        | mov param5, [rbp-hashCountOffset]
        | mov param6, [rhHashOut + param5 * 4]

        // param1 -> ctx->vars.elems[i]
        | lea param1, [rbp-varsBufferOffset]
        | mov param1, [param1 + param2 * 4]

        // hashOut[ctx->hashctr] += ctx->vars.elems[i];
        | add param6, param1
        | mov [rhHashOut + param5 * 4], r9d

        // ctx->hashctr = (ctx->hashctr + 1) % RandHash_INOUT_SZ;
        | add param5, 1
        | and param5, (RandHash_INOUT_SZ - 1) // modulo RandHash_INOUT_SZ which is a power of 2
        | mov [rbp-hashCountOffset], param5

        | inc param2 // i++
        | jmp <1

        | 2:

        //ctx->vars.count -= ctx->varCount;
        //ctx->varCount = Vec_pop(&ctx->scopes);

        | mov param1, [rbp-scopeVarCountOffset]
        | mov param2, [rbp-varsCountOffset]

        | sub param2, param1
        | dec param2

        | mov [rbp-varsCountOffset], param2

        | mov param2, [rbp-scopeCountOffset]
        | lea param1, [rbp-scopeBufferOffset]

        | dec param2
        | mov [rbp-scopeCountOffset], param2

        | mov param6, [param1 + param2 * 4]
        | mov [rbp-scopeVarCountOffset], r9d
        return pc;
      }

      case OpCode_POPCNT8 : {
        rh_get_a(state, insn);
        | mov     esi, edi
        | mov     eax, edi
        | mov     edx, edi
        | shr     esi, 16
        | shr     eax, 24
        | movzx   ecx, dh
        | popcnt  eax, eax
        | movzx   esi, r6b
        | sal     eax, 8
        | movzx   edx, r7b
        | popcnt  esi, esi
        | popcnt  ecx, ecx
        | or      eax, esi
        | sal     ecx, 8
        | sal     eax, 16
        | popcnt  edx, edx
        | or      edx, ecx
        | or      eax, edx
        rh_out_1_var(state);
      break; }
      case OpCode_POPCNT16 : {
        rh_get_a(state, insn);
        | mov     eax, edi
        | shr     eax, 16
        | popcnt  eax, eax
        | popcnt  di, di
        | sal     eax, 16
        | movzx   edi, di
        | or      eax, edi
        rh_out_1_var(state);
      break; }
      case OpCode_POPCNT32 : {
        rh_get_a(state, insn);
        | popcnt r0d, r7d
        rh_out_1_var(state);
      break; }

      case OpCode_CLZ8 : {
        rh_get_a(state, insn);
        | mov     edx, edi
        | shr     edx, 16
        | mov     esi, edi
        | shr     esi, 24
        | mov     cl, 8
        | mov     al, 8
        | je      >1
        | movzx   eax, r6b
        | bsr     eax, eax
        | xor     eax, 7
        | 1:
        | movzx   eax, al
        | test    dl, dl
        | je      >2
        | movzx   ecx, dl
        | bsr     ecx, ecx
        | xor     ecx, 7
        | 2:
        | movzx   edx, cl
        | shl     eax, 24
        | shl     edx, 16
        | mov     ecx, edi
        | shr     ecx, 8
        | mov     r8b, 8
        | mov     r6b, 8
        | test    cl, cl
        | je      >3
        | movzx   ecx, cl
        | bsr     esi, ecx
        | xor     esi, 7
        | 3:
        | or      eax, edx
        | movzx   edx, r6b
        | shl     edx, 8
        | test    r7b , r7b
        | je      >4
        | movzx   ecx, r7b
        | bsr     r8d, ecx
        | xor     r8d, 7
        | 4:
        | movzx   ecx, r8b
        | or      edx, ecx
        | or      eax, edx
        rh_out_1_var(state);
      break; }
      case OpCode_CLZ16 : {
        rh_get_a(state, insn);
        | mov     edx, edi
        | shr     edx, 16
        | mov     cx, 16
        | mov     ax, 16
        | je      >1
        | bsr     ax, dx
        | xor     eax, 15
        | 1:
        | shl     eax, 16
        | test    di, di
        | je      >2
        | bsr     cx, di
        | xor     ecx, 15
        | 2:
        | movzx   ecx, cx
        | or      eax, ecx
        rh_out_1_var(state);
      break; }
      case OpCode_CLZ32 : {
        rh_get_a(state, insn);
        | mov     eax, 32
        | test    edi, edi
        | je      >1
        | bsr     eax, edi
        | xor     eax, 31
        | 1:
        rh_out_1_var(state);
      break; }

      case OpCode_CTZ8 : {
        rh_get_a(state, insn);
        | mov     ecx, edi
        | shr     ecx, 16
        | mov     eax, edi
        | shr     eax, 24
        | mov     dl,  8
        | mov     r6b, 8
        | je      >1
        | movzx   eax, al
        | bsf     esi, eax
        | 1:
        | movzx   eax, r6b
        | test    cl,  cl
        | je      >2
        | movzx   ecx, cl
        | bsf     edx, ecx
        | 2:
        | movzx   edx, dl
        | shl     eax, 24
        | shl     edx, 16
        | mov     ecx, edi
        | shr     ecx, 8
        | mov     r8b, 8
        | mov     r6b, 8
        | test    cl,  cl
        | je      >3
        | movzx   ecx, cl
        | bsf     esi, ecx
        | 3:
        | or      eax, edx
        | movzx   edx, r6b
        | shl     edx, 8
        | test    r7b, r7b
        | je      >4
        | movzx   ecx, r7b
        | bsf     r8d, ecx
        | 4:
        | movzx   ecx, r8b
        | or      edx, ecx
        | or      eax, edx
        rh_out_1_var(state);
      break; }
      case OpCode_CTZ16 : {
        rh_get_a(state, insn);
        | mov     edx, edi
        | shr     edx, 16
        | mov     cx, 16
        | mov     ax, 16
        | je      >1
        | bsf     ax, dx
        | 1:
        | shl     eax, 16
        | test    di, di
        | je      >2
        | bsf     cx, di
        | 2:
        | movzx   ecx, cx
        | or      eax, ecx
        rh_out_1_var(state);
      break; }
      case OpCode_CTZ32 : {
        rh_get_a(state, insn);
        | mov     eax, 32
        | test    edi, edi
        | je      >1
        | bsf     eax, edi
        | 1:
        rh_out_1_var(state);
      break; }

      case OpCode_BSWAP16 : {
        rh_get_a(state, insn);
        | mov     eax, edi
        | rol     eax, 16
        | bswap   eax
        rh_out_1_var(state);
      break; }

      case OpCode_BSWAP32 : {
        rh_get_a(state, insn);
        | bswap r7d
        | mov eax, r7d
        rh_out_1_var(state);
      break; }

      //////////////////////////////////////////////////////////////////////

      case OpCode_ADD8 : {
        rh_get_ab(state, insn);
        | mov     eax, esi
        | mov     ecx, esi
        | and     ecx, 65280
        | add     ecx, edi
        | add     esi, edi
        | shr     edi, 16
        | shr     eax, 16
        | mov     edx, eax
        | and     edx, 65280
        | add     edx, edi
        | and     edx, 65280
        | add     eax, edi
        | movzx   edi, al
        | or      edi, edx
        | shl     edi, 16
        | and     ecx, 65280
        | movzx   eax, r6b
        | or      eax, ecx
        | or      eax, edi
        rh_out_1_var(state);
      break; }
      case OpCode_ADD16 : {
        rh_get_ab(state, insn);
        | mov     ecx, esi
        | and     ecx, -65536
        | add     ecx, edi
        | and     ecx, -65536
        | add     esi, edi
        | movzx   eax, si
        | or      eax, ecx
        rh_out_1_var(state);
      break; }
      case OpCode_ADD32 : {
        rh_get_ab(state, insn);
        | add r7d, r6d
        | mov r0d, r7d
        rh_out_1_var(state);
      break; }

      case OpCode_SUB8 : {
        rh_get_ab(state, insn);
        | mov     ecx, edi
        | shr     ecx, 16
        | mov     r8d, esi
        | mov     edx, edi
        | sub     edi, esi
        | shr     esi, 16
        | mov     eax, ecx
        | sub     ecx, esi
        | and     esi, 65280
        | sub     eax, esi
        | and     eax, 65280
        | movzx   ecx, cl
        | or      ecx, eax
        | shl     ecx, 16
        | and     r8d, 65280
        | sub     edx, r8d
        | and     edx, 65280
        | movzx   eax, r7b
        | or      eax, edx
        | or      eax, ecx
        rh_out_1_var(state);
      break; }
      case OpCode_SUB16 : {
        rh_get_ab(state, insn);
        | mov     ecx, edi
        | sub     edi, esi
        | and     esi, -65536
        | sub     ecx, esi
        | and     ecx, -65536
        | movzx   eax, di
        | or      eax, ecx
        rh_out_1_var(state);
      break; }
      case OpCode_SUB32 : {
        rh_get_ab(state, insn);
        | sub r7d, r6d
        | mov eax, r7d
        rh_out_1_var(state);
      break; }

      case OpCode_SHLL8 : {
        rh_get_ab(state, insn);
        | mov     r8d, esi
        | mov     edx, edi
        | shr     edx, 16
        | mov     eax, esi
        | shr     eax, 16
        | mov     esi, edi
        | shr     esi, 24
        | mov     ecx, r8d
        | shr     ecx, 24
        | and     cl, 7
        | shl     r6b, cl
        | and     al, 7
        | mov     ecx, eax
        | shl     dl, cl
        | movzx   eax, r6b
        | movzx   edx, dl
        | shl     eax, 24
        | shl     edx, 16
        | or      edx, eax
        | mov     eax, edi
        | shr     eax, 8
        | mov     ecx, r8d
        | shr     ecx, 8
        | and     cl, 7
        | shl     al, cl
        | movzx   esi, al
        | and     r8b, 7
        | mov     ecx, r8d
        | shl     r7b, cl
        | shl     esi, 8
        | movzx   eax, r7b
        | or      eax, esi
        | or      eax, edx
        rh_out_1_var(state);
      break; }
      case OpCode_SHLL16 : {
        rh_get_ab(state, insn);
        | mov     edx, edi
        | shr     edx, 16
        | mov     ecx, esi
        | shr     ecx, 16
        | and     cl,  15
        | shl     edx, cl
        | and     r6b, 15
        | mov     ecx, esi
        | shl     edi, cl
        | shl     edx, 16
        | movzx   eax, di
        | or      eax, edx
        rh_out_1_var(state);
      break; }
      case OpCode_SHLL32 : {
        rh_get_ab(state, insn);
        | mov cl, r6b
        | sal r7d, cl
        | mov r0d, r7d
        rh_out_1_var(state);
      break; }

      case OpCode_SHRL8 : {
        rh_get_ab(state, insn);
        | mov     r8d, esi
        | mov     edx, edi
        | shr     edx, 16
        | mov     eax, esi
        | shr     eax, 16
        | mov     esi, edi
        | shr     esi, 24
        | mov     ecx, r8d
        | shr     ecx, 24
        | and     cl,  7
        | shr     r6b, cl
        | and     al,  7
        | mov     ecx, eax
        | shr     dl,  cl
        | movzx   eax, r6b
        | movzx   edx, dl
        | shl     eax, 24
        | shl     edx, 16
        | or      edx, eax
        | mov     eax, edi
        | shr     eax, 8
        | mov     ecx, r8d
        | shr     ecx, 8
        | and     cl,  7
        | shr     al,  cl
        | movzx   esi, al
        | and     r8b, 7
        | mov     ecx, r8d
        | shr     r7b, cl
        | shl     esi, 8
        | movzx   eax, r7b
        | or      eax, esi
        | or      eax, edx
        rh_out_1_var(state);
      break; }
      case OpCode_SHRL16 : {
        rh_get_ab(state, insn);
        | mov     edx, edi
        | shr     edx, 16
        | mov     ecx, esi
        | shr     ecx, 16
        | and     cl, 15
        | shr     edx, cl
        | movzx   eax, di
        | shl     edx, 16
        | and     r6b, 15
        | mov     ecx, esi
        | shr     eax, cl
        | or      eax, edx
        rh_out_1_var(state);
      break; }
      case OpCode_SHRL32 : {
        rh_get_ab(state, insn);
        | mov cl, r6b
        | shr r7d, cl
        | mov r0d, r7d
        rh_out_1_var(state);
      break; }

      case OpCode_SHRA8 : {
        rh_get_ab(state, insn);
        | mov     r8d, esi
        | mov     edx, edi
        | shr     edx, 16
        | mov     eax, esi
        | shr     eax, 16
        | mov     esi, edi
        | shr     esi, 24
        | mov     ecx, r8d
        | shr     ecx, 24
        | and     cl, 7
        | sar     r6b, cl
        | and     al, 7
        | mov     ecx, eax
        | sar     dl, cl
        | movzx   eax, r6b
        | movzx   edx, dl
        | shl     eax, 24
        | shl     edx, 16
        | or      edx, eax
        | mov     eax, edi
        | shr     eax, 8
        | mov     ecx, r8d
        | shr     ecx, 8
        | and     cl, 7
        | sar     al, cl
        | movzx   esi, al
        | and     r8b, 7
        | mov     ecx, r8d
        | sar     r7b, cl
        | shl     esi, 8
        | movzx   eax, r7b
        | or      eax, esi
        | or      eax, edx
        rh_out_1_var(state);
      break; }
      case OpCode_SHRA16 : {
        rh_get_ab(state, insn);
        | movsx   eax, di
        | sar     edi, 16
        | mov     ecx, esi
        | shr     ecx, 16
        | and     cl, 15
        | sar     edi, cl
        | and     r6d, 15
        | mov     ecx, esi
        | sar     eax, cl
        | shl     edi, 16
        | movzx   eax, ax
        | or      eax, edi
        rh_out_1_var(state);
      break; }
      case OpCode_SHRA32 : {
        rh_get_ab(state, insn);
        | mov cl, r6b
        | sar r7d, cl
        | mov r0d, r7d
        rh_out_1_var(state);
      break; }

      case OpCode_ROTL8 : {
        rh_get_ab(state, insn);
        | mov     r8d, esi
        | mov     edx, edi
        | shr     edx, 16
        | mov     eax, esi
        | shr     eax, 16
        | mov     esi, edi
        | shr     esi, 24
        | mov     ecx, r8d
        | shr     ecx, 24
        | rol     r6b, cl
        | movzx   esi, r6b
        | mov     ecx, eax
        | rol     dl, cl
        | movzx   edx, dl
        | shl     esi, 24
        | shl     edx, 16
        | or      edx, esi
        | mov     eax, edi
        | shr     eax, 8
        | mov     ecx, r8d
        | shr     ecx, 8
        | rol     al, cl
        | movzx   esi, al
        | mov     ecx, r8d
        | rol     r7b, cl
        | shl     esi, 8
        | movzx   eax, r7b
        | or      eax, esi
        | or      eax, edx
        rh_out_1_var(state);
      break; }
      case OpCode_ROTL16 : {
        rh_get_ab(state, insn);
        | mov     edx, edi
        | shr     edx, 16
        | mov     ecx, esi
        | shr     ecx, 16
        | rol     dx, cl
        | mov     ecx, esi
        | rol     di, cl
        | shl     edx, 16
        | movzx   eax, di
        | or      eax, edx
        rh_out_1_var(state);
      break; }
      case OpCode_ROTL32 : {
        rh_get_ab(state, insn);
        | mov cl, r6b
        | rol r7d, cl
        | mov r0d, r7d
        rh_out_1_var(state);
      break; }

      case OpCode_MUL8 : {
        rh_get_ab(state, insn);
        | push    rbx
        | mov     eax, esi
        | mov     ecx, esi
        | mov     edx, esi
        | mov     esi, edi
        | movzx   ebx, ah
        | imul    eax, edi
        | shr     edi, 16
        | shr     ecx, 16
        | imul    ecx, edi
        | and     edi, 65280
        | shr     edx, 24
        | imul    edx, edi
        | movzx   ecx, cl
        | or      ecx, edx
        | shl     ecx, 16
        | and     esi, -256
        | imul    ebx, esi
        | movzx   eax, al
        | or      eax, ebx
        | movzx   eax, ax
        | or      eax, ecx
        | pop     rbx
        rh_out_1_var(state);
      break; }
      case OpCode_MUL16 : {
        rh_get_ab(state, insn);
        | mov     ecx, esi
        | imul    esi, edi
        | and     edi, -65536
        | shr     ecx, 16
        | imul    ecx, edi
        | movzx   eax, si
        | or      eax, ecx
        rh_out_1_var(state);
      break; }

      case OpCode_MUL32 : {
        rh_get_ab(state, insn);
        | imul r7d, r6d
        | mov  r0d, r7d
        rh_out_1_var(state);
      break; }

      case OpCode_AND : {
        rh_get_ab(state, insn);
        | and r7d, r6d
        | mov r0d, r7d
        rh_out_1_var(state);
      break; }
      case OpCode_OR : {
        rh_get_ab(state, insn);
        | or  r7d, r6d
        | mov r0d, r7d
        rh_out_1_var(state);
      break; }
      case OpCode_XOR : {
        rh_get_ab(state, insn);
        | xor r7d, r6d
        | mov r0d, r7d
        rh_out_1_var(state);
      break; }

      //////////////////////////////////////////////////////////////////////

      case OpCode_ADD8C : {
       rh_get_ab(state, insn);
       | push    rbp
       | push    rbx
       | mov     ecx, esi
       | mov     eax, edi
       | mov     edx, edi
       | movzx   ebp, ah
       | movzx   edi, al
       | mov     esi, eax
       | shr     esi, 16
       | shr     edx, 24
       | mov     ebx, ecx
       | shr     ebx, 24
       | add     ebx, edx
       | movzx   edx, ch
       | movzx   eax, cl
       | shr     ecx, 16
       | movzx   esi, r6b
       | movzx   ecx, cl
       | add     ecx, esi
       | shl     ebx, 16
       | or      ecx, ebx
       | shl     rcx, 32
       | add     edx, ebp
       | shl     edx, 16
       | add     eax, edi
       | or      eax, edx
       | or      rax, rcx
       | pop     rbx
       | pop     rbp
       rh_out_2_var(state);
      break; }
      case OpCode_ADD16C : {
        rh_get_ab(state, insn);
        | movzx   ecx, di
        | shr     edi, 16
        | movzx   eax, si
        | mov     edx, esi
        | shr     edx, 16
        | add     edx, edi
        | shl     rdx, 32
        | add     eax, ecx
        | or      rax, rdx
        rh_out_2_var(state);
      break; }
      case OpCode_ADD32C : {
        rh_get_ab(state, insn);
        | mov eax, r7d
        | mov edx, r6d
        | add rax, rdx
        rh_out_2_var(state);
      break; }
      case OpCode_SUB8C : {
        rh_get_ab(state, insn);
        | push    rbx
        | mov     eax, esi
        | mov     edx, edi
        | mov     ecx, edi
        | movzx   esi, dh
        | movzx   edi, dl
        | shr     edx, 16
        | shr     ecx, 24
        | mov     ebx, eax
        | shr     ebx, 24
        | sub     ecx, ebx
        | movzx   ebx, ah
        | movzx   r8d, al
        | shr     eax, 16
        | movzx   edx, dl
        | movzx   eax, al
        | sub     edx, eax
        | shl     ecx, 16
        | movzx   edx, dx
        | or      edx, ecx
        | shl     rdx, 32
        | sub     esi, ebx
        | shl     esi, 16
        | sub     edi, r8d
        | movzx   eax, di
        | or      eax, esi
        | or      rax, rdx
        | pop     rbx
        rh_out_2_var(state);
      break; }
      case OpCode_SUB16C : {
        rh_get_ab(state, insn);
        | movzx   eax, di
        | mov     ecx, edi
        | shr     ecx, 16
        | movzx   edx, si
        | shr     esi, 16
        | sub     ecx, esi
        | shl     rcx, 32
        | sub     eax, edx
        | or      rax, rcx
        rh_out_2_var(state);
      break; }
      case OpCode_SUB32C : {
        rh_get_ab(state, insn);
        | mov eax, r7d
        | mov edx, r6d
        | sub rax, rdx
        rh_out_2_var(state);
      break; }
      case OpCode_MUL8C : {
        rh_get_ab(state, insn);
        | mov     eax, edi
        | movsx   ecx, di
        | shr     edi, 16
        | mov     edx, esi
        | movsx   r8d, si
        | shr     esi, 16
        | sar     eax, 24
        | sar     edx, 24
        | imul    edx, eax
        | movsx   eax, r7b
        | movsx   esi, r6b
        | imul    esi, eax
        | movzx   esi, si
        | shl     rdx, 48
        | shl     rsi, 32
        | or      rsi, rdx
        | movsx   eax, cl
        | sar     ecx, 8
        | movsx   edx, r8b
        | mov     edi, r8d
        | sar     edi, 8
        | imul    edi, ecx
        | movzx   ecx, di
        | shl     rcx, 16
        | imul    edx, eax
        | movzx   eax, dx
        | or      rax, rcx
        | or      rax, rsi
        rh_out_2_var(state);
      break; }
      case OpCode_MUL16C : {
        rh_get_ab(state, insn);
        | movsx   ecx, di
        | sar     edi, 16
        | movsx   eax, si
        | mov     edx, esi
        | sar     edx, 16
        | imul    edx, edi
        | shl     rdx, 32
        | imul    eax, ecx
        | or      rax, rdx
        rh_out_2_var(state);
      break; }
      case OpCode_MUL32C : {
        rh_get_ab(state, insn);
        |  movsxd rax, r7d
        |  movsxd rsi, r6d
        |  imul   rax, rsi
        rh_out_2_var(state);
      break; }
      case OpCode_MULSU8C : {
        rh_get_ab(state, insn);
        | push    rbx
        | mov     eax, esi
        | mov     ecx, edi
        | movsx   esi, di
        | shr     edi, 16
        | mov     edx, eax
        | shr     edx, 24
        | sar     ecx, 24
        | imul    ecx, edx
        | movzx   ebx, ah
        | movzx   edx, al
        | shr     eax, 16
        | movsx   edi, r7b
        | movzx   eax, al
        | imul    eax, edi
        | movzx   edi, ax
        | shl     rcx, 48
        | shl     rdi, 32
        | or      rdi, rcx
        | movsx   eax, r6b
        | mov     ecx, esi
        | sar     ecx, 8
        | imul    ecx, ebx
        | movzx   ecx, cx
        | shl     rcx, 16
        | imul    edx, eax
        | movzx   eax, dx
        | or      rax, rcx
        | or      rax, rdi
        | pop     rbx
        rh_out_2_var(state);
      break; }
      case OpCode_MULSU16C : {
        rh_get_ab(state, insn);
        | movzx   eax, si
        | shr     esi, 16
        | movsx   ecx, di
        | mov     edx, edi
        | sar     edx, 16
        | imul    edx, esi
        | shl     rdx, 32
        | imul    eax, ecx
        | or      rax, rdx
        rh_out_2_var(state);
      break; }
      case OpCode_MULSU32C : {
        rh_get_ab(state, insn);
        | movsxd rdx, r7d
        | mov    r0d, r6d
        | imul   rax, rdx
        rh_out_2_var(state);
      break; }
      case OpCode_MULU8C : {
        rh_get_ab(state, insn);
        | push    rbp
        | push    rbx
        | mov     ecx, esi
        | mov     eax, edi
        | mov     edx, edi
        | movzx   ebx, ah
        | movzx   edi, al
        | mov     esi, eax
        | shr     esi, 16
        | mov     eax, ecx
        | shr     eax, 24
        | shr     edx, 8
        | and     edx, 16711680
        | imul    edx, eax
        | movzx   ebp, ch
        | movzx   eax, cl
        | shr     ecx, 16
        | movzx   esi, r6b
        | movzx   ecx, cl
        | imul    ecx, esi
        | or      ecx, edx
        | shl     rcx, 32
        | imul    ebp, ebx
        | shl     ebp, 16
        | imul    eax, edi
        | or      eax, ebp
        | or      rax, rcx
        | pop     rbx
        | pop     rbp
        rh_out_2_var(state);
      break; }
      case OpCode_MULU16C : {
        rh_get_ab(state, insn);
        | movzx   ecx, di
        | shr     edi, 16
        | movzx   eax, si
        | mov     edx, esi
        | shr     edx, 16
        | imul    edx, edi
        | shl     rdx, 32
        | imul    eax, ecx
        | or      rax, rdx
        rh_out_2_var(state);
      break; }
      case OpCode_MULU32C : {
        rh_get_ab(state, insn);
        | mov  r0d, r7d
        | mov  r2d, r6d
        | imul rax, rdx
        rh_out_2_var(state);
      break; }

      //////////////////////////////////////////////////////////////////////

      case OpCode_ADD64 : {
        rh_get_a2b2(state, insn);
        | add r7, r6
        | mov r0, r7
        rh_out_2_var(state);
      break; }
      case OpCode_SUB64 : {
        rh_get_a2b2(state, insn);
        | sub r7, r6
        | mov r0, r7
        rh_out_2_var(state);
      break; }
      case OpCode_SHLL64 : {
        rh_get_a2b2(state, insn);
        | mov cl, r6b
        | shl r7, cl
        | mov r0, r7
        rh_out_2_var(state);
      break; }
      case OpCode_SHRL64 : {
        rh_get_a2b2(state, insn);
        | mov cl, r6b
        | shr r7, cl
        | mov r0, r7
        rh_out_2_var(state);
      break; }
      case OpCode_SHRA64 : {
        rh_get_a2b2(state, insn);
        | mov rax, rdi
        | mov ecx, esi
        | sar rax, cl
        rh_out_2_var(state);
      break; }
      case OpCode_ROTL64 : {
        rh_get_a2b2(state, insn);
        | mov cl, r6b
        | rol r7, cl
        | mov r0, r7
        rh_out_2_var(state);
      break; }
      case OpCode_ROTR64 : {
        rh_get_a2b2(state, insn);
        | mov cl, r6b
        | ror r7, cl
        | mov r0, r7
        rh_out_2_var(state);
      break; }
      case OpCode_MUL64 : {
        rh_get_a2b2(state, insn);
        | imul r7, r6
        | mov  r0, r7
        rh_out_2_var(state);
      break; }

      //////////////////////////////////////////////////////////////////////

      case OpCode_ADD64C : {
        rh_get_a2b2(state, insn);
        | mov  rax, r7
        | xor  edx, edx
        | add  rax, r6
        | setc dl
        rh_out_4_var(state);
      break; }
      case OpCode_SUB64C : {
        rh_get_a2b2(state, insn);
        | mov rax, r7
        | sub rax, r6
        | cmp r7,  r6
        | sbb rdx, rdx
        rh_out_4_var(state);
      break; }
      case OpCode_MUL64C : {
        rh_get_a2b2(state, insn);
        | mov     rcx, rsi
        | mov     rax, rdi
        | mov     rsi, rdi
        | imul    rsi, rcx
        | mov     r9,  rcx
        | neg     rax
        | cmovs   rax, rdi
        | neg     r9
        | cmovs   r9,  rcx
        | mov     r8,  rax
        | mov     eax, eax
        | mov     r11, r9
        | shr     r8,  32
        | mov     r9d, r9d
        | shr     r11, 32
        | mov     r10, r8
        | mov     rdx, r11
        | imul    r10, r9
        | imul    rdx, rax
        | imul    rax, r9
        | imul    r8, r11
        | mov     r9d, edx
        | shr     rdx, 32
        | shr     rax, 32
        | add     rax, r9
        | mov     r9d, r10d
        | shr     r10, 32
        | add     rax, r9
        | add     rdx, r10
        | mov     r9d, r8d
        | shr     r8,  32
        | add     rdx, r9
        | shr     rax, 32
        | add     rax, rdx
        | mov     rdx, rax
        | mov     eax, eax
        | shr     rdx, 32
        | add     edx, r8d
        | mov     edx, edx
        | sal     rdx, 32
        | or      rdx, rax
        | xor     rcx, rdi
        | jns     >1
        | mov     rax, rdx
        | neg     rdx
        | test    rsi, rsi
        | not     rax
        | cmovne  rdx, rax
        | 1:
        | mov     rax, rsi
        rh_out_4_var(state);
      break; }
      case OpCode_MULSU64C : {
        rh_get_a2b2(state, insn);
        | mov     rcx, rdi
        | mov     rax, rdi
        | mov     r8,  rdi
        | mov     r10, rsi
        | imul    rcx, rsi
        | neg     rax
        | mov     esi, esi
        | cmovns  rdi, rax
        | shr     r10, 32
        | mov     rax, r10
        | mov     rdx, rdi
        | mov     edi, edi
        | shr     rdx, 32
        | imul    rax, rdi
        | mov     r9,  rdx
        | imul    rdi, rsi
        | imul    r9,  rsi
        | imul    rdx, r10
        | mov     esi, eax
        | shr     rax, 32
        | shr     rdi, 32
        | add     rdi, rsi
        | mov     esi, r9d
        | shr     r9,  32
        | add     rdi, rsi
        | add     rax, r9
        | mov     esi, edx
        | shr     rdx, 32
        | add     rax, rsi
        | shr     rdi, 32
        | add     rax, rdi
        | mov     rsi, rax
        | mov     eax, eax
        | shr     rsi, 32
        | add     edx, esi
        | mov     edx, edx
        | sal     rdx, 32
        | or      rdx, rax
        | test    r8,  r8
        | jns     >1
        | mov     rax, rdx
        | neg     rdx
        | test    rcx, rcx
        | not     rax
        | cmovne  rdx, rax
        | 1:
        | mov     rax, rcx
        rh_out_4_var(state);
      break; }
      case OpCode_MULU64C : {
        rh_get_a2b2(state, insn);
        | mov     r9,  rsi
        | mov     rcx, rdi
        | mov     rdx, rdi
        | mov     edi, edi
        | shr     r9,  32
        | imul    rcx, rsi
        | shr     rdx, 32
        | mov     esi, esi
        | mov     rax, r9
        | mov     r8,  rdx
        | imul    rax, rdi
        | imul    rdi, rsi
        | imul    r8,  rsi
        | imul    rdx, r9
        | mov     esi, eax
        | shr     rax, 32
        | shr     rdi, 32
        | add     rdi, rsi
        | mov     esi, r8d
        | shr     r8,  32
        | add     rdi, rsi
        | add     rax, r8
        | mov     esi, edx
        | shr     rdx, 32
        | add     rax, rsi
        | shr     rdi, 32
        | add     rax, rdi
        | mov     rsi, rax
        | mov     eax, eax
        | shr     rsi, 32
        | add     edx, esi
        | mov     edx, edx
        | sal     rdx, 32
        | or      rdx, rax
        | mov     rax, rcx
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

  | mov param2, 1              // Used as a flag to specify if we should exit the program or not (0 means yes)
  | ->rh_entry:                // Entry to the program

  | push param2                // Save the exit flag before calling any function
  | mov qword [rbp-hashCountOffset], 0

  rh_main_loop(0, state);      // Generate the JIT code starting at instruction 0 on the tape
  | pop param2                 // Restore the exit flag

  | xchg rhHashIn, rhHashOut   // Swap hashIn and hashOut

  | cmp param2, 0              // Check if exit flag is set
  | je ->rh_exit               // If exit flag is set, exit the program

  | mov param2, 0              // If exit flag was not set, set the exit flag so that next run exits
  | jmp ->rh_entry             // Rerun the program once more

  | ->rh_exit:                 // Jump to this global flag to exit the program
}

// Start the JIT process for the RandHash program
static inline void rh_jit(rh_state_compile_t* state)
{
  // Subsequent asm lines are rewritten to dasm_put(Dst, ...), we need this variable to reference the state
  dasm_State** Dst = &state->dynasm_state;

  // Start code section and write the main for our program
  | .code
  | ->rh_main:

  // SYSTEM V ABI forces us to save callee-save registers to avoid stack corruption
  | prologue

  // Shortcut registers for frequently used addresses, so we don't have to go to the cache all the time
  | mov rhMemory,  param1
  | mov rhHashIn,  param2
  | mov rhHashOut, param3

  // Align memory to 8 bytes as this program is only expected to run on x86_64
  | .align qword

  // Start unrolling and generating the ASM associated with the RandHash program
  rh_unroll(state);

  // Restore the registers we saved at the start of the program to avoid stack corruption
  | epilogue
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

  | .actionlist rh_actions
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