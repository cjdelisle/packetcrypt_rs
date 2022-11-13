#ifndef JIT_H
#define JIT_H

// RandGen.xyz  - JIT - 2021
// Michel Blanc - contact@randgen.xyz

#include "RandHash.h"
#include <stdint.h>

typedef struct rh_jit_program
{
    void     (*exec)(void*, void*, void*);
    void*    programBuffer;
    uint32_t length;
} rh_jit_program_t;

rh_jit_program_t* rh_generate_program(uint32_t* programBuffer, uint32_t programLength);
void rh_run(uint32_t* programBuffer, int index, void* hashIn, void* hashOut, rh_jit_program_t* program);
void rh_free_program(rh_jit_program_t* program);

#endif
