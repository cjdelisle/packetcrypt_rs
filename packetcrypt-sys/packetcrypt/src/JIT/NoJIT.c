#include "JIT.h"

#include <assert.h>

rh_jit_program_t* rh_generate_program(uint32_t* programBuffer, uint32_t programLength)
{
    programBuffer = programBuffer;
    programLength = programLength;
    assert(0 && "JIT not enabled");
}
void rh_run(uint32_t* programBuffer, int index, void* hashIn, void* hashOut, rh_jit_program_t* program)
{
    programBuffer = programBuffer;
    index = index;
    hashIn = hashIn;
    hashOut = hashOut;
    program = program;
    assert(0 && "JIT not enabled");
}
void rh_free_program(rh_jit_program_t* program)
{
    program = program;
    assert(0 && "JIT not enabled");
}
