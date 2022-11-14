# RandHash JIT

- Executes **RandHash** programs using internally-generated x64 assembly
- Runs at least twice faster than the interpreter on most programs
- Compilation time on the order of a millisecond or less
- No reliance on external functions
- All operands reimplemented
- Internal ABI
- Internal stack frame, no reliance on C structures passed through addresses
- Plug and play, not tightly coupled

## How to modify the JIT
- Edit the code in ```JIT/JIT.c``` or ```JIT/JIT.h```
- Regenerate the ```JIT.posix64.c``` file using the following command:
```
git clone https://luajit.org/git/luajit.git
cd luajit
git checkout v2.0.5
make
./src/host/minilua ./dynasm/dynasm.lua -o ../packetcrypt-sys/packetcrypt/src/JIT/JIT.posix64.c \
    -D X64 ../packetcrypt-sys/packetcrypt/src/JIT/JIT.c
```

Note: **DynASM/ASM** code can only be written in the ```JIT.c``` file. It must then be converted to **DynASM** functions using the above command.

## Cargo features
The JIT is included in the miner at compile-time only if the Cargo ```jit``` feature is selected.  
```./do --jit``` will automatically compile using the JIT, otherwise the native interpreter is used.  
The JIT miner can also be built using ```cargo build --release --features jemalloc --features jit```

## Author
Michel Blanc - 2021   
[RandGen.xyz](https://RandGen.xyz) - [contact@randgen.xyz](contact@randgen.xyz)