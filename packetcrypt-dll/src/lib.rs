#![allow(non_snake_case)]

#[no_mangle]
pub unsafe fn pc_Validate_checkBlock_outToString(x: i32) -> *mut i8 {
    packetcrypt_sys::Validate_checkBlock_outToString(x)
}

#[no_mangle]
pub unsafe fn pc_ValidateCtx_create() -> *mut packetcrypt_sys::PacketCrypt_ValidateCtx_s {
    packetcrypt_sys::ValidateCtx_create()
}

#[no_mangle]
pub unsafe fn pc_ValidateCtx_destroy(x: *mut packetcrypt_sys::PacketCrypt_ValidateCtx_s) {
    packetcrypt_sys::ValidateCtx_destroy(x)
}

#[no_mangle]
pub unsafe fn pc_Validate_checkBlock(
    a: *const packetcrypt_sys::PacketCrypt_HeaderAndProof_t,
    b: u32,
    c: u32,
    d: u32,
    e: *const packetcrypt_sys::PacketCrypt_Coinbase_t,
    f: *const u8,
    g: *mut u8,
    h: *mut packetcrypt_sys::PacketCrypt_ValidateCtx_s
) -> i32 {
    packetcrypt_sys::Validate_checkBlock(a,b,c,d,e,f,g,h)
}

#[no_mangle]
pub unsafe fn pc_init() {
    packetcrypt_sys::init();
}

#[cfg(all(target_os = "windows", target_arch = "x86", target_env = "gnu"))]
#[no_mangle]
pub extern "C" fn _Unwind_Resume(_ex_obj: *mut ()) {
    eprintln!("_Unwind_Resume() unsupported on this on this platform, aborting");
    std::process::abort();
}

#[cfg(all(target_os = "windows", target_arch = "x86", target_env = "gnu"))]
#[no_mangle]
pub extern "C" fn _Unwind_RaiseException(_ex_obj: *mut ()) {
    eprintln!("_Unwind_RaiseException() unsupported on this platform, aborting");
    std::process::abort();
}