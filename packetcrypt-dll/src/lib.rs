#[no_mangle]
pub static packetcrypt_Validate_checkBlock_outToString:
    unsafe extern "C" fn(i32) -> *mut i8 =
        packetcrypt_sys::Validate_checkBlock_outToString;

#[no_mangle]
pub static packetcrypt_ValidateCtx_create:
    unsafe extern "C" fn() -> *mut packetcrypt_sys::PacketCrypt_ValidateCtx_s =
        packetcrypt_sys::ValidateCtx_create;

#[no_mangle]
pub static packetcrypt_ValidateCtx_destroy:
    unsafe extern "C" fn(*mut packetcrypt_sys::PacketCrypt_ValidateCtx_s) =
        packetcrypt_sys::ValidateCtx_destroy;

#[no_mangle]
pub static packetcrypt_Validate_checkBlock: unsafe extern "C" fn(
    *const packetcrypt_sys::PacketCrypt_HeaderAndProof_t,
    u32,
    u32,
    u32,
    *const packetcrypt_sys::PacketCrypt_Coinbase_t,
    *const u8,
    *mut u8,
    *mut packetcrypt_sys::PacketCrypt_ValidateCtx_s
) -> i32 = packetcrypt_sys::Validate_checkBlock;

#[no_mangle]
pub unsafe fn packetcrypt_init() {
    packetcrypt_sys::init();
}
