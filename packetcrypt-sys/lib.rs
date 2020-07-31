#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use std::convert::TryInto;

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

pub struct ValidateCtx {
    raw: *mut PacketCrypt_ValidateCtx_t,
}
impl Drop for ValidateCtx {
    fn drop(&mut self) {
        unsafe {
            ValidateCtx_destroy(self.raw);
        }
    }
}
impl Default for ValidateCtx {
    fn default() -> ValidateCtx {
        ValidateCtx {
            raw: unsafe { ValidateCtx_create() },
        }
    }
}

#[derive(Clone, Debug)]
pub struct PacketCryptAnn {
    pub bytes: bytes::Bytes,
}
impl PacketCryptAnn {
    pub fn version(&self) -> u8 {
        self.bytes[0]
    }
    pub fn soft_nonce(&self) -> u32 {
        u32::from_le_bytes(self.bytes[..4].try_into().unwrap()) << 8
    }
    pub fn hard_nonce(&self) -> u32 {
        u32::from_le_bytes(self.bytes[4..8].try_into().unwrap())
    }
    pub fn work_bits(&self) -> u32 {
        u32::from_le_bytes(self.bytes[8..12].try_into().unwrap())
    }
    pub fn parent_block_height(&self) -> i32 {
        i32::from_le_bytes(self.bytes[12..16].try_into().unwrap())
    }
    pub fn content_hash(&self) -> &[u8] {
        &self.bytes[24..56]
    }
    pub fn signing_key(&self) -> &[u8] {
        &self.bytes[56..88]
    }
}

pub fn check_ann(
    ann: &PacketCryptAnn,
    parent_block_hash: &[u8; 32],
    vctx: &mut ValidateCtx,
) -> Result<[u8; 32], &'static str> {
    let mut hashout: [u8; 32] = [0; 32];
    let annptr = ann.bytes.as_ptr() as *const PacketCrypt_Announce_t;
    let res = unsafe {
        Validate_checkAnn(
            hashout.as_mut_ptr(),
            annptr,
            parent_block_hash.as_ptr(),
            vctx.raw,
        )
    };
    match res as i32 {
        0 => Ok(hashout),
        1 => Err("INVAL"),
        2 => Err("INVAL_ITEM4"),
        3 => Err("INSUF_POW"),
        4 => Err("SOFT_NONCE_HIGH"),
        _ => Err("UNKNOWN"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;
    #[test]
    fn basic_test() {
        let res = unsafe { CStr::from_ptr(Validate_checkBlock_outToString(256)).to_str() };
        assert_eq!("Validate_checkBlock_SHARE_OK", res.unwrap());
    }
}
