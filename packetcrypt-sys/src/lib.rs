#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

pub use sodiumoxide;

pub mod difficulty;

use bytes::{BufMut, BytesMut};
use packetcrypt_util::util;

use std::convert::TryInto;

include!("../bindings.rs");

pub fn init() {
    sodiumoxide::init().unwrap();
}

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

pub fn hard_nonce(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(bytes[4..8].try_into().unwrap())
}
pub fn work_bits(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(bytes[8..12].try_into().unwrap())
}
pub fn parent_block_height(bytes: &[u8]) -> i32 {
    i32::from_le_bytes(bytes[12..16].try_into().unwrap())
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

pub fn check_block_work(
    header: &[u8],
    low_nonce: u32,
    share_target: u32,
    anns: &[[u8; 1024]],
    coinbase: &[u8],
    mining_height: i32,
    proof: &[u8],
) -> Result<[u8; 32], String> {
    let mut hap = BytesMut::with_capacity(80 + 8 + (1024 * 4) + proof.len());
    hap.put(header);
    hap.put_u32_le(0);
    hap.put_u32_le(low_nonce);
    for ann in anns.iter() {
        hap.put(&ann[..]);
    }
    assert!(hap.len() == 80 + 8 + (1024 * 4));
    hap.put(proof);
    let aligned_hap = util::aligned_bytes(&hap, 8);
    let aligned_coinbase = util::aligned_bytes(coinbase, 8);
    let mut hashout = [0_u8; 32];
    let res = unsafe {
        Validate_checkBlock(
            aligned_hap.as_ptr() as *const PacketCrypt_HeaderAndProof_t,
            aligned_hap.len() as u32,
            mining_height as u32,
            share_target,
            aligned_coinbase.as_ptr() as *const PacketCrypt_Coinbase_t,
            std::ptr::null(),
            hashout.as_mut_ptr(),
            std::ptr::null_mut::<PacketCrypt_ValidateCtx_t>(),
        )
    } as u32;
    match res {
        Validate_checkBlock_Res_Validate_checkBlock_OK
        | Validate_checkBlock_Res_Validate_checkBlock_SHARE_OK => Ok(hashout),
        Validate_checkBlock_Res_Validate_checkBlock_INSUF_POW => {
            Err(format!("INSUF_POW {}", hex::encode(hashout)))
        }
        Validate_checkBlock_Res_Validate_checkBlock_PCP_INVAL => Err("PCP_INVAL".to_owned()),
        Validate_checkBlock_Res_Validate_checkBlock_PCP_MISMATCH => Err("PCP_MISMATCH".to_owned()),
        Validate_checkBlock_Res_Validate_checkBlock_BAD_COINBASE => Err("BAD_COINBASE".to_owned()),
        _ => {
            if let Some(x) = {
                match res & 0xff00 {
                    Validate_checkBlock_Res_Validate_checkBlock_ANN_INVALID_ => Some("ANN_INVALID"),
                    Validate_checkBlock_Res_Validate_checkBlock_ANN_INSUF_POW_ => {
                        Some("ANN_INSUF_POW")
                    }
                    Validate_checkBlock_Res_Validate_checkBlock_ANN_SIG_INVALID_ => {
                        Some("ANN_SIG_INVALID")
                    }
                    Validate_checkBlock_Res_Validate_checkBlock_ANN_CONTENT_INVALID_ => {
                        Some("ANN_CONTENT_INVALID")
                    }
                    _ => None,
                }
            } {
                Err(format!("{} {}", x, res & 0xff))
            } else {
                Err(format!("UNKNOWN {}", res))
            }
        }
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
