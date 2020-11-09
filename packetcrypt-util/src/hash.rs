// SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
use blake2b_simd::Params;
use sha2::{Digest, Sha256};
use std::convert::TryInto;

pub fn compress_sha256(buf: &[u8]) -> [u8; 32] {
    let mut s = Sha256::new();
    s.update(buf);
    s.finalize().try_into().unwrap()
}

pub fn compress32(buf: &[u8]) -> [u8; 32] {
    Params::new()
        .hash_length(32)
        .to_state()
        .update(buf)
        .finalize()
        .as_bytes()
        .try_into()
        .unwrap()
}
#[cfg(test)]
mod tests {
    use crate::hash;
    use blake2b_simd::blake2b;
    #[test]
    fn compress32_test() {
        assert_eq!((b"hello world").len(), 11);
        let hash = hash::compress32(b"hello world");
        let hex_hash = hex::encode(hash);
        assert_eq!(
            hex_hash,
            "256c83b297114d201b30179f3f0ef0cace9783622da5974326b436178aeef610"
        );
    }

    // This is moved into the test becuase it is currently unused
    fn compress64(buf: &[u8]) -> [u8; 64] {
        *blake2b(buf).as_array()
    }

    #[test]
    fn compress64_test() {
        assert_eq!((b"hello world").len(), 11);
        let hash = compress64(b"hello world");
        let hex_hash = hex::encode(&hash[..]);
        assert_eq!(
            hex_hash,
            concat!(
                "021ced8799296ceca557832ab941a50b4a11f83478cf141f51f933f653ab9fbc",
                "c05a037cddbed06e309bf334942c4e58cdf1a46e237911ccd7fcf9787cbc7fd0"
            )
        );
    }
}
