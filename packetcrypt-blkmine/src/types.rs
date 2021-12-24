use packetcrypt_sys::sodiumoxide::crypto::generichash;
use std::convert::TryInto;
use std::ops::Deref;

#[derive(Default, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct AnnData {
    pub hash_pfx: u64,
    pub mloc: usize,
}

#[derive(Default, Copy, Clone)]
pub struct Hash([u64; 4]);

impl Hash {
    pub fn compute(&mut self, ann: &[u8]) {
        let digest = generichash::hash(ann, Some(32), None).unwrap();
        self.from_bytes(&digest[..]);
    }

    pub fn to_u64(&self) -> u64 {
        self.0[0]
    }

    pub fn from_bytes(&mut self, x: &[u8]) {
        self.0 = [
            u64::from_le_bytes(x[0..8].try_into().unwrap()),
            u64::from_le_bytes(x[8..16].try_into().unwrap()),
            u64::from_le_bytes(x[16..24].try_into().unwrap()),
            u64::from_le_bytes(x[24..32].try_into().unwrap()),
        ];
    }

    pub fn copy_bytes(&self, x: &mut [u8]) {
        x[0..8].copy_from_slice(&self.0[0].to_le_bytes()[..]);
        x[8..16].copy_from_slice(&self.0[1].to_le_bytes()[..]);
        x[16..24].copy_from_slice(&self.0[2].to_le_bytes()[..]);
        x[24..32].copy_from_slice(&self.0[3].to_le_bytes()[..]);
    }

    pub fn as_bytes(&self) -> [u8; 32] {
        let mut out = [0_u8; 32];
        self.copy_bytes(&mut out);
        out
    }
}

impl From<[u8; 32]> for Hash {
    fn from(hash: [u8; 32]) -> Self {
        let mut out = Hash::default();
        out.from_bytes(&hash[..]);
        out
    }
}

impl Deref for Hash {
    type Target = [u64; 4];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(PartialEq, Eq, Ord, PartialOrd, Copy, Clone, Debug)]
pub struct HeightWork {
    pub block_height: i32,
    pub work: u32,
}

#[derive(PartialEq, Eq, Ord, PartialOrd, Clone, Debug)]
pub struct ClassSet {
    pub min_orig_work: u32,
    pub count: u64,
    pub best_set: Vec<HeightWork>,
}