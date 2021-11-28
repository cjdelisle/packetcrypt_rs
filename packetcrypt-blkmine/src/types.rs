use sodiumoxide::crypto::generichash;
use std::convert::TryInto;
use std::ops::Deref;

#[derive(Default, Copy, Clone)]
pub struct AnnData {
    pub hash_pfx: u64,
    pub mloc: usize,
}

#[derive(Default, Copy, Clone)]
pub struct Hash([u8; 32]);

impl Hash {
    pub fn compute(&mut self, ann: &[u8]) {
        let digest = generichash::hash(ann, Some(32), None).unwrap();
        self.0.copy_from_slice(digest.as_ref())
    }

    pub fn to_u64(&self) -> u64 {
        u64::from_le_bytes(self.0[..8].try_into().unwrap())
    }
}

impl From<[u8; 32]> for Hash {
    fn from(hash: [u8; 32]) -> Self {
        Self(hash)
    }
}

impl Deref for Hash {
    type Target = [u8; 32];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
