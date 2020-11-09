// SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
use anyhow::{bail, Result};
use bytes::{Buf, Bytes};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct AnnsEvent {
    #[serde(rename = "type")]
    pub anns_type: String,

    pub accepted: u32,
    pub dup: u32,
    pub inval: u32,
    pub bad_hash: u32,
    pub runt: u32,
    pub internal_err: u32,
    pub pay_to: String,
    pub unsigned: u32,
    pub total_len: u32,
    pub target: u32,
    pub time: u64,
    pub event_id: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct IndexFile {
    pub highest_ann_file: usize,
    pub files: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct PaymakerResult {
    pub event_id: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct PaymakerReply {
    pub warn: Vec<String>,
    pub error: Vec<String>,
    pub result: Option<PaymakerResult>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct AnnPostReply {
    pub warn: Vec<String>,
    pub error: Vec<String>,
    pub result: Option<AnnsEvent>,
}

#[derive(Deserialize, Debug, Clone, Default, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct MasterConf {
    pub current_height: i32,
    pub master_url: String,
    pub submit_ann_urls: Vec<String>,
    pub download_ann_urls: Vec<String>,
    pub submit_block_urls: Vec<String>,
    pub paymaker_url: String,
    pub version: u32,
    pub soft_version: u32,
    pub ann_versions: Vec<u8>,
    pub mine_old_anns: u32,
}

#[derive(Debug, Clone, Default)]
pub struct BlockHeader {
    pub version: u32,
    pub hash_prev_block: [u8; 32],
    pub hash_merkle_root: [u8; 32],
    pub time_seconds: i32,
    pub work_bits: u32,
    pub nonce: u32,
}

#[derive(Debug, Clone, Default)]
pub struct Work {
    pub header: BlockHeader,
    pub signing_key: [u8; 32],
    pub share_target: u32,
    pub ann_target: u32,
    pub height: i32,
    pub coinbase_no_witness: Bytes,
    pub coinbase_merkle: Vec<Bytes>,
}

pub fn blockheader_decode(out: &mut BlockHeader, b: &mut Bytes) -> Result<()> {
    if b.remaining() < 80 {
        bail!("runt block header");
    }
    let rem = b.remaining();
    out.version = b.get_u32_le();
    b.copy_to_slice(&mut out.hash_prev_block);
    b.copy_to_slice(&mut out.hash_merkle_root);
    out.time_seconds = b.get_i32_le();
    out.work_bits = b.get_u32_le();
    out.nonce = b.get_u32_le();
    assert_eq!(rem - 80, b.remaining());
    Ok(())
}

pub fn work_decode(out: &mut Work, b: &mut Bytes) -> Result<()> {
    blockheader_decode(&mut out.header, b)?;
    if b.remaining() < 32 + 16 {
        bail!("runt work");
    }
    b.copy_to_slice(&mut out.signing_key);
    out.share_target = b.get_u32_le();
    out.ann_target = b.get_u32_le();
    out.height = b.get_i32_le();
    let cnwlen = b.get_u32_le() as usize;
    if b.remaining() < cnwlen {
        bail!("runt work");
    }
    out.coinbase_no_witness = b.slice(0..cnwlen);
    b.advance(cnwlen);
    if b.remaining() % 32 != 0 {
        bail!(
            "work proof branch not a multiple of 32 ({}) {}",
            b.remaining(),
            cnwlen
        );
    }
    while b.remaining() > 0 {
        out.coinbase_merkle.push(b.slice(0..32).clone());
        b.advance(32);
    }
    Ok(())
}
