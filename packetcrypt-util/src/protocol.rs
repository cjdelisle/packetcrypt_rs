// SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
use anyhow::{bail, Result};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use serde::{Deserialize, Serialize};
use serde_hex::{SerHex, SerHexOpt, SerHexSeq, Strict};

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
pub struct BlkShareEvent {
    #[serde(rename = "type")]
    pub blk_type: String,

    pub pay_to: String,
    pub block: bool,
    pub time: u64,
    pub event_id: String,
    pub header_hash: Option<String>,
    pub target: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum MaybeBlkShareEvent {
    Bse(BlkShareEvent),
    Str(String),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BlkShareReply {
    pub warn: Vec<String>,
    pub error: Vec<String>,
    pub result: MaybeBlkShareEvent,
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
    #[serde(with = "SerHexOpt::<Strict>")]
    pub tip_hash: Option<[u8; 32]>,

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
    pub ann_target: Option<u32>,
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

#[derive(Serialize, Deserialize, Debug, Clone, Default, Copy)]
#[serde(rename_all = "camelCase")]
pub struct BlockInfoHeader {
    #[serde(with = "SerHex::<Strict>")]
    pub hash: [u8; 32],
    pub height: i32,
    pub version: u32,
    #[serde(with = "SerHex::<Strict>")]
    pub version_hex: [u8; 4],
    #[serde(with = "SerHex::<Strict>")]
    pub merkleroot: [u8; 32],
    pub time: u32,
    pub nonce: u32,
    #[serde(with = "SerHex::<Strict>")]
    pub bits: [u8; 4],
    pub difficulty: f64,
    #[serde(with = "SerHex::<Strict>")]
    pub previousblockhash: [u8; 32],
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct AnnIndex {
    pub highest_ann_file: i64,
    pub files: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, Copy)]
#[serde(rename_all = "camelCase")]
pub struct BlockInfo {
    pub header: BlockInfoHeader,
    #[serde(with = "SerHexOpt::<Strict>")]
    pub sig_key: Option<[u8; 32]>,
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

pub fn put_varint(num: u64, b: &mut BytesMut) {
    if num <= 0xfc {
        b.put_u8(num as u8);
    } else if num <= 0xffff {
        b.put_u8(0xfd);
        b.put_u16_le(num as u16);
    } else if num <= 0xffffffff {
        b.put_u8(0xfe);
        b.put_u32_le(num as u32);
    } else {
        b.put_u8(0xff);
        b.put_u64_le(num);
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct BlkShare {
    #[serde(with = "SerHexSeq::<Strict>")]
    pub coinbase_commit: Bytes,

    #[serde(with = "SerHexSeq::<Strict>")]
    pub header_and_proof: Bytes,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct SprayerReq {
    pub yes_please_dos_me_passwd: String,

    // deprecated, nolonger used
    pub num: Option<u32>,
    pub count: Option<u32>,
}
