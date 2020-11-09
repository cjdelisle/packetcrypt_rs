// SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
#[macro_export]
macro_rules! async_spawn {
    ($arc:ident, $blk:block) => {{
        let $arc = Arc::clone($arc);
        tokio::spawn(async move { $blk });
    }};
}

pub mod hash;
pub mod poolclient;
pub mod protocol;
pub mod util;
