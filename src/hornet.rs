//! Hornetライブラリとのブリッジ層。
//!
//! router 側からは std の時計やログなどを扱いたいため、ここで
//! `hornet` クレートを再公開しつつ TimeProvider 実装などを用意する。

pub use hornet::{forward, node, packet, policy, routing, setup, sphinx, time, types, wire};

use std::time::{SystemTime, UNIX_EPOCH};

/// 標準ライブラリの `SystemTime` を利用した TimeProvider 実装。
pub struct StdClock;

impl time::TimeProvider for StdClock {
    fn now_coarse(&self) -> u32 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|dur| dur.as_secs().min(u32::MAX as u64) as u32)
            .unwrap_or(0)
    }
}
