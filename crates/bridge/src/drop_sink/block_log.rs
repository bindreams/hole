use lru::LruCache;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::time::Instant;

const BLOCK_LOG_LRU_CAPACITY: usize = 1024;
const SUPPRESS_DURATION: std::time::Duration = std::time::Duration::from_secs(1);

type BlockKey = (u32, SocketAddr);

pub struct BlockLog {
    cache: LruCache<BlockKey, Instant>,
}

impl Default for BlockLog {
    fn default() -> Self {
        Self::new()
    }
}

impl BlockLog {
    pub fn new() -> Self {
        Self::with_capacity(BLOCK_LOG_LRU_CAPACITY)
    }

    pub fn with_capacity(cap: usize) -> Self {
        Self {
            cache: LruCache::new(NonZeroUsize::new(cap.max(1)).unwrap()),
        }
    }

    /// Returns true if this block should be logged (not suppressed).
    pub fn should_log(&mut self, rule_index: u32, dst: SocketAddr) -> bool {
        let key = (rule_index, dst);
        let now = Instant::now();
        if let Some(last) = self.cache.get(&key) {
            if now.duration_since(*last) < SUPPRESS_DURATION {
                return false;
            }
        }
        self.cache.put(key, now);
        true
    }
}

#[cfg(test)]
#[path = "block_log_tests.rs"]
mod block_log_tests;
