mod block;
mod script;
mod transaction;

pub mod bincode;
pub mod electrum_merkle;
pub mod fees;

pub use self::block::{
    BlockHeaderMeta, BlockId, BlockMeta, BlockStatus, HeaderEntry, HeaderList, DEFAULT_BLOCKHASH,
};
pub use self::fees::get_tx_fee;
pub use self::script::{get_innerscripts, ScriptToAddr, ScriptToAsm};
pub use self::transaction::{
    extract_tx_prevouts, get_prev_outpoints, has_prevout, is_coinbase, is_spendable,
    serialize_outpoint, TransactionStatus, TxInput,
};

#[cfg(feature = "liquid")]
pub use self::transaction::optional_value_for_newer_blocks;

use std::collections::HashMap;
use std::sync::mpsc::{channel, sync_channel, Receiver, Sender, SyncSender};
use std::thread;

use crate::chain::BlockHeader;
use bitcoin::hashes::sha256d::Hash as Sha256dHash;
use socket2::{Domain, Protocol, Socket, Type};
use std::net::SocketAddr;

pub type Bytes = Vec<u8>;
pub type HeaderMap = HashMap<Sha256dHash, BlockHeader>;

// TODO: consolidate serialization/deserialize code for bincode/bitcoin.
const HASH_LEN: usize = 32;

pub type FullHash = [u8; HASH_LEN];

pub fn full_hash(hash: &[u8]) -> FullHash {
    *array_ref![hash, 0, HASH_LEN]
}

pub struct SyncChannel<T> {
    tx: SyncSender<T>,
    rx: Receiver<T>,
}

impl<T> SyncChannel<T> {
    pub fn new(size: usize) -> SyncChannel<T> {
        let (tx, rx) = sync_channel(size);
        SyncChannel { tx, rx }
    }

    pub fn sender(&self) -> SyncSender<T> {
        self.tx.clone()
    }

    pub fn receiver(&self) -> &Receiver<T> {
        &self.rx
    }

    pub fn into_receiver(self) -> Receiver<T> {
        self.rx
    }
}

pub struct Channel<T> {
    tx: Sender<T>,
    rx: Receiver<T>,
}

impl<T> Channel<T> {
    pub fn unbounded() -> Self {
        let (tx, rx) = channel();
        Channel { tx, rx }
    }

    pub fn sender(&self) -> Sender<T> {
        self.tx.clone()
    }

    pub fn receiver(&self) -> &Receiver<T> {
        &self.rx
    }

    pub fn into_receiver(self) -> Receiver<T> {
        self.rx
    }
}

// Owned fixed-size chunks: the elements move, unlike slice::chunks (which
// borrows) or chunks().map(to_vec) (which transiently doubles the memory).
pub fn chunked<T>(items: Vec<T>, chunk_size: usize) -> Vec<Vec<T>> {
    let mut chunks = Vec::with_capacity(items.len().div_ceil(chunk_size));
    let mut it = items.into_iter().peekable();
    while it.peek().is_some() {
        chunks.push(it.by_ref().take(chunk_size).collect());
    }
    chunks
}

pub fn spawn_thread<F, T>(name: &str, f: F) -> thread::JoinHandle<T>
where
    F: FnOnce() -> T,
    F: Send + 'static,
    T: Send + 'static,
{
    thread::Builder::new()
        .name(name.to_owned())
        .spawn(f)
        .unwrap()
}

// Similar to https://doc.rust-lang.org/std/primitive.bool.html#method.then (nightly only),
// but with a function that returns an `Option<T>` instead of `T`. Adding something like
// this to std is being discussed: https://github.com/rust-lang/rust/issues/64260

pub trait BoolThen {
    fn and_then<T>(self, f: impl FnOnce() -> Option<T>) -> Option<T>;
}

impl BoolThen for bool {
    fn and_then<T>(self, f: impl FnOnce() -> Option<T>) -> Option<T> {
        if self {
            f()
        } else {
            None
        }
    }
}

pub fn create_socket(addr: &SocketAddr) -> Socket {
    let domain = match &addr {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };
    let socket =
        Socket::new(domain, Type::STREAM, Some(Protocol::TCP)).expect("creating socket failed");

    #[cfg(unix)]
    socket
        .set_reuse_port(true)
        .expect("cannot enable SO_REUSEPORT");

    socket.bind(&addr.clone().into()).expect("cannot bind");

    socket
}

#[cfg(test)]
mod tests {
    use super::chunked;

    #[test]
    fn chunked_moves_elements_into_full_and_remainder_chunks() {
        assert_eq!(
            chunked(vec![1, 2, 3, 4, 5], 2),
            vec![vec![1, 2], vec![3, 4], vec![5]]
        );
        assert_eq!(chunked(Vec::<u8>::new(), 3), Vec::<Vec<u8>>::new());
    }
}
