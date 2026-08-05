use rayon::prelude::*;

#[cfg(feature = "liquid")]
use crate::elements::ebcompact::*;
#[cfg(not(feature = "liquid"))]
use bitcoin::consensus::encode::{deserialize, deserialize_partial, Decodable};
#[cfg(feature = "liquid")]
use elements::encode::{deserialize, deserialize_partial, Decodable};

use std::collections::HashMap;
use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::mpsc::Receiver;
use std::thread;

use electrs_macros::trace;

use crate::chain::{Block, BlockHash, BlockHeader, Txid};
use crate::daemon::Daemon;
use crate::errors::*;
use crate::signal;
use crate::util::{chunked, spawn_thread, HeaderEntry, SyncChannel};

#[derive(Clone, Copy, Debug)]
pub enum FetchFrom {
    Bitcoind,
    BlkFiles,
}

#[trace]
pub fn start_fetcher(
    from: FetchFrom,
    daemon: &Daemon,
    new_headers: Vec<HeaderEntry>,
    batch_size: usize,
    chain_tip_height: usize,
) -> Result<Fetcher<Vec<BlockEntry>>> {
    match from {
        FetchFrom::Bitcoind => bitcoind_fetcher(daemon, new_headers, batch_size),
        FetchFrom::BlkFiles => blkfiles_fetcher(daemon, new_headers),
    }
}

#[derive(Clone)]
pub struct BlockEntry {
    pub block: Block,
    pub entry: HeaderEntry,
    pub size: u32,
    /// Pre-computed txids, must always correspond 1:1 with block.txdata
    pub txids: Vec<Txid>,
}

// Why a fetcher stream ended — reported by the producer thread itself, so
// consumers never have to infer it from ambient state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FetchOutcome {
    // every requested item was delivered
    Completed,
    // shutdown was requested; production stopped at a natural boundary
    // (a blk file / an RPC batch) and the remainder was never fetched
    Interrupted,
}

// A batch producer driven by Fetcher::produce: one batch per work item,
// with a completion hook for end-of-stream assertions.
trait Producer: Send + 'static {
    type Item: Send + 'static;
    type Batch: Send + 'static;
    fn produce(&mut self, item: Self::Item) -> Self::Batch;
    // runs only after every item was produced
    fn finish(self)
    where
        Self: Sized,
    {
    }
}

pub struct Fetcher<T> {
    receiver: Receiver<T>,
    thread: thread::JoinHandle<FetchOutcome>,
}

impl<T> Fetcher<T> {
    fn from(receiver: Receiver<T>, thread: thread::JoinHandle<FetchOutcome>) -> Self {
        Fetcher { receiver, thread }
    }

    // The production protocol shared by every fetcher: one batch per work
    // item on a named thread, observing shutdown between items, with the
    // outcome reported by this producer itself.
    fn produce<P>(name: &'static str, items: Vec<P::Item>, mut producer: P) -> Fetcher<T>
    where
        T: Send + 'static,
        P: Producer<Batch = T>,
    {
        // 2 batches of read-ahead overlap production with consumption
        let chan = SyncChannel::new(2);
        let sender = chan.sender();
        Fetcher::from(
            chan.into_receiver(),
            spawn_thread(name, move || {
                let total = items.len();
                for (i, item) in items.into_iter().enumerate() {
                    if signal::shutdown_requested() {
                        info!("{} stopping early at {}/{}", name, i, total);
                        return FetchOutcome::Interrupted;
                    }
                    // silent when there is no backlog (steady-state tip
                    // following produces single-item runs)
                    if total > 1 {
                        info!("{} {}/{}", name, i, total);
                    }
                    sender
                        .send(producer.produce(item))
                        .expect("failed to send produced batch");
                }
                producer.finish();
                FetchOutcome::Completed
            }),
        )
    }

    // Consume every delivered item, then report why the stream ended.
    // Chained stages propagate their upstream's outcome by returning it
    // from their own thread.
    pub fn for_each<F>(self, mut func: F) -> FetchOutcome
    where
        F: FnMut(T),
    {
        for item in self.receiver {
            func(item);
        }
        self.thread.join().expect("fetcher thread panicked")
    }
}

#[trace]
fn bitcoind_fetcher(
    daemon: &Daemon,
    new_headers: Vec<HeaderEntry>,
    batch_size: usize,
) -> Result<Fetcher<Vec<BlockEntry>>> {
    if let Some(tip) = new_headers.last() {
        debug!("{:?} ({} left to index)", tip, new_headers.len());
    };
    let daemon = daemon.reconnect()?;
    let chunks = chunked(new_headers, batch_size);
    Ok(Fetcher::produce("bitcoind_fetcher", chunks, RpcFetch { daemon }))
}

// Fetches block batches over bitcoind's RPC.
struct RpcFetch {
    daemon: Daemon,
}

impl Producer for RpcFetch {
    type Item = Vec<HeaderEntry>;
    type Batch = Vec<BlockEntry>;

    fn produce(&mut self, entries: Vec<HeaderEntry>) -> Vec<BlockEntry> {
        let blockhashes: Vec<BlockHash> = entries.iter().map(|e| *e.hash()).collect();
        let blocks = self
            .daemon
            .getblocks(&blockhashes)
            .expect("failed to get blocks from bitcoind");
        assert_eq!(blocks.len(), entries.len());
        blocks
            .into_iter()
            .zip(entries)
            .map(|(block, entry)| {
                let txids = block.txdata.iter().map(|tx| tx.compute_txid()).collect();
                BlockEntry {
                    entry,
                    size: block.total_size() as u32,
                    txids,
                    block,
                }
            })
            .collect()
    }
}

fn blkfiles_fetcher(
    daemon: &Daemon,
    new_headers: Vec<HeaderEntry>,
) -> Result<Fetcher<Vec<BlockEntry>>> {
    let magic = daemon.magic();
    let blk_files = daemon.list_blk_files()?;
    let xor_key = daemon.read_blk_file_xor_key()?;

    let wanted: HashMap<BlockHash, HeaderEntry> =
        new_headers.into_iter().map(|h| (*h.hash(), h)).collect();

    let locator = BlockLocator::new(magic, XorKey(xor_key), wanted);
    Ok(blkfiles_loader(blkfiles_walker(blk_files, locator)))
}

// A block that needs indexing, located by the walker: its consensus bytes
// (already XOR-decoded) and the header entry it matched.
struct RawBlock {
    entry: HeaderEntry,
    bytes: Vec<u8>,
}

// The obfuscation bitcoind v28+ applies to blk*.dat contents: an 8-byte key
// XORed cyclically over the absolute file offset (None for older datadirs).
// Decoding therefore always needs the offset a range came from — and must
// happen on copies, never through the mmap.
#[derive(Clone, Copy)]
struct XorKey(Option<[u8; 8]>);

impl XorKey {
    fn decode(&self, file_offset: usize, bytes: &mut [u8]) {
        if let Some(key) = self.0 {
            for (i, b) in bytes.iter_mut().enumerate() {
                *b ^= key[(file_offset + i) & 0x7];
            }
        }
    }
}

// One blk*.dat file viewed through its XOR obfuscation — an mmap or any
// other byte source. Every access decodes on the fly and is bounds-checked;
// callers never handle raw bytes, key phase, or EOF arithmetic.
struct BlkFile<'a> {
    bytes: &'a [u8],
    xor: XorKey,
    // the network's record magic — part of the file format, like the key
    magic: u32,
}

// One well-formed `magic|size|block` record: the body's location.
struct Record {
    // offset of the block's consensus bytes (past magic and size)
    start: usize,
    // their length, from the record's size field
    size: usize,
}

impl Record {
    fn next_offset(&self) -> usize {
        self.start + self.size
    }
}

// What lies at a given offset, structurally.
enum NextRecord {
    Record(Record),
    // a header-only stub (Core ftell failure wrote magic+size, no body):
    // the next record head sits at `next`
    Stub { next: usize },
    // the data ends here: EOF, a record cut off mid-write (never connected,
    // its rewrite appears in a later file), or the zeroed preallocated tail
    End,
    // not a record boundary — byte-scan territory
    Unrecognized,
}

impl<'a> BlkFile<'a> {
    fn new(bytes: &'a [u8], xor: XorKey, magic: u32) -> Self {
        BlkFile { bytes, xor, magic }
    }

    // Read the record structure at `offset`, trusting (but verifying) the
    // size fields.
    fn next_record(&self, offset: usize) -> NextRecord {
        let magic = self.magic.to_le_bytes();
        let head = match self.read_array::<8>(offset) {
            Some(head) => head,
            None => return NextRecord::End, // EOF
        };
        if head[0..4] != magic {
            // the untouched tail of a preallocated file is raw zeros
            // (never written, so never XORed)
            return if self.is_zero_tail(offset) {
                NextRecord::End
            } else {
                NextRecord::Unrecognized
            };
        }
        let size = u32::from_le_bytes([head[4], head[5], head[6], head[7]]) as usize;
        let start = offset + 8;
        // a stub's size field is garbage — peek for the following record
        // head before trusting it
        if let Some(peek) = self.read_array::<4>(start) {
            if peek == magic {
                return NextRecord::Stub { next: start };
            }
        }
        if !self.has_range(start, size) {
            return NextRecord::End;
        }
        NextRecord::Record(Record { start, size })
    }

    // The record's block header. Its prefix decides membership: 4096 covers
    // variable-length headers (elements) at the same one-page cost as
    // bitcoin's fixed 80. None if it doesn't parse — structural doubt.
    fn header(&self, record: &Record) -> Option<BlockHeader> {
        let head = self.read_vec(record.start, record.size.min(4096))?;
        deserialize_partial(&head).ok().map(|(header, _)| header)
    }

    // The record's full decoded consensus bytes.
    fn body(&self, record: &Record) -> Vec<u8> {
        self.read_vec(record.start, record.size)
            .expect("record ranges are validated by next_record")
    }

    // decoded fixed-size read; None past EOF
    fn read_array<const N: usize>(&self, offset: usize) -> Option<[u8; N]> {
        let mut buf = [0u8; N];
        buf.copy_from_slice(self.bytes.get(offset..offset.checked_add(N)?)?);
        self.xor.decode(offset, &mut buf);
        Some(buf)
    }

    // decoded variable-size read; None if the range passes EOF
    fn read_vec(&self, offset: usize, len: usize) -> Option<Vec<u8>> {
        let mut buf = self
            .bytes
            .get(offset..offset.checked_add(len)?)?
            .to_vec();
        self.xor.decode(offset, &mut buf);
        Some(buf)
    }

    fn has_range(&self, offset: usize, len: usize) -> bool {
        offset
            .checked_add(len)
            .map_or(false, |end| end <= self.bytes.len())
    }

    // the untouched tail of a preallocated file: raw zeros from `offset` to
    // EOF (never written, so never XORed)
    fn is_zero_tail(&self, offset: usize) -> bool {
        self.bytes[offset..].iter().all(|&b| b == 0)
    }

    // the whole file decoded — the scan fallback wants a plain blob
    fn decoded(&self) -> Vec<u8> {
        let mut blob = self.bytes.to_vec();
        self.xor.decode(0, &mut blob);
        blob
    }
}

// A blk*.dat file's raw bytes: mmap'd when possible (bitcoind's own use of
// these files keeps the interesting pages warm), read into memory otherwise.
// Derefs to [u8] like Mmap itself does.
enum FileBytes {
    Mapped(memmap2::Mmap),
    Read(Vec<u8>),
}

impl FileBytes {
    fn open(path: &Path) -> Result<FileBytes> {
        let file = fs::File::open(path).chain_err(|| format!("failed to open {:?}", path))?;
        match unsafe { memmap2::Mmap::map(&file) } {
            Ok(map) => {
                let _ = map.advise(memmap2::Advice::Random); // defeat readahead
                Ok(FileBytes::Mapped(map))
            }
            // mmap can fail on exotic filesystems; walking needs only bytes
            Err(_) => Ok(FileBytes::Read(
                fs::read(path).chain_err(|| format!("failed to read {:?}", path))?,
            )),
        }
    }
}

impl std::ops::Deref for FileBytes {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match self {
            FileBytes::Mapped(map) => map,
            FileBytes::Read(vec) => vec,
        }
    }
}

// walk() bails out to the byte-scanning fallback on the first structural
// surprise instead of guessing at recovery.
struct NeedsScan;

// One blk*.dat sweep: the record format, the datadir's XOR key, the blocks
// still wanted, and the survivors of the current file. locate() drives one
// file through the fast mmap walk with the scan as fallback.
struct BlockLocator {
    // the network's record magic, forwarded into each BlkFile view (and
    // used directly by the scan fallback's cursor)
    magic: u32,
    // the datadir's obfuscation key, forwarded into each BlkFile view
    xor: XorKey,
    // blocks still to find, by header hash; drained as files yield them
    wanted: HashMap<BlockHash, HeaderEntry>,
}

impl BlockLocator {
    fn new(magic: u32, xor: XorKey, wanted: HashMap<BlockHash, HeaderEntry>) -> Self {
        BlockLocator { magic, xor, wanted }
    }

    // Blocks that were requested but not found by any locate() call so far.
    fn missing(&self) -> usize {
        self.wanted.len()
    }

    // Find this file's wanted blocks and return them.
    fn locate(&mut self, path: &Path) -> Result<Vec<RawBlock>> {
        let bytes = FileBytes::open(path)?;
        self.walk_or_scan(path, &BlkFile::new(&bytes, self.xor, self.magic))
    }

    // The per-file strategy: the fast record walk, with the byte-scanning
    // fallback for structural surprises. walk() and scan() only read; the
    // claim is committed here, once, for whichever succeeded.
    fn walk_or_scan(&mut self, path: &Path, file: &BlkFile) -> Result<Vec<RawBlock>> {
        let found = match self.walk(file) {
            Ok(found) => found,
            Err(NeedsScan) => {
                debug!("record walk of {:?} failed — falling back to full scan", path);
                self.scan(file)?
            }
        };
        for raw in &found {
            self.wanted.remove(raw.entry.hash());
        }
        Ok(found)
    }

    // Walk the file's records, touching only their heads — bodies of blocks
    // nobody wants are never read, decoded, or deserialized.
    fn walk(&self, file: &BlkFile) -> std::result::Result<Vec<RawBlock>, NeedsScan> {
        let mut found = vec![];
        let mut offset = 0usize;
        loop {
            let record = match file.next_record(offset) {
                NextRecord::Record(record) => record,
                NextRecord::Stub { next } => {
                    offset = next;
                    continue;
                }
                NextRecord::End => return Ok(found),
                NextRecord::Unrecognized => return Err(NeedsScan),
            };
            let header = file.header(&record).ok_or(NeedsScan)?;
            if let Some(entry) = self.wanted.get(&header.block_hash()) {
                found.push(RawBlock {
                    entry: entry.clone(),
                    bytes: file.body(&record),
                });
            }
            offset = record.next_offset();
        }
    }

    // Fallback for files walk() can't make sense of: XOR-decode the whole
    // file and scan byte-by-byte for record boundaries (the pre-mmap
    // behavior, which tolerates arbitrary garbage between records).
    fn scan(&self, file: &BlkFile) -> Result<Vec<RawBlock>> {
        let blob = file.decoded();

        let mut found = vec![];
        let mut cursor = Cursor::new(&blob);
        let max_pos = blob.len() as u64;
        while cursor.position() < max_pos {
            let offset = cursor.position();
            match u32::consensus_decode(&mut cursor) {
                Ok(value) => {
                    if self.magic != value {
                        cursor.set_position(offset + 1);
                        continue;
                    }
                }
                Err(_) => break, // EOF
            };
            let block_size = u32::consensus_decode(&mut cursor).chain_err(|| "no block size")?;
            let start = cursor.position() as usize;
            let end = start + block_size as usize;
            if end > blob.len() {
                break; // record cut off by EOF
            }

            // If Core's WriteBlockToDisk ftell fails, only the magic bytes and size will be written
            // and the block body won't be written to the blk*.dat file.
            // Since the first 4 bytes should contain the block's version, we can skip such blocks
            // by peeking the cursor (and skipping previous `magic` and `block_size`).
            match u32::consensus_decode(&mut cursor) {
                Ok(value) => {
                    if self.magic == value {
                        cursor.set_position(start as u64);
                        continue;
                    }
                }
                Err(_) => break, // EOF
            }

            let slice = &blob[start..end];
            if let Ok((header, _)) = deserialize_partial::<BlockHeader>(slice) {
                if let Some(entry) = self.wanted.get(&header.block_hash()) {
                    found.push(RawBlock {
                        entry: entry.clone(),
                        bytes: slice.to_vec(),
                    });
                }
            }
            cursor.set_position(end as u64);
        }
        Ok(found)
    }
}

// Locate the blocks that need indexing by walking each blk*.dat through an
// mmap — for already-indexed regions only the record heads are touched, so
// a restart re-scan costs page faults on ~1% of the data instead of reading
// and deserializing all of it (and bitcoind's own use of these files keeps
// the head pages warm in the page cache).
fn blkfiles_walker(blk_files: Vec<PathBuf>, locator: BlockLocator) -> Fetcher<Vec<RawBlock>> {
    Fetcher::produce("blkfiles_walker", blk_files, locator)
}

impl Producer for BlockLocator {
    type Item = PathBuf;
    type Batch = Vec<RawBlock>;

    fn produce(&mut self, path: PathBuf) -> Vec<RawBlock> {
        self.locate(&path)
            .unwrap_or_else(|e| panic!("failed to read {:?}: {:?}", path, e))
    }

    // an interrupted walk legitimately leaves blocks unfound; a completed
    // one must have located every requested block
    fn finish(self) {
        if self.missing() != 0 {
            panic!(
                "failed to locate {} blocks in blk*.dat files",
                self.missing()
            )
        }
    }
}

// Deserialize the located blocks and compute their txids, in parallel —
// only blocks that actually need indexing ever reach this stage.
fn blkfiles_loader(walker: Fetcher<Vec<RawBlock>>) -> Fetcher<Vec<BlockEntry>> {
    let chan = SyncChannel::new(2);
    let sender = chan.sender();

    Fetcher::from(
        chan.into_receiver(),
        spawn_thread("blkfiles_loader", move || {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(0) // CPU-bound
                .thread_name(|i| format!("parse-blocks-{}", i))
                .build()
                .unwrap();
            walker.for_each(|batch| {
                let block_entries: Vec<BlockEntry> = pool.install(|| {
                    batch
                        .into_par_iter()
                        .map(|raw| {
                            let size = raw.bytes.len() as u32;
                            let block: Block = deserialize(&raw.bytes)
                                .expect("failed to parse block from blk*.dat");
                            let txids =
                                block.txdata.iter().map(|tx| tx.compute_txid()).collect();
                            BlockEntry {
                                block,
                                entry: raw.entry,
                                size,
                                txids,
                            }
                        })
                        .collect()
                });
                trace!("fetched {} blocks", block_entries.len());
                sender
                    .send(block_entries)
                    .expect("failed to send blocks entries from blk*.dat files");
            })
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(not(feature = "liquid"))]
    use crate::chain::{Sequence, TxIn, TxMerkleNode};
    #[cfg(not(feature = "liquid"))]
    use bitcoin::consensus::serialize;
    #[cfg(not(feature = "liquid"))]
    use bitcoin::hashes::Hash;

    #[cfg(not(feature = "liquid"))]
    const MAGIC: u32 = 0xD9B4_BEF9;
    #[cfg(not(feature = "liquid"))]
    const XOR_KEY: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

    #[cfg(not(feature = "liquid"))]
    fn test_block(tag: u8) -> (Block, Vec<u8>) {
        let tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version::ONE,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: bitcoin::OutPoint::null(),
                script_sig: vec![tag].into(),
                sequence: Sequence::MAX,
                witness: Default::default(),
            }],
            output: vec![],
        };
        let header = BlockHeader {
            version: bitcoin::block::Version::ONE,
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: tag as u32,
            bits: bitcoin::CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        };
        let block = Block {
            header,
            txdata: vec![tx],
        };
        let bytes = serialize(&block);
        (block, bytes)
    }

    #[cfg(not(feature = "liquid"))]
    fn record(bytes: &[u8]) -> Vec<u8> {
        let mut rec = MAGIC.to_le_bytes().to_vec();
        rec.extend((bytes.len() as u32).to_le_bytes());
        rec.extend(bytes);
        rec
    }

    #[cfg(not(feature = "liquid"))]
    fn entry_for(block: &Block, height: usize) -> HeaderEntry {
        HeaderEntry::new(height, block.block_hash(), block.header)
    }

    #[cfg(not(feature = "liquid"))]
    fn locator_wanting(blocks: &[(&Block, usize)]) -> BlockLocator {
        let wanted = blocks
            .iter()
            .map(|(b, height)| (b.block_hash(), entry_for(b, *height)))
            .collect();
        BlockLocator::new(MAGIC, XorKey(Some(XOR_KEY)), wanted)
    }

    // A realistic file: record A, an ftell-failure stub (magic + garbage
    // size, no body), record B, preallocated zero tail — all XORed. Only B
    // is wanted; the walk must find it, skip everything else, and never
    // report A as missing (it was never requested).
    #[cfg(not(feature = "liquid"))]
    #[test]
    fn walk_filters_records_through_stub_and_tail() {
        let (_a, a_bytes) = test_block(1);
        let (b, b_bytes) = test_block(2);
        let mut file = record(&a_bytes);
        file.extend(MAGIC.to_le_bytes());
        file.extend(9999u32.to_le_bytes()); // stub: size is garbage, no body
        file.extend(record(&b_bytes));
        file.extend([0u8; 300]); // untouched preallocated tail (raw zeros)
        let tail_start = file.len() - 300;
        let mut xored = file;
        XorKey(Some(XOR_KEY)).decode(0, &mut xored[..]);
        xored[tail_start..].fill(0); // the tail was never written, so never XORed

        let locator = locator_wanting(&[(&b, 2)]);
        let file = BlkFile::new(&xored, XorKey(Some(XOR_KEY)), MAGIC);
        let found = locator.walk(&file).ok().unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].bytes, b_bytes, "decoded bytes must round-trip");
        assert_eq!(*found[0].entry.hash(), b.block_hash());
    }

    // Garbage between records defeats the seek-walk (NeedsScan); locate()
    // must then re-find every wanted block via the byte-scanning fallback —
    // including ones the failed walk had already claimed.
    #[cfg(not(feature = "liquid"))]
    #[test]
    fn scan_fallback_survives_garbage_between_records() {
        let (a, a_bytes) = test_block(1);
        let (b, b_bytes) = test_block(2);
        let mut file = record(&a_bytes);
        file.extend([0xAB; 50]); // non-zero garbage: not a tail, not a record
        file.extend(record(&b_bytes));
        let mut xored = file;
        XorKey(Some(XOR_KEY)).decode(0, &mut xored[..]);

        let locator = locator_wanting(&[(&a, 1), (&b, 2)]);
        let file = BlkFile::new(&xored, XorKey(Some(XOR_KEY)), MAGIC);
        assert!(
            locator.walk(&file).is_err(),
            "garbage must trigger the fallback"
        );

        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), &xored).unwrap();
        let mut locator = locator_wanting(&[(&a, 1), (&b, 2)]);
        let batch = locator.locate(tmp.path()).unwrap();
        assert_eq!(locator.missing(), 0);
        assert_eq!(batch.len(), 2);
        assert_eq!(batch[0].bytes, a_bytes);
        assert_eq!(batch[1].bytes, b_bytes);
    }

    // A record whose size field points past EOF is a write bitcoind never
    // finished: the walk must end there quietly and must NOT claim the
    // block — its finished rewrite lives in a later file.
    #[cfg(not(feature = "liquid"))]
    #[test]
    fn walk_leaves_truncated_records_unclaimed() {
        let (a, a_bytes) = test_block(1);
        let (b, b_bytes) = test_block(2);
        let mut file = record(&a_bytes);
        file.extend(MAGIC.to_le_bytes());
        file.extend((b_bytes.len() as u32 + 100).to_le_bytes()); // size past EOF
        file.extend(&b_bytes); // partial body: the "rest" was never written

        let locator = locator_wanting(&[(&a, 1), (&b, 2)]);
        let found = locator
            .walk(&BlkFile::new(&file, XorKey(None), MAGIC))
            .ok()
            .unwrap();
        assert_eq!(found.len(), 1, "only the complete record is found");
        assert_eq!(found[0].bytes, a_bytes);
    }

    // End to end through both threads: real files on disk, mmap'd, walked,
    // survivors deserialized — with the producer's outcome intact.
    #[cfg(not(feature = "liquid"))]
    #[test]
    fn walker_and_loader_deliver_block_entries() {
        let (a, a_bytes) = test_block(1);
        let (b, b_bytes) = test_block(2);
        let dir = tempfile::tempdir().unwrap();
        let path1 = dir.path().join("blk0.dat");
        let path2 = dir.path().join("blk1.dat");
        std::fs::write(&path1, record(&a_bytes)).unwrap();
        std::fs::write(&path2, record(&b_bytes)).unwrap();

        let mut wanted = HashMap::new();
        wanted.insert(b.block_hash(), entry_for(&b, 2));
        let locator = BlockLocator::new(MAGIC, XorKey(None), wanted);

        let mut entries = vec![];
        let outcome = blkfiles_loader(blkfiles_walker(vec![path1, path2], locator))
            .for_each(|batch| entries.extend(batch));
        assert_eq!(outcome, FetchOutcome::Completed);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].block.block_hash(), b.block_hash());
        assert_eq!(entries[0].size as usize, b_bytes.len());
        assert_eq!(entries[0].txids, vec![b.txdata[0].compute_txid()]);
        assert_eq!(*entries[0].entry.hash(), b.block_hash());
    }

    // A wanted block that no file contains must be a loud failure — the
    // walker thread panics, which surfaces through the join in for_each.
    #[cfg(not(feature = "liquid"))]
    #[test]
    #[should_panic(expected = "fetcher thread panicked")]
    fn missing_wanted_block_panics() {
        let (_a, a_bytes) = test_block(1);
        let (b, _) = test_block(2);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blk0.dat");
        std::fs::write(&path, record(&a_bytes)).unwrap();

        let mut wanted = HashMap::new();
        wanted.insert(b.block_hash(), entry_for(&b, 2));
        let locator = BlockLocator::new(MAGIC, XorKey(None), wanted);
        blkfiles_loader(blkfiles_walker(vec![path], locator)).for_each(|_| {});
    }

    // The contract everything above relies on: every delivered item is
    // processed, then the producer's own outcome reaches the consumer.
    #[test]
    fn for_each_delivers_all_items_then_reports_producer_outcome() {
        let chan = SyncChannel::new(2);
        let sender = chan.sender();
        let fetcher = Fetcher::from(
            chan.into_receiver(),
            spawn_thread("test_producer", move || {
                sender.send(1).unwrap();
                sender.send(2).unwrap();
                FetchOutcome::Interrupted
            }),
        );
        let mut seen = vec![];
        assert_eq!(fetcher.for_each(|i| seen.push(i)), FetchOutcome::Interrupted);
        assert_eq!(seen, vec![1, 2]);
    }
}
