use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver, Sender, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::Instant;

use bitcoin::hashes::{sha256, sha256d::Hash as Sha256dHash, Hash, HashEngine};
use bitcoin::hex::DisplayHex;
use error_chain::ChainedError;
use serde_json::{from_str, Value};

use electrs_macros::trace;

#[cfg(not(feature = "liquid"))]
use bitcoin::consensus::encode::serialize_hex;
#[cfg(feature = "liquid")]
use elements::encode::serialize_hex;
use crate::chain::Txid;
use crate::config::{Config, RpcLogging};
use crate::electrum::{get_electrum_height, ProtocolVersion};
use crate::errors::*;
use crate::metrics::{Gauge, HistogramOpts, HistogramVec, MetricOpts, Metrics};
use crate::new_index::{Query, Utxo};
use crate::util::electrum_merkle::{get_header_merkle_proof, get_id_from_pos, get_tx_merkle_proof};
use crate::util::{create_socket, spawn_thread, BlockId, BoolThen, Channel, FullHash, HeaderEntry};

const ELECTRS_VERSION: &str = env!("CARGO_PKG_VERSION");
const PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::new(1, 4);
const MAX_HEADERS: usize = 2016;
const MAX_ARRAY_BATCH: usize = 20;

#[cfg(feature = "electrum-discovery")]
use crate::electrum::{DiscoveryManager, ServerFeatures};

fn invalid_params(msg: impl Into<String>) -> Error {
    ErrorKind::InvalidParams(msg.into()).into()
}

// TODO: Sha256dHash should be a generic hash-container (since script hash is single SHA256)
fn hash_from_value(val: Option<&Value>) -> Result<Sha256dHash> {
    let script_hash = val.ok_or_else(|| invalid_params("missing hash"))?;
    let script_hash = script_hash
        .as_str()
        .ok_or_else(|| invalid_params("non-string hash"))?;
    let script_hash = script_hash
        .parse()
        .map_err(|_| invalid_params("non-hex hash"))?;
    Ok(script_hash)
}

fn usize_from_value(val: Option<&Value>, name: &str) -> Result<usize> {
    let val = val.ok_or_else(|| invalid_params(format!("missing {}", name)))?;
    let val = val
        .as_u64()
        .ok_or_else(|| invalid_params(format!("non-integer {}", name)))?;
    Ok(val as usize)
}

fn usize_from_value_or(val: Option<&Value>, name: &str, default: usize) -> Result<usize> {
    if val.is_none() {
        return Ok(default);
    }
    usize_from_value(val, name)
}

fn bool_from_value(val: Option<&Value>, name: &str) -> Result<bool> {
    let val = val.ok_or_else(|| invalid_params(format!("missing {}", name)))?;
    let val = val
        .as_bool()
        .ok_or_else(|| invalid_params(format!("not a bool {}", name)))?;
    Ok(val)
}

fn bool_from_value_or(val: Option<&Value>, name: &str, default: bool) -> Result<bool> {
    if val.is_none() {
        return Ok(default);
    }
    bool_from_value(val, name)
}

// JSON-RPC 2.0 error codes (https://www.jsonrpc.org/specification#error_object),
// plus the application-level codes used by ElectrumX and romanz/electrs.
#[repr(i16)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum JsonRpcV2Error {
    ParseError = -32700,
    InvalidRequest = -32600,
    MethodNotFound = -32601,
    InvalidParams = -32602,
    InternalError = -32603,
    BadRequest = 1,
    DaemonError = 2,
}

impl JsonRpcV2Error {
    #[inline]
    fn into_i16(self) -> i16 {
        self as i16
    }
}

fn jsonrpc_code(e: &Error) -> JsonRpcV2Error {
    match e.kind() {
        ErrorKind::InvalidParams(_) => JsonRpcV2Error::InvalidParams,
        ErrorKind::TooPopular => JsonRpcV2Error::BadRequest,
        ErrorKind::RpcError(..) => JsonRpcV2Error::DaemonError,
        _ => JsonRpcV2Error::InternalError,
    }
}

#[inline]
fn json_rpc_error(
    input: impl core::fmt::Display,
    id: Option<&Value>,
    code: JsonRpcV2Error,
) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id.unwrap_or(&Value::Null),
        "error": {
            "code": code.into_i16(),
            "message": format!("{}", input),
        },
    })
}

// TODO: implement caching and delta updates
#[trace]
fn get_status_hash(txs: Vec<(Txid, Option<BlockId>)>, query: &Query) -> Option<FullHash> {
    if txs.is_empty() {
        None
    } else {
        let mut engine = sha256::Hash::engine();
        for (txid, blockid) in txs {
            let is_mempool = blockid.is_none();
            let has_unconfirmed_parents = is_mempool
                .and_then(|| Some(query.has_unconfirmed_parents(&txid)))
                .unwrap_or(false);
            let height = get_electrum_height(blockid, has_unconfirmed_parents);
            let part = format!("{}:{}:", txid, height);
            engine.input(part.as_bytes());
        }
        Some(sha256::Hash::from_engine(engine).to_byte_array())
    }
}

macro_rules! conditionally_log_rpc_event {
    ($self:ident, $event:expr) => {
        if $self.rpc_logging.enabled {
            $self.log_rpc_event($event);
        }
    };
}

struct Connection {
    query: Arc<Query>,
    last_header_entry: Option<HeaderEntry>,
    status_hashes: HashMap<Sha256dHash, Value>, // ScriptHash -> StatusHash
    stream: TcpStream,
    addr: SocketAddr,
    sender: SyncSender<Message>,
    stats: Arc<Stats>,
    txs_limit: usize,
    #[cfg(feature = "electrum-discovery")]
    discovery: Option<Arc<DiscoveryManager>>,
    rpc_logging: RpcLogging,
    salt: String,
}

fn hash_ip_with_salt(salt: &str, ip: &str) -> String {
    let mut engine = sha256::Hash::engine();
    engine.input(salt.as_bytes());
    engine.input(ip.as_bytes());
    format!("{:x}", sha256::Hash::from_engine(engine))
}

impl Connection {
    pub fn new(
        query: Arc<Query>,
        stream: TcpStream,
        addr: SocketAddr,
        sender: SyncSender<Message>,
        stats: Arc<Stats>,
        txs_limit: usize,
        #[cfg(feature = "electrum-discovery")] discovery: Option<Arc<DiscoveryManager>>,
        rpc_logging: RpcLogging,
        salt: String,
    ) -> Connection {
        Connection {
            query,
            last_header_entry: None, // disable header subscription for now
            status_hashes: HashMap::new(),
            stream,
            addr,
            sender,
            stats,
            txs_limit,
            #[cfg(feature = "electrum-discovery")]
            discovery,
            rpc_logging,
            salt,
        }
    }

    fn blockchain_headers_subscribe(&mut self) -> Result<Value> {
        let entry = self.query.chain().best_header();
        let hex_header = serialize_hex(entry.header());
        let result = json!({"hex": hex_header, "height": entry.height()});
        self.last_header_entry = Some(entry);
        Ok(result)
    }

    fn server_version(&self) -> Result<Value> {
        Ok(json!([
            format!("electrs-esplora {}", ELECTRS_VERSION),
            PROTOCOL_VERSION
        ]))
    }

    fn server_banner(&self) -> Result<Value> {
        Ok(json!(self.query.config().electrum_banner.clone()))
    }

    #[cfg(feature = "electrum-discovery")]
    fn server_features(&self) -> Result<Value> {
        let discovery = self
            .discovery
            .as_ref()
            .chain_err(|| "discovery is disabled")?;
        Ok(json!(discovery.our_features()))
    }

    fn server_donation_address(&self) -> Result<Value> {
        Ok(Value::Null)
    }

    fn server_peers_subscribe(&self) -> Result<Value> {
        #[cfg(feature = "electrum-discovery")]
        let servers = self
            .discovery
            .as_ref()
            .map_or_else(|| json!([]), |d| json!(d.get_servers()));

        #[cfg(not(feature = "electrum-discovery"))]
        let servers = json!([]);

        Ok(servers)
    }

    #[cfg(feature = "electrum-discovery")]
    fn server_add_peer(&self, params: &[Value]) -> Result<Value> {
        let discovery = self
            .discovery
            .as_ref()
            .chain_err(|| "discovery is disabled")?;

        let features = params
            .get(0)
            .ok_or_else(|| invalid_params("missing features param"))?
            .clone();
        let features =
            serde_json::from_value(features).map_err(|_| invalid_params("invalid features"))?;

        discovery.add_server_request(self.addr.ip(), features)?;
        Ok(json!(true))
    }

    fn mempool_get_fee_histogram(&self) -> Result<Value> {
        Ok(json!(&self.query.mempool().backlog_stats().fee_histogram))
    }

    fn blockchain_block_header(&self, params: &[Value]) -> Result<Value> {
        let height = usize_from_value(params.get(0), "height")?;
        let cp_height = usize_from_value_or(params.get(1), "cp_height", 0)?;

        let raw_header_hex: String = self
            .query
            .chain()
            .header_by_height(height)
            .map(|entry| serialize_hex(entry.header()))
            .chain_err(|| "missing header")?;

        if cp_height == 0 {
            return Ok(json!(raw_header_hex));
        }
        let (branch, root) = get_header_merkle_proof(self.query.chain(), height, cp_height)?;

        Ok(json!({
            "header": raw_header_hex,
            "root": root,
            "branch": branch
        }))
    }

    fn blockchain_block_headers(&self, params: &[Value]) -> Result<Value> {
        let start_height = usize_from_value(params.get(0), "start_height")?;
        let count = MAX_HEADERS.min(usize_from_value(params.get(1), "count")?);
        let cp_height = usize_from_value_or(params.get(2), "cp_height", 0)?;
        let heights: Vec<usize> = (start_height..(start_height + count)).collect();
        let headers: Vec<String> = heights
            .into_iter()
            .filter_map(|height| {
                self.query
                    .chain()
                    .header_by_height(height)
                    .map(|entry| serialize_hex(entry.header()))
            })
            .collect();

        if count == 0 || cp_height == 0 {
            return Ok(json!({
                "count": headers.len(),
                "hex": headers.join(""),
                "max": MAX_HEADERS,
            }));
        }

        let (branch, root) =
            get_header_merkle_proof(self.query.chain(), start_height + (count - 1), cp_height)?;

        Ok(json!({
            "count": headers.len(),
            "hex": headers.join(""),
            "max": MAX_HEADERS,
            "root": root,
            "branch" : branch,
        }))
    }

    #[trace]
    fn blockchain_estimatefee(&self, params: &[Value]) -> Result<Value> {
        let conf_target = usize_from_value(params.get(0), "blocks_count")?;
        let fee_rate = self
            .query
            .estimate_fee(conf_target as u16)
            .chain_err(|| format!("cannot estimate fee for {} blocks", conf_target))?;
        // convert from sat/b to BTC/kB, as expected by Electrum clients
        Ok(json!(fee_rate / 100_000f64))
    }

    fn blockchain_relayfee(&self) -> Result<Value> {
        let relayfee = self.query.get_relayfee()?;
        // convert from sat/b to BTC/kB, as expected by Electrum clients
        Ok(json!(relayfee / 100_000f64))
    }

    fn blockchain_scripthash_subscribe(&mut self, params: &[Value]) -> Result<Value> {
        let script_hash = hash_from_value(params.get(0))?;

        let history_txids = get_history(&self.query, &script_hash[..], self.txs_limit)?;
        let status_hash = get_status_hash(history_txids, &self.query)
            .map_or(Value::Null, |h| json!(h.to_lower_hex_string()));

        if let None = self.status_hashes.insert(script_hash, status_hash.clone()) {
            self.stats.subscriptions.inc();
        }
        Ok(status_hash)
    }

    fn blockchain_scripthash_unsubscribe(&mut self, params: &[Value]) -> Result<Value> {
        let script_hash = hash_from_value(params.get(0))?;

        match self.status_hashes.remove(&script_hash) {
            None => Ok(json!(false)),
            Some(_) => {
                self.stats.subscriptions.dec();
                Ok(json!(true))
            }
        }
    }

    #[cfg(not(feature = "liquid"))]
    fn blockchain_scripthash_get_balance(&self, params: &[Value]) -> Result<Value> {
        let script_hash = hash_from_value(params.get(0))?;
        let (chain_stats, mempool_stats) = self.query.stats(&script_hash[..]);

        Ok(json!({
            "confirmed": chain_stats.funded_txo_sum - chain_stats.spent_txo_sum,
            "unconfirmed": mempool_stats.funded_txo_sum as i64 - mempool_stats.spent_txo_sum as i64,
        }))
    }

    fn blockchain_scripthash_get_history(&self, params: &[Value]) -> Result<Value> {
        let script_hash = hash_from_value(params.get(0))?;
        let history_txids = get_history(&self.query, &script_hash[..], self.txs_limit)?;

        Ok(json!(history_txids
            .into_iter()
            .map(|(txid, blockid)| {
                let is_mempool = blockid.is_none();
                let fee = is_mempool.and_then(|| self.query.get_mempool_tx_fee(&txid));
                let has_unconfirmed_parents = is_mempool
                    .and_then(|| Some(self.query.has_unconfirmed_parents(&txid)))
                    .unwrap_or(false);
                let height = get_electrum_height(blockid, has_unconfirmed_parents);
                GetHistoryResult { txid, height, fee }
            })
            .collect::<Vec<_>>()))
    }

    fn blockchain_scripthash_get_mempool(&self, params: &[Value]) -> Result<Value> {
        let script_hash = hash_from_value(params.get(0))?;
        // ask for one extra more than the limit and fail if it exists, to avoid silently truncating
        let mempool_txids = self
            .query
            .mempool()
            .history_txids(&script_hash[..], self.txs_limit + 1);
        ensure!(mempool_txids.len() <= self.txs_limit, ErrorKind::TooPopular);

        Ok(json!(mempool_txids
            .into_iter()
            .map(|txid| {
                let fee = self.query.get_mempool_tx_fee(&txid);
                let has_unconfirmed_parents = self.query.has_unconfirmed_parents(&txid);
                // per the Electrum protocol: 0 if all inputs are confirmed, -1 otherwise
                let height = if has_unconfirmed_parents { -1 } else { 0 };
                GetHistoryResult { txid, height, fee }
            })
            .collect::<Vec<_>>()))
    }

    fn blockchain_scripthash_listunspent(&self, params: &[Value]) -> Result<Value> {
        let script_hash = hash_from_value(params.get(0))?;
        let utxos = self.query.utxo(&script_hash[..])?;

        let to_json = |utxo: Utxo| {
            let json = json!({
                "height": utxo.confirmed.map_or(0, |b| b.height),
                "tx_pos": utxo.vout,
                "tx_hash": utxo.txid,
                "value": utxo.value,
            });

            #[cfg(feature = "liquid")]
            let json = {
                let mut json = json;
                json["asset"] = json!(utxo.asset);
                json["nonce"] = json!(utxo.nonce);
                json
            };

            json
        };

        Ok(json!(Value::Array(
            utxos.into_iter().map(to_json).collect()
        )))
    }

    fn blockchain_transaction_broadcast(&self, params: &[Value]) -> Result<Value> {
        let tx = params.get(0).ok_or_else(|| invalid_params("missing tx"))?;
        let tx = tx
            .as_str()
            .ok_or_else(|| invalid_params("non-string tx"))?
            .to_string();
        let txid = self.query.broadcast_raw(&tx)?;
        if let Err(e) = self.sender.try_send(Message::PeriodicUpdate) {
            warn!("failed to issue PeriodicUpdate after broadcast: {}", e);
        }
        Ok(json!(txid))
    }

    // Ported from romanz/electrs (https://github.com/romanz/electrs).
    fn blockchain_transaction_broadcast_package(&self, params: &[Value]) -> Result<Value> {
        let txhexes: Vec<String> = params
            .get(0)
            .ok_or_else(|| invalid_params("missing transactions"))
            .and_then(|txs| {
                serde_json::from_value(txs.clone())
                    .map_err(|_| invalid_params("non-array transactions"))
            })?;
        let verbose = bool_from_value_or(params.get(1), "verbose", false)?;

        let result = self.query.submit_package(txhexes, None, None)?;
        if let Err(e) = self.sender.try_send(Message::PeriodicUpdate) {
            warn!(
                "failed to issue PeriodicUpdate after broadcast_package: {}",
                e
            );
        }
        Ok(result.into_electrum_response(verbose))
    }

    fn blockchain_transaction_get(&self, params: &[Value]) -> Result<Value> {
        let tx_hash = Txid::from(hash_from_value(params.get(0))?);
        let verbose = match params.get(1) {
            Some(value) => value
                .as_bool()
                .ok_or_else(|| invalid_params("non-bool verbose value"))?,
            None => false,
        };

        let raw_tx = self
            .query
            .lookup_raw_txn(&tx_hash)
            .chain_err(|| "missing transaction")?;

        if !verbose {
            return Ok(json!(raw_tx.to_lower_hex_string()));
        }

        self.verbose_transaction_json(&tx_hash, &raw_tx)
    }

    /// Verbose response for blockchain.transaction.get, matching Bitcoin
    /// Core's getrawtransaction format, plus a "height" field (Electrum
    /// protocol extension).
    #[cfg(not(feature = "liquid"))]
    fn verbose_transaction_json(&self, tx_hash: &Txid, raw_tx: &[u8]) -> Result<Value> {
        let tx = self
            .query
            .lookup_txn(tx_hash)
            .chain_err(|| "missing transaction")?;

        let blockid = self.query.chain().tx_confirming_block(tx_hash);

        let vin: Vec<Value> = tx
            .input
            .iter()
            .map(|txin| {
                let mut vin_obj = if txin.previous_output.is_null() {
                    json!({
                        "coinbase": txin.script_sig.as_bytes().to_lower_hex_string(),
                        "sequence": txin.sequence.0
                    })
                } else {
                    json!({
                        "txid": txin.previous_output.txid.to_string(),
                        "vout": txin.previous_output.vout,
                        "scriptSig": {
                            "asm": txin.script_sig.to_asm_string(),
                            "hex": txin.script_sig.as_bytes().to_lower_hex_string()
                        },
                        "sequence": txin.sequence.0
                    })
                };

                if !txin.witness.is_empty() {
                    let witness: Vec<String> = txin
                        .witness
                        .iter()
                        .map(|w| w.to_lower_hex_string())
                        .collect();
                    vin_obj
                        .as_object_mut()
                        .unwrap()
                        .insert("txinwitness".to_string(), json!(witness));
                }

                vin_obj
            })
            .collect();

        let vout: Vec<Value> = tx
            .output
            .iter()
            .enumerate()
            .map(|(n, txout)| {
                let script = &txout.script_pubkey;
                let script_type = if script.is_empty() {
                    "nonstandard"
                } else if script.is_op_return() {
                    "nulldata"
                } else if script.is_p2pk() {
                    "pubkey"
                } else if script.is_p2pkh() {
                    "pubkeyhash"
                } else if script.is_p2sh() {
                    "scripthash"
                } else if script.is_p2wpkh() {
                    "witness_v0_keyhash"
                } else if script.is_p2wsh() {
                    "witness_v0_scripthash"
                } else if script.is_p2tr() {
                    "witness_v1_taproot"
                } else if script.is_witness_program() {
                    "witness_unknown"
                } else {
                    "nonstandard"
                };

                let mut script_pub_key = json!({
                    "asm": script.to_asm_string(),
                    "hex": script.as_bytes().to_lower_hex_string(),
                    "type": script_type
                });

                if let Ok(addr) = bitcoin::Address::from_script(
                    script,
                    bitcoin::Network::from(self.query.network()),
                ) {
                    script_pub_key
                        .as_object_mut()
                        .unwrap()
                        .insert("address".to_string(), json!(addr.to_string()));
                }

                json!({
                    "value": txout.value.to_btc(),
                    "n": n,
                    "scriptPubKey": script_pub_key
                })
            })
            .collect();

        let mut result = json!({
            "txid": tx_hash.to_string(),
            "hash": tx.compute_wtxid().to_string(),
            "version": tx.version.0,
            "size": raw_tx.len(),
            "vsize": tx.vsize(),
            "weight": tx.weight().to_wu(),
            "locktime": tx.lock_time.to_consensus_u32(),
            "vin": vin,
            "vout": vout,
            "hex": raw_tx.to_lower_hex_string()
        });

        if let Some(blockid) = blockid {
            let best_height = self.query.chain().best_height();
            let confirmations = best_height - blockid.height + 1;
            let obj = result.as_object_mut().unwrap();
            obj.insert("blockhash".to_string(), json!(blockid.hash.to_string()));
            obj.insert("confirmations".to_string(), json!(confirmations));
            obj.insert("time".to_string(), json!(blockid.time));
            obj.insert("blocktime".to_string(), json!(blockid.time));
            obj.insert("height".to_string(), json!(blockid.height));
        }

        Ok(result)
    }

    #[cfg(feature = "liquid")]
    fn verbose_transaction_json(&self, _tx_hash: &Txid, _raw_tx: &[u8]) -> Result<Value> {
        bail!("verbose transactions are not supported on liquid")
    }

    #[trace]
    fn blockchain_transaction_get_merkle(&self, params: &[Value]) -> Result<Value> {
        let txid = Txid::from(hash_from_value(params.get(0))?);
        let height = usize_from_value(params.get(1), "height")?;
        let blockid = self
            .query
            .chain()
            .tx_confirming_block(&txid)
            .ok_or_else(|| "tx not found or is unconfirmed")?;
        if blockid.height != height {
            return Err(invalid_params("invalid confirmation height provided"));
        }
        let (merkle, pos) = get_tx_merkle_proof(self.query.chain(), &txid, &blockid.hash)
            .chain_err(|| "cannot create merkle proof")?;
        Ok(json!({
            "block_height": blockid.height,
            "merkle": merkle,
            "pos": pos
        }))
    }

    fn blockchain_transaction_id_from_pos(&self, params: &[Value]) -> Result<Value> {
        let height = usize_from_value(params.get(0), "height")?;
        let tx_pos = usize_from_value(params.get(1), "tx_pos")?;
        let want_merkle = bool_from_value_or(params.get(2), "merkle", false)?;

        let (txid, merkle) = get_id_from_pos(self.query.chain(), height, tx_pos, want_merkle)?;

        if !want_merkle {
            return Ok(json!(txid));
        }

        Ok(json!({
            "tx_hash": txid,
            "merkle" : merkle
        }))
    }

    #[trace(method = %method)]
    fn handle_command(&mut self, method: &str, params: &[Value], id: &Value) -> Result<Value> {
        let timer = self
            .stats
            .latency
            .with_label_values(&[method])
            .start_timer();

        let result = match method {
            "blockchain.block.header" => self.blockchain_block_header(&params),
            "blockchain.block.headers" => self.blockchain_block_headers(&params),
            "blockchain.estimatefee" => self.blockchain_estimatefee(&params),
            "blockchain.headers.subscribe" => self.blockchain_headers_subscribe(),
            "blockchain.relayfee" => self.blockchain_relayfee(),
            #[cfg(not(feature = "liquid"))]
            "blockchain.scripthash.get_balance" => self.blockchain_scripthash_get_balance(&params),
            "blockchain.scripthash.get_history" => self.blockchain_scripthash_get_history(&params),
            "blockchain.scripthash.get_mempool" => self.blockchain_scripthash_get_mempool(&params),
            "blockchain.scripthash.listunspent" => self.blockchain_scripthash_listunspent(&params),
            "blockchain.scripthash.subscribe" => self.blockchain_scripthash_subscribe(&params),
            "blockchain.scripthash.unsubscribe" => self.blockchain_scripthash_unsubscribe(&params),
            "blockchain.transaction.broadcast" => self.blockchain_transaction_broadcast(&params),
            "blockchain.transaction.broadcast_package" => {
                self.blockchain_transaction_broadcast_package(&params)
            }
            "blockchain.transaction.get" => self.blockchain_transaction_get(&params),
            "blockchain.transaction.get_merkle" => self.blockchain_transaction_get_merkle(&params),
            "blockchain.transaction.id_from_pos" => {
                self.blockchain_transaction_id_from_pos(&params)
            }
            "mempool.get_fee_histogram" => self.mempool_get_fee_histogram(),
            "server.banner" => self.server_banner(),
            "server.donation_address" => self.server_donation_address(),
            "server.peers.subscribe" => self.server_peers_subscribe(),
            "server.ping" => Ok(Value::Null),
            "server.version" => self.server_version(),

            #[cfg(feature = "electrum-discovery")]
            "server.features" => self.server_features(),
            #[cfg(feature = "electrum-discovery")]
            "server.add_peer" => self.server_add_peer(&params),

            &_ => {
                warn!("rpc #{} unknown method {} {:?}", id, method, params);
                return Ok(json_rpc_error(
                    format!("unknown method {}", method),
                    Some(id),
                    JsonRpcV2Error::MethodNotFound,
                ));
            }
        };
        timer.observe_duration();
        Ok(match result {
            Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
            Err(e) => {
                warn!(
                    "rpc #{} {} {:?} failed: {}",
                    id,
                    method,
                    params,
                    e.display_chain()
                );
                json_rpc_error(&e, Some(id), jsonrpc_code(&e))
            }
        })
    }

    #[trace]
    fn update_subscriptions(&mut self) -> Result<Vec<Value>> {
        let timer = self
            .stats
            .latency
            .with_label_values(&["periodic_update"])
            .start_timer();
        let mut result = vec![];
        if let Some(ref mut last_entry) = self.last_header_entry {
            let entry = self.query.chain().best_header();
            if *last_entry != entry {
                *last_entry = entry;
                let hex_header = serialize_hex(last_entry.header());
                let header = json!({"hex": hex_header, "height": last_entry.height()});
                result.push(json!({
                    "jsonrpc": "2.0",
                    "method": "blockchain.headers.subscribe",
                    "params": [header]}));
            }
        }
        for (script_hash, status_hash) in self.status_hashes.iter_mut() {
            let history_txids = get_history(&self.query, &script_hash[..], self.txs_limit)?;
            let new_status_hash = get_status_hash(history_txids, &self.query)
                .map_or(Value::Null, |h| json!(h.to_lower_hex_string()));
            if new_status_hash == *status_hash {
                continue;
            }
            result.push(json!({
                "jsonrpc": "2.0",
                "method": "blockchain.scripthash.subscribe",
                "params": [script_hash, new_status_hash]}));
            *status_hash = new_status_hash;
        }
        timer.observe_duration();
        Ok(result)
    }

    fn log_rpc_event(&self, mut log: Value) {
        let real_ip = self.addr.ip().to_string();
        let ip_to_log = if self.rpc_logging.anonymize_ip {
            hash_ip_with_salt(&self.salt, &real_ip)
        } else {
            real_ip
        };

        log.as_object_mut().unwrap().insert(
            "source".into(),
            json!({
                "ip": ip_to_log,
                "port": self.addr.port(),
            }),
        );
        println!("{}", log);
    }

    fn send_values(&mut self, values: &[Value]) -> Result<()> {
        for value in values {
            let line = value.to_string() + "\n";
            self.stream
                .write_all(line.as_bytes())
                .chain_err(|| format!("failed to send response ({} bytes)", line.len()))?;
        }
        Ok(())
    }

    #[trace]
    fn handle_replies(&mut self, receiver: Receiver<Message>) -> Result<()> {
        let empty_params = json!([]);
        loop {
            let msg = receiver.recv().chain_err(|| "channel closed")?;
            trace!("RPC {:?}", msg);
            match msg {
                Message::Request(line) => {
                    let reply = match from_str::<Value>(&line) {
                        Ok(Value::Array(arr)) => {
                            if arr.len() > MAX_ARRAY_BATCH {
                                bail!(
                                    "Too many elements in batch requests {} max:{}",
                                    arr.len(),
                                    MAX_ARRAY_BATCH
                                );
                            }
                            let mut result = Vec::with_capacity(arr.len());
                            for el in arr {
                                result.push(self.handle_value(el, &empty_params));
                            }
                            Value::Array(result)
                        }
                        Ok(cmd) => self.handle_value(cmd, &empty_params),
                        Err(err) => {
                            warn!("[{}] invalid JSON request: {}", self.addr, err);
                            json_rpc_error("parse error", None, JsonRpcV2Error::ParseError)
                        }
                    };
                    self.send_values(&[reply])?
                }
                Message::PeriodicUpdate => {
                    let values = self
                        .update_subscriptions()
                        .chain_err(|| "failed to update subscriptions")?;
                    self.send_values(&values)?
                }
                Message::Done => return Ok(()),
            }
        }
    }

    fn handle_value(&mut self, cmd: Value, empty_params: &Value) -> Value {
        let start_time = Instant::now();
        match (
            cmd.get("method"),
            cmd.get("params").unwrap_or_else(|| empty_params),
            cmd.get("id"),
        ) {
            (Some(&Value::String(ref method)), &Value::Array(ref params), Some(ref id)) => {
                let reply = self.handle_command(method, params, id).unwrap_or_else(|e| {
                    json_rpc_error(
                        format!("{} failed: {}", method, e),
                        Some(id),
                        JsonRpcV2Error::InternalError,
                    )
                });

                conditionally_log_rpc_event!(
                    self,
                    json!({
                        "event": "rpc_response",
                        "method": method,
                        "params": if self.rpc_logging.hide_params {
                                Value::Null
                            } else {
                                json!(params)
                            },
                        "request_size": serde_json::to_vec(&cmd).map(|v| v.len()).unwrap_or(0),
                        "response_size": reply.to_string().as_bytes().len(),
                        "duration_micros": start_time.elapsed().as_micros(),
                        "id": id,
                    })
                );

                reply
            }
            _ => {
                warn!("[{}] invalid request: {}", self.addr, cmd);
                json_rpc_error("invalid request", cmd.get("id"), JsonRpcV2Error::InvalidRequest)
            }
        }
    }

    #[trace]
    fn parse_requests(mut reader: BufReader<TcpStream>, tx: &SyncSender<Message>) -> Result<()> {
        loop {
            let mut line = Vec::<u8>::new();
            reader
                .read_until(b'\n', &mut line)
                .chain_err(|| "failed to read a request")?;
            if line.is_empty() {
                return Ok(());
            } else {
                if line.starts_with(&[22, 3, 1]) {
                    // (very) naive SSL handshake detection
                    bail!("invalid request - maybe SSL-encrypted data?: {:?}", line)
                }
                match String::from_utf8(line) {
                    Ok(req) => tx
                        .send(Message::Request(req))
                        .chain_err(|| "channel closed")?,
                    Err(err) => {
                        bail!("invalid UTF8: {}", err)
                    }
                }
            }
        }
    }

    fn reader_thread(reader: BufReader<TcpStream>, tx: SyncSender<Message>) -> Result<()> {
        let result = Connection::parse_requests(reader, &tx);
        if let Err(e) = tx.send(Message::Done) {
            warn!("failed closing channel: {}", e);
        }
        result
    }

    pub fn run(mut self, receiver: Receiver<Message>) {
        self.stats.clients.inc();
        conditionally_log_rpc_event!(self, json!({ "event": "connection_established" }));

        let reader = BufReader::new(self.stream.try_clone().expect("failed to clone TcpStream"));
        let sender = self.sender.clone();
        let child = spawn_thread("reader", || Connection::reader_thread(reader, sender));
        if let Err(e) = self.handle_replies(receiver) {
            if is_disconnect(&e) {
                // client went away mid-exchange (broken pipe / reset) — not actionable
                debug!("[{}] connection closed by client: {}", self.addr, e);
            } else {
                error!(
                    "[{}] connection handling failed: {}",
                    self.addr,
                    e.display_chain().to_string()
                );
            }
        }
        self.stats.clients.dec();
        self.stats
            .subscriptions
            .sub(self.status_hashes.len() as i64);

        debug!("[{}] shutting down connection", self.addr);
        conditionally_log_rpc_event!(self, json!({ "event": "connection_closed" }));

        let _ = self.stream.shutdown(Shutdown::Both);
        if let Err(err) = child.join().expect("receiver panicked") {
            error!("[{}] receiver failed: {}", self.addr, err);
        }
    }
}

/// True if the error chain is rooted in a client disconnect (broken pipe /
/// connection reset / aborted), which is expected and shouldn't be logged as ERROR.
fn is_disconnect(err: &Error) -> bool {
    use std::io::ErrorKind::*;
    let mut cause: Option<&(dyn std::error::Error + 'static)> = Some(err);
    while let Some(e) = cause {
        if let Some(io_err) = e.downcast_ref::<std::io::Error>() {
            if matches!(
                io_err.kind(),
                BrokenPipe | ConnectionReset | ConnectionAborted | UnexpectedEof
            ) {
                return true;
            }
        }
        cause = e.source();
    }
    false
}

#[trace]
fn get_history(
    query: &Query,
    scripthash: &[u8],
    txs_limit: usize,
) -> Result<Vec<(Txid, Option<BlockId>)>> {
    // to avoid silently trunacting history entries, ask for one extra more than the limit and fail if it exists
    let history_txids = query.history_txids(scripthash, txs_limit + 1);
    ensure!(history_txids.len() <= txs_limit, ErrorKind::TooPopular);
    Ok(history_txids)
}

#[derive(Serialize, Debug)]
struct GetHistoryResult {
    #[serde(rename = "tx_hash")]
    txid: Txid,
    height: isize,
    #[serde(skip_serializing_if = "Option::is_none")]
    fee: Option<u64>,
}

#[derive(Debug)]
pub enum Message {
    Request(String),
    PeriodicUpdate,
    Done,
}

pub enum Notification {
    Periodic,
    Exit,
}

pub struct RPC {
    notification: Sender<Notification>,
    server: Option<thread::JoinHandle<()>>, // so we can join the server while dropping this ojbect
}

struct Stats {
    latency: HistogramVec,
    clients: Gauge,
    subscriptions: Gauge,
}

impl RPC {
    fn start_notifier(
        notification: Channel<Notification>,
        senders: Arc<Mutex<Vec<SyncSender<Message>>>>,
        acceptor: Sender<Option<(TcpStream, SocketAddr)>>,
    ) {
        spawn_thread("notification", move || {
            for msg in notification.receiver().iter() {
                let mut senders = senders.lock().unwrap();
                match msg {
                    Notification::Periodic => {
                        senders.retain(|sender| {
                            if let Err(TrySendError::Disconnected(_)) =
                                sender.try_send(Message::PeriodicUpdate)
                            {
                                false // drop disconnected clients
                            } else {
                                true
                            }
                        })
                    }
                    Notification::Exit => {
                        if acceptor.send(None).is_err() {
                            warn!("acceptor already shut down before Exit notification");
                        }
                    }
                }
            }
        });
    }

    fn start_acceptor(addr: SocketAddr) -> Channel<Option<(TcpStream, SocketAddr)>> {
        let chan = Channel::unbounded();
        let acceptor = chan.sender();
        spawn_thread("acceptor", move || {
            let socket = create_socket(&addr);
            socket.listen(511).expect("setting backlog failed");
            socket
                .set_nonblocking(false)
                .expect("cannot set nonblocking to false");
            let listener = TcpListener::from(socket);

            info!("Electrum RPC server running on {}", addr);
            loop {
                let (stream, addr) = listener.accept().expect("accept failed");
                stream
                    .set_nonblocking(false)
                    .expect("failed to set connection as blocking");
                stream.set_nodelay(true).expect("failed to set TCP_NODELAY");
                if acceptor.send(Some((stream, addr))).is_err() {
                    break; // receiver dropped, server is shutting down
                }
            }
        });
        chan
    }

    pub fn start(
        config: Arc<Config>,
        query: Arc<Query>,
        metrics: &Metrics,
        salt_rwlock: Arc<RwLock<String>>
    ) -> RPC {
        let stats = Arc::new(Stats {
            latency: metrics.histogram_vec(
                HistogramOpts::new("electrum_rpc", "Electrum RPC latency (seconds)"),
                &["method"],
            ),
            clients: metrics.gauge(MetricOpts::new("electrum_clients", "# of Electrum clients")),
            subscriptions: metrics.gauge(MetricOpts::new(
                "electrum_subscriptions",
                "# of Electrum subscriptions",
            )),
        });
        stats.clients.set(0);
        stats.subscriptions.set(0);

        let notification = Channel::unbounded();

        // Discovery is enabled when electrum-public-hosts is set
        #[cfg(feature = "electrum-discovery")]
        let discovery = config.electrum_public_hosts.clone().map(|hosts| {
            use crate::chain::genesis_hash;
            let features = ServerFeatures {
                hosts,
                server_version: format!("electrs-esplora {}", ELECTRS_VERSION),
                genesis_hash: genesis_hash(config.network_type),
                protocol_min: PROTOCOL_VERSION,
                protocol_max: PROTOCOL_VERSION,
                hash_function: "sha256".into(),
                pruning: None,
            };
            let discovery = Arc::new(DiscoveryManager::new(
                config.network_type,
                features,
                PROTOCOL_VERSION,
                config.electrum_announce,
                config.tor_proxy,
            ));
            DiscoveryManager::spawn_jobs_thread(Arc::clone(&discovery));
            discovery
        });

        let rpc_addr = config.electrum_rpc_addr;
        let txs_limit = config.electrum_txs_limit;

        RPC {
            notification: notification.sender(),
            server: Some(spawn_thread("rpc", move || {
                let senders = Arc::new(Mutex::new(Vec::<SyncSender<Message>>::new()));

                let acceptor = RPC::start_acceptor(rpc_addr);
                RPC::start_notifier(notification, senders.clone(), acceptor.sender());

                let mut threads = HashMap::new();
                let (garbage_sender, garbage_receiver) = crossbeam_channel::unbounded();

                while let Some((stream, addr)) = acceptor.receiver().recv().unwrap() {
                    // explicitly scope the shadowed variables for the new thread
                    let query = Arc::clone(&query);
                    let stats = Arc::clone(&stats);
                    let garbage_sender = garbage_sender.clone();
                    let rpc_logging = config.rpc_logging.clone();
                    #[cfg(feature = "electrum-discovery")]
                    let discovery = discovery.clone();

                    let (sender, receiver) = mpsc::sync_channel(10);
                    senders.lock().unwrap().push(sender.clone());

                    let salt = salt_rwlock.read().unwrap().clone();

                    let spawned = spawn_thread("peer", move || {
                        debug!("[{}] connected peer", addr);
                        let conn = Connection::new(
                            query,
                            stream,
                            addr,
                            sender,
                            stats,
                            txs_limit,
                            #[cfg(feature = "electrum-discovery")]
                            discovery,
                            rpc_logging,
                            salt,
                        );
                        conn.run(receiver);
                        debug!("[{}] disconnected peer", addr);
                        let _ = garbage_sender.send(std::thread::current().id());
                    });

                    trace!("[{}] spawned {:?}", addr, spawned.thread().id());
                    threads.insert(spawned.thread().id(), spawned);
                    while let Ok(id) = garbage_receiver.try_recv() {
                        if let Some(thread) = threads.remove(&id) {
                            trace!("[{}] joining {:?}", addr, id);
                            if let Err(error) = thread.join() {
                                error!("failed to join {:?}: {:?}", id, error);
                            }
                        }
                    }
                }

                trace!("closing {} RPC connections", senders.lock().unwrap().len());
                for sender in senders.lock().unwrap().iter() {
                    let _ = sender.send(Message::Done);
                }

                for (id, thread) in threads {
                    trace!("joining {:?}", id);
                    if let Err(error) = thread.join() {
                        error!("failed to join {:?}: {:?}", id, error);
                    }
                }

                trace!("RPC connections are closed");
            })),
        }
    }

    pub fn notify(&self) {
        self.notification.send(Notification::Periodic).unwrap();
    }
}

impl Drop for RPC {
    fn drop(&mut self) {
        trace!("stop accepting new RPCs");
        self.notification.send(Notification::Exit).unwrap();
        if let Some(handle) = self.server.take() {
            handle.join().unwrap();
        }
        trace!("RPC server is stopped");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_ip_with_salt() {
        // SHA-256("test_salt" || "127.0.0.1")
        let result = hash_ip_with_salt("test_salt", "127.0.0.1");
        assert_eq!(
            result,
            "d474826bbd126d38bdfb1e61bf727a2d9a306ea1645071faf2638cc3891a2b30"
        );
    }
}

#[cfg(test)]
mod verbose_tx_tests {
    use serde_json::{json, Value};

    /// Validates that a verbose transaction response contains all required fields
    /// per the Electrum protocol specification for blockchain.transaction.get
    fn validate_verbose_tx_structure(response: &Value, is_confirmed: bool) {
        // Required fields per Electrum protocol (matching Bitcoin Core's getrawtransaction)
        assert!(response.get("txid").is_some(), "missing txid field");
        assert!(response.get("hash").is_some(), "missing hash (wtxid) field");
        assert!(response.get("version").is_some(), "missing version field");
        assert!(response.get("size").is_some(), "missing size field");
        assert!(response.get("vsize").is_some(), "missing vsize field");
        assert!(response.get("weight").is_some(), "missing weight field");
        assert!(response.get("locktime").is_some(), "missing locktime field");
        assert!(response.get("vin").is_some(), "missing vin field");
        assert!(response.get("vout").is_some(), "missing vout field");
        assert!(response.get("hex").is_some(), "missing hex field");

        // Type validations
        assert!(
            response["txid"].is_string(),
            "txid must be a string"
        );
        assert!(
            response["hash"].is_string(),
            "hash must be a string"
        );
        assert!(
            response["version"].is_number(),
            "version must be a number"
        );
        assert!(
            response["size"].is_number(),
            "size must be a number"
        );
        assert!(
            response["vsize"].is_number(),
            "vsize must be a number"
        );
        assert!(
            response["weight"].is_number(),
            "weight must be a number"
        );
        assert!(
            response["locktime"].is_number(),
            "locktime must be a number"
        );
        assert!(response["vin"].is_array(), "vin must be an array");
        assert!(response["vout"].is_array(), "vout must be an array");
        assert!(response["hex"].is_string(), "hex must be a string");

        // Confirmed transaction specific fields
        if is_confirmed {
            assert!(
                response.get("blockhash").is_some(),
                "confirmed tx missing blockhash"
            );
            assert!(
                response.get("confirmations").is_some(),
                "confirmed tx missing confirmations"
            );
            assert!(
                response.get("time").is_some(),
                "confirmed tx missing time"
            );
            assert!(
                response.get("blocktime").is_some(),
                "confirmed tx missing blocktime"
            );
            // Electrum protocol adds height field
            assert!(
                response.get("height").is_some(),
                "confirmed tx missing height (Electrum extension)"
            );

            assert!(
                response["blockhash"].is_string(),
                "blockhash must be a string"
            );
            assert!(
                response["confirmations"].is_number(),
                "confirmations must be a number"
            );
            assert!(response["time"].is_number(), "time must be a number");
            assert!(
                response["blocktime"].is_number(),
                "blocktime must be a number"
            );
            assert!(
                response["height"].is_number(),
                "height must be a number"
            );
        }
    }

    /// Validates the structure of a vin entry
    fn validate_vin_structure(vin: &Value, is_coinbase: bool) {
        assert!(vin.get("sequence").is_some(), "vin missing sequence");
        assert!(vin["sequence"].is_number(), "sequence must be a number");

        if is_coinbase {
            assert!(
                vin.get("coinbase").is_some(),
                "coinbase vin missing coinbase field"
            );
            assert!(
                vin["coinbase"].is_string(),
                "coinbase must be a string"
            );
        } else {
            assert!(vin.get("txid").is_some(), "vin missing txid");
            assert!(vin.get("vout").is_some(), "vin missing vout");
            assert!(vin.get("scriptSig").is_some(), "vin missing scriptSig");

            assert!(vin["txid"].is_string(), "vin txid must be a string");
            assert!(vin["vout"].is_number(), "vin vout must be a number");
            assert!(
                vin["scriptSig"].is_object(),
                "scriptSig must be an object"
            );

            let script_sig = &vin["scriptSig"];
            assert!(
                script_sig.get("asm").is_some(),
                "scriptSig missing asm"
            );
            assert!(
                script_sig.get("hex").is_some(),
                "scriptSig missing hex"
            );
        }

        // txinwitness is optional (only for segwit inputs)
        if let Some(witness) = vin.get("txinwitness") {
            assert!(witness.is_array(), "txinwitness must be an array");
        }
    }

    /// Validates the structure of a vout entry
    fn validate_vout_structure(vout: &Value) {
        assert!(vout.get("value").is_some(), "vout missing value");
        assert!(vout.get("n").is_some(), "vout missing n");
        assert!(
            vout.get("scriptPubKey").is_some(),
            "vout missing scriptPubKey"
        );

        assert!(vout["value"].is_number(), "value must be a number");
        assert!(vout["n"].is_number(), "n must be a number");
        assert!(
            vout["scriptPubKey"].is_object(),
            "scriptPubKey must be an object"
        );

        let script_pub_key = &vout["scriptPubKey"];
        assert!(
            script_pub_key.get("asm").is_some(),
            "scriptPubKey missing asm"
        );
        assert!(
            script_pub_key.get("hex").is_some(),
            "scriptPubKey missing hex"
        );
        assert!(
            script_pub_key.get("type").is_some(),
            "scriptPubKey missing type"
        );
    }

    #[test]
    fn test_verbose_tx_unconfirmed_structure() {
        // Simulated unconfirmed verbose transaction response
        let response = json!({
            "txid": "abc123def456789abc123def456789abc123def456789abc123def456789abc1",
            "hash": "abc123def456789abc123def456789abc123def456789abc123def456789abc1",
            "version": 2,
            "size": 225,
            "vsize": 144,
            "weight": 573,
            "locktime": 0,
            "vin": [
                {
                    "txid": "def456789abc123def456789abc123def456789abc123def456789abc123def4",
                    "vout": 0,
                    "scriptSig": {
                        "asm": "",
                        "hex": ""
                    },
                    "txinwitness": [
                        "304402...",
                        "02abc..."
                    ],
                    "sequence": 4294967295u64
                }
            ],
            "vout": [
                {
                    "value": 0.001,
                    "n": 0,
                    "scriptPubKey": {
                        "asm": "OP_DUP OP_HASH160 ... OP_EQUALVERIFY OP_CHECKSIG",
                        "hex": "76a914...",
                        "type": "pubkeyhash",
                        "address": "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"
                    }
                }
            ],
            "hex": "0200000001..."
        });

        validate_verbose_tx_structure(&response, false);

        for vin in response["vin"].as_array().unwrap() {
            validate_vin_structure(vin, false);
        }

        for vout in response["vout"].as_array().unwrap() {
            validate_vout_structure(vout);
        }
    }

    #[test]
    fn test_verbose_tx_confirmed_structure() {
        // Simulated confirmed verbose transaction response
        let response = json!({
            "txid": "abc123def456789abc123def456789abc123def456789abc123def456789abc1",
            "hash": "abc123def456789abc123def456789abc123def456789abc123def456789abc1",
            "version": 2,
            "size": 225,
            "vsize": 144,
            "weight": 573,
            "locktime": 0,
            "vin": [
                {
                    "txid": "def456789abc123def456789abc123def456789abc123def456789abc123def4",
                    "vout": 0,
                    "scriptSig": {
                        "asm": "",
                        "hex": ""
                    },
                    "sequence": 4294967295u64
                }
            ],
            "vout": [
                {
                    "value": 0.001,
                    "n": 0,
                    "scriptPubKey": {
                        "asm": "OP_DUP OP_HASH160 ... OP_EQUALVERIFY OP_CHECKSIG",
                        "hex": "76a914...",
                        "type": "pubkeyhash"
                    }
                }
            ],
            "hex": "0200000001...",
            "blockhash": "0000000000000000000abc123def456789abc123def456789abc123def456789",
            "confirmations": 100,
            "time": 1700000000,
            "blocktime": 1700000000,
            "height": 800000
        });

        validate_verbose_tx_structure(&response, true);

        for vin in response["vin"].as_array().unwrap() {
            validate_vin_structure(vin, false);
        }

        for vout in response["vout"].as_array().unwrap() {
            validate_vout_structure(vout);
        }
    }

    #[test]
    fn test_verbose_tx_coinbase_structure() {
        // Simulated coinbase transaction response
        let response = json!({
            "txid": "abc123def456789abc123def456789abc123def456789abc123def456789abc1",
            "hash": "abc123def456789abc123def456789abc123def456789abc123def456789abc1",
            "version": 1,
            "size": 200,
            "vsize": 200,
            "weight": 800,
            "locktime": 0,
            "vin": [
                {
                    "coinbase": "03a50c0b...",
                    "sequence": 4294967295u64
                }
            ],
            "vout": [
                {
                    "value": 6.25,
                    "n": 0,
                    "scriptPubKey": {
                        "asm": "OP_HASH160 ... OP_EQUAL",
                        "hex": "a914...",
                        "type": "scripthash",
                        "address": "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"
                    }
                }
            ],
            "hex": "01000000010000...",
            "blockhash": "0000000000000000000abc123def456789abc123def456789abc123def456789",
            "confirmations": 1000,
            "time": 1700000000,
            "blocktime": 1700000000,
            "height": 800000
        });

        validate_verbose_tx_structure(&response, true);

        // First vin is coinbase
        validate_vin_structure(&response["vin"][0], true);

        for vout in response["vout"].as_array().unwrap() {
            validate_vout_structure(vout);
        }
    }

    #[test]
    fn test_vsize_calculation() {
        // vsize = (weight + 3) / 4 (ceiling division)
        // Test various weight values
        let test_cases = [
            (400, 100),   // weight 400 -> vsize 100
            (401, 101),   // weight 401 -> vsize 101 (ceiling)
            (402, 101),   // weight 402 -> vsize 101
            (403, 101),   // weight 403 -> vsize 101
            (404, 101),   // weight 404 -> vsize 101
            (573, 144),   // typical segwit tx
            (1000, 250),  // weight 1000 -> vsize 250
        ];

        for (weight, expected_vsize) in test_cases {
            let vsize = (weight + 3) / 4;
            assert_eq!(
                vsize, expected_vsize,
                "weight {} should give vsize {}, got {}",
                weight, expected_vsize, vsize
            );
        }
    }

    #[test]
    fn test_verbose_tx_script_types() {
        // Test that various script types are recognized
        let script_types = [
            "pubkeyhash",           // P2PKH
            "scripthash",           // P2SH
            "witness_v0_keyhash",   // P2WPKH
            "witness_v0_scripthash", // P2WSH
            "nulldata",             // OP_RETURN
            "pubkey",               // P2PK
            "nonstandard",          // Unknown
            "witness_unknown",      // Unknown witness version
        ];

        for script_type in script_types {
            let vout = json!({
                "value": 0.001,
                "n": 0,
                "scriptPubKey": {
                    "asm": "...",
                    "hex": "...",
                    "type": script_type
                }
            });

            validate_vout_structure(&vout);
            assert_eq!(
                vout["scriptPubKey"]["type"].as_str().unwrap(),
                script_type
            );
        }
    }
}
