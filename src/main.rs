pub extern crate chrono;
pub extern crate digest;
pub extern crate hmac;
pub extern crate itertools;

use chrono::prelude::*;
use digest::Digest;
use itertools::Itertools;
use time::Timespec;

const GENESIS_USER_ADDRESS_DEFAULT: String = "genesis".to_string();
const GENESIS_IP_DEFAULT: String = "127.0.0.1".to_string();
const GENESIS_PORT_DEFAULT: u32 = 5000;
const GENESIS_PASSPHRASE_DEFAULT: String = "YOU NEED TO CHANGE THIS
PHRASE IT IS CRITICAL FOR YOUR BLOCKCHAIN PROJECT".to_string();
const GENESIS_STAKE_SCORE_DEFAULT: u32 = 1000;
const GENESIS_REPUTATION_SCORE_DEFAULT: u32 = 1000;
const GENESIS_AMOUNT_DEFAULT: u64 = 1000000000;
const GENESIS_PREVIOUS_HASH_DEFAULT: u32 = 1;
const GENESIS_PROOF_DEFAULT: u32 = 100;

const USER_STAKE_SCORE_DEFAULT: u32 = 0;
const USER_REPUTATION_SCORE_DEFAULT: u32 = 0;

const ADDRESS_SIZE_DEFAULT: u32 = 32;

pub struct Log {
    json: String,
    timestampValue: i64,
    len: usize,
    hash: [u8],
}

pub struct Host {
    router_host_address_network: u64,
    cypher_host_address_network: u64,
    data_host_address_network: u64,
    key_host_address_network: u64,
    gen_host_address_network: u64,
    address_user: Vec<String>,
    address_network: u64,
    reputation_score: u32,
    stake_score: u32,
    ip: String,
    port: u32,
    timestampValue: i64,
    log: Log,
}

pub struct Transaction {
    message: String,
    sender: Host,
    recipient: Host,
    amount: u64,
    timestampValue: i64,
    log: Log,
}

pub struct Block {
    previous_hash: String,
    proof: u32,
    mined: bool,
    transactions: Option<Vec<Transaction>>,
    index: Option<u32>,
    timestampValue: i64,
    log: Log,
}

pub struct Blockchain {
    current_transaction: Vec<Transaction>,
    chain: Vec<Block>,
    nodes: Vec<Host>,
    router_hosts: Vec<Host>,
    cypher_hosts: Vec<Host>,
    data_hosts: Vec<Host>,
    key_hosts: Vec<Host>,
    gen_hosts: Vec<Host>,
    timestampValue: i64,
    log: Log,
}

impl Log {
    fn get_unix_timestamp_ms(&self) -> i64 {
        let now = Utc::now();
        let seconds: i64 = now.timestamp();
        let nanoseconds: i64 = now.nanosecond() as i64;
        (seconds * 1000) + (nanoseconds / 1000 / 1000)
    }
    fn update<D: Digest>(&mut self, json: String) {
        let salt: String = "ssdfsdfsdf".to_string();
        self.json = json;
        let mut hasher = D::new();
        hasher.input(self.json.as_bytes());
        hasher.input(b"$");
        hasher.input(salt.as_bytes());
        self.hashcopy_from_slice(hasher.result().as_slice());
    }
}

impl Host {
    fn serialize(&mut self) -> String {
        let t: String = self.timestampValue;
        let json: String = "{" + format!(
            "\"router_host_address_network\": \"{router_host_address_network}\",
            \"cypher_host_address_network\": \"{cypher_host_address_network}\",
            \"data_host_address_network\": \"{data_host_address_network}\",
            \"key_host_address_network\": \"{key_host_address_network}\",
            \"gen_host_address_network\": \"{gen_host_address_network}\",
            \"address_user\": {address_user}, \
            \"address_network\": {address_network}, \
            \"reputation_score\": {reputation_score}, \
            \"stake_score\": {stake_score}, \
            \"ip\": \"{ip}\", \
            \"port\": {port}, \
            \"timestampValue\": {timestampValue}",
            router_host_address_network = self.router_host_address_network,
            cypher_host_address_network = self.cypher_host_address_network,
            data_host_address_network = self.data_host_address_network,
            key_host_address_network = self.key_host_address_network,
            gen_host_address_network = self.gen_host_address_network,
            address_user = self.address_user,
            address_network = self.address_network,
            reputation_score = self.reputation_score,
            stake_score = self.stake_score,
            ip = self.ip,
            port = self.port,
            timestampValue = t) + "}";
        json
    }
}

impl Transaction {
    fn serialize(&mut self) -> String {
        let t: String = self.timestampValue.to_string();
        let json: String = "{" + format!(
            "\"message\": \"{message}\",
            \"sender\": \"{sender}\",
            \"recipient\": \"{recipient}\",
            \"amount\": {amount},
            \"timestampValue\": {timestampValue}",
            message = self.message,
            sender = self.sender,
            recipient = self.recipient,
            amount = self.amount,
            timestampValue = t) + "}";
        json
    }
}

impl Block {
    fn serialize(&mut self) -> String {
        let t: String = self.timestampValue.to_string();
        let json: String = "{" + format!(
            "\"previous_hash\": \"{previous_hash}\",
            \"proof\": \"{proof}\",
            \"mined\": \"{mined}\",
            \"transactions\": \"{transactions}\",
            \"index\": {index},
            \"timestampValue\": {timestampValue}",
            previous_hash = self.previous_hash,
            proof = self.proof,
            mined = self.mined,
            transactions = self.transactions,
            index = self.index,
            timestampValue = t) + "}";
        json
    }
}

impl Blockchain {
    fn serialize(&mut self) -> String {
        let t: String = self.timestampValue.to_string();
        let json: String = "{" + format!(
            "\"current_transaction\": \"{current_transaction}\",
            \"chain\": \"{chain}\",
            \"nodes\": \"{nodes}\",
            \"router_hosts\": \"{router_hosts}\",
            \"cypher_hosts\": \"{cypher_hosts}\",
            \"data_hosts\": \"{data_hosts}\",
            \"key_hosts\": \"{key_hosts}\",
            \"gen_hosts\": \"{gen_hosts}\",
            \"timestampValue\": {timestampValue}",
            current_transaction = self.current_transaction,
            chain = self.chain,
            nodes = self.nodes,
            router_hosts = self.router_hosts,
            cypher_hosts = self.cypher_hosts,
            data_hosts = self.data_hosts,
            key_hosts = self.key_hosts,
            gen_hosts = self.gen_hosts,
            timestampValue = t) + "}";
        json
    }
}


impl Host {
    fn new(router_host_address_network: u64,
           cypher_host_address_network: u64, data_host_address_network: u64,
           key_host_address_network: u64, gen_host_address_network: u64,
           address_user: Vec<String>, ip: String, port: u32,
           passphrase: String) -> Host {
        let address_network: u64;
        let len: u32;
        let hash: u64;
        let timestampValue: Timespec;
        let mut host = Host {
            router_host_address_network,
            cypher_host_address_network,
            data_host_address_network,
            key_host_address_network,
            gen_host_address_network,
            address_user,
            address_network,
            reputation_score: USER_REPUTATION_SCORE_DEFAULT,
            stake_score: USER_STAKE_SCORE_DEFAULT,
            ip,
            port,
            timestampValue,
        };
        host.hash = Host::calculate_hash(&host);
        host.address_network = host.hash;
        host;
    }

    pub fn new_genesis(address_user: String, ip: String, port: u32,
                       passphrase: String) -> Host {
        let address_network: String;
        let len: u32;
        let hash: u64;
        let timestampValue: Timespec;
        let mut host = Host {
            router_host_address_network: &address_network,
            cypher_host_address_network: &address_network,
            data_host_address_network: &address_network,
            key_host_address_network: &address_network,
            gen_host_address_network: &address_network,
            address_user,
            address_network,
            reputation_score: GENESIS_REPUTATION_SCORE_DEFAULT,
            stake_score: GENESIS_STAKE_SCORE_DEFAULT,
            ip,
            port,
            timestampValue,
        };
        host.hash = Host::calculate_hash(&host);
        host.router_host_address_network = &host.hash;
        host.cypher_host_address_network = &host.hash;
        host.data_host_address_network = &host.hash;
        host.key_host_address_network = &host.hash;
        host.gen_host_address_network = &host.hash;

        host.hash = Host::calculate_hash(&host);
        host.address_network = host.hash;
        host;
    }
}

impl Transaction {
    pub fn new(message: String, sender: Host, recipient: Host,
               amount: u64) -> Transaction {
        let len: u32;
        let hash: u64;
        let timestampValue: Timespec;
        let mut transaction = Transaction {
            message,
            sender,
            recipient,
            amount,
            timestampValue,
        };
        transaction.hash = Transaction::calculate_hash(&transaction);
        transaction;
    }
}

impl Block {
    pub fn new(previous_hash: u32, proof: u32) -> Block {
        let transactions: Option<Vec<Transaction>>;
        let index: Option<u32>;
        let len: u32;
        let hash: String;
        let timestampValue: Timespec;
        let mined: bool = false;

        let mut block = Block {
            previous_hash,
            proof,
            mined,
            timestampValue,
            transactions,
            index,
        };
        block.hash = Block::calculate_hash(&block);
        block;
    }
}

impl Blockchain {
    pub fn new(genesis_transaction: Transaction, genesis_block: Block,
               genesis_host: Host) -> Block {
        let mut current_transaction: Vec<Transaction>;
        let mut chain: Vec<Block>;
        let mut nodes: Vec<Host>;
        let mut router_hosts: Vec<Host>;
        let mut cypher_hosts: Vec<Host>;
        let mut data_hosts: Vec<Host>;
        let mut key_hosts: Vec<Host>;
        let mut gen_hosts: Vec<Host>;

        let len: u32;
        let hash: u64;
        let timestampValue: Timespec;

        let mut blockchain = Blockchain {
            current_transaction,
            chain,
            nodes,
            router_hosts,
            cypher_hosts,
            data_hosts,
            key_hosts,
            gen_hosts,
            timestampValue,
        };
        blockchain.current_transaction.push(genesis_transaction);
        blockchain.chain.push(genesis_block);
        blockchain.nodes.push(genesis_host);
        blockchain.router_hosts.push(genesis_host);
        blockchain.cypher_hosts.push(genesis_host);
        blockchain.data_hosts.push(genesis_host);
        blockchain.key_hosts.push(genesis_host);
        blockchain.gen_hosts.push(genesis_host);
        blockchain.hash = Blockchain::calculate_hash(&blockchain);
        blockchain;
    }

    fn register_node(&self, node: Host, router_state: bool,
                     cypher_state: bool, data_state: bool, key_state: bool, gen_state: bool) ->
                     bool {
        // Add a new node to the list of nodes
        // :param address: Address of node. Eg. xleflefefkelmkf

        self.nodes.push(&node);
        self.nodes.sort_unstable();
        self.nodes.dedup();

        if router_state == true {
            self.router_hosts.push(&node);
            self.router_hosts.sort_unstable();
            self.router_hosts.dedup();
        };
        if cypher_state == true {
            self.cypher_hosts.push(&node);
            self.cypher_hosts.sort_unstable();
            self.cypher_hosts.dedup();
        };
        if data_state == true {
            self.data_hosts.push(&node);
            self.data_hosts.sort_unstable();
            self.data_hosts.dedup();
        };
        if key_state == true {
            self.key_hosts.push(&node);
            self.key_hosts.sort_unstable();
            self.key_hosts.dedup();
        };
        if gen_state == true {
            self.gen_hosts.push(&node);
            self.gen_hosts.sort_unstable();
            self.gen_hosts.dedup();
        };

        true
    }

    fn valid_chain(&self) -> bool {
        // Determine if a given blockchain is valid
        // :param chain: A blockchain
        // :return: True if valid, Flse if not"

        let mut last_block: Block = self.chain[0];
        let mut current_index: u32 = 1;

        for i in &self.chain() {
            println!("Test block index: {}", &last_block.log.hash);

            let last_block_hash: Block = self.hash(&last_block);

            if i.previous_hash != last_block_hash {
                false
            } else {
                if !self.valid_proof(last_block.proof, i.proof, last_block_hash) {
                    false
                } else {}
            }
            last_block = i;
            current_index += 1;

            break;
        }
        true
    }

    fn resolve_conflicts(&self) {}

    fn new_block(&self, proof: u32, previous_hash: String) -> Block {
        let block: Block;
        block
    }

    fn new_transaction(&self, sender: String, recipient: String, amount: u64) -> Transaction {
        let transaction: Transaction;
        transaction
    }

    fn proof_of_work(&self, last_block: String) -> u32 {
        let proof: u32;
        proof
    }

    fn valid_proof(&self, last_proof: u32, proof: u32, last_hash: String) -> bool {
        let valid: bool;
        valid
    }
}

pub trait Log_tool {
    fn log(&mut self) {
        let json: String = self.serialize();
        self.log.update(&json);
    }
}

impl Log_tool for Host {}

impl Log_tool for Transaction {}

impl Log_tool for Block {}

impl Log_tool for Blockchain {}

struct API {}

impl API {
    fn route(path: String) -> String {}

    fn response(response: String) -> String {}

    fn mine() -> String {}

    fn new_transaction() -> Block {}

    fn full_chain() -> Blockchain {}

    fn register_nodes() {}

    fn consensus() -> Blockchain {}
}

impl API {}

fn main() {}

fn build() {
    let genesis_host: Host =
        Host::new_genesis(GENESIS_USER_ADDRESS_DEFAULT, GENESIS_IP_DEFAULT,
                          GENESIS_PORT_DEFAULT, GENESIS_PASSPHRASE_DEFAULT);
    let genesis_block: Block = Block::new(GENESIS_PREVIOUS_HASH_DEFAULT,
                                          GENESIS_PROOF_DEFAULT);
    let genesis_transaction: Transaction =
        Transaction::new(GENESIS_USER_ADDRESS_DEFAULT, &genesis_host,
                         &genesis_host, GENESIS_AMOUNT_DEFAULT);
    let blockhain: Blockchain = Blockchain::new(&genesis_transaction,
                                                &genesis_block, &genesis_host);
}
