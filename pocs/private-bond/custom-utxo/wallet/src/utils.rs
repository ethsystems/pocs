//! Utility functions and data paths for the wallet

use alloy::primitives::FixedBytes;
use chrono::DateTime;
use num_bigint::BigUint;
use poseidon_rs::Fr;
use ff::PrimeField;
use serde::{Deserialize, Serialize};
use std::fs;

use crate::keys::ShieldedKeys;

/// Data directory for all wallet files
pub const DATA_DIR: &str = "data";

/// Get path for wallet file
pub fn wallet_path(wallet_name: &str) -> String {
    format!("{}/{}.json", DATA_DIR, wallet_name)
}

/// Get path for bond file  
pub fn bond_path(filename: &str) -> String {
    if filename.starts_with(DATA_DIR) || filename.starts_with("./") {
        filename.to_string()
    } else {
        format!("{}/{}", DATA_DIR, filename)
    }
}

/// Get path for tree state file
pub fn tree_state_path() -> String {
    format!("{}/tree_state.json", DATA_DIR)
}

/// Get path for global note tranche file
pub fn global_note_path() -> String {
    format!("{}/global_note_tranche.json", DATA_DIR)
}

/// Ensure data directory exists
pub fn ensure_data_dir() {
    let _ = fs::create_dir_all(DATA_DIR);
}

/// Convert Fr field element to bytes32 for contract calls
pub fn fr_to_bytes32(fr: &Fr) -> FixedBytes<32> {
    let repr = fr.into_repr();
    let limbs: &[u64] = repr.as_ref();
    
    // Convert 4 u64 limbs to 32 bytes (little-endian limbs to big-endian bytes)
    let mut bytes = [0u8; 32];
    for (i, limb) in limbs.iter().enumerate() {
        let limb_bytes = limb.to_le_bytes();
        bytes[i * 8..(i + 1) * 8].copy_from_slice(&limb_bytes);
    }
    // Reverse for big-endian (contract expects big-endian)
    bytes.reverse();
    FixedBytes::from(bytes)
}

/// Convert u64 (such as a maturity date) to big-endian bytes32 for contract calls
pub fn u64_to_bytes32(value: u64) -> FixedBytes<32> {
    let mut bytes = [0u8; 32];
    bytes[24..32].copy_from_slice(&value.to_be_bytes());
    FixedBytes::from(bytes)
}

/// Format timestamp as human-readable date
pub fn format_date(ts: u64) -> String {
    match DateTime::from_timestamp(ts as i64, 0) {
        Some(dt) => dt.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        None => format!("{} (invalid)", ts),
    }
}

/// Parse commitment string (Fr(0x...) format) to Fr
pub fn parse_commitment(s: &str) -> Option<Fr> {
    // Strip "Fr(0x" prefix and ")" suffix
    let clean = s
        .trim_start_matches("Fr(0x")
        .trim_start_matches("Fr(")
        .trim_start_matches("0x")
        .trim_end_matches(')');
    
    // Try parsing as hex
    if let Ok(bytes) = hex::decode(clean) {
        if !bytes.is_empty() {
            // Convert hex bytes to a big number, then to Fr
            let mut num_bytes = [0u8; 32];
            let start = if bytes.len() > 32 { bytes.len() - 32 } else { 0 };
            let copy_start = 32 - std::cmp::min(32, bytes.len());
            num_bytes[copy_start..].copy_from_slice(&bytes[start..]);
            
            // Convert to decimal string for Fr::from_str
            let result = BigUint::from_bytes_be(&num_bytes);
            if let Some(fr) = Fr::from_str(&result.to_string()) {
                return Some(fr);
            }
        }
    }
    
    // Fallback: try parsing as decimal
    Fr::from_str(clean)
}

// === Wallet and Bond types ===

#[derive(Serialize, Deserialize, Debug)]
pub struct Wallet {
    pub keys: ShieldedKeys,
    pub created_at: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Bond {
    pub commitment: String,
    pub nullifier: String,
    pub value: u64,
    pub salt: u64,
    pub owner: String,
    pub asset_id: u64,
    pub maturity_date: u64,
    pub created_at: String,
}

/// Load wallet from data directory
pub fn load_wallet(wallet_name: &str) -> Option<Wallet> {
    let path = wallet_path(wallet_name);
    match fs::read_to_string(&path) {
        Ok(content) => serde_json::from_str(&content).ok(),
        Err(_) => None,
    }
}

/// Save wallet to data directory
pub fn save_wallet(wallet_name: &str, wallet: &Wallet) -> std::io::Result<()> {
    ensure_data_dir();
    let path = wallet_path(wallet_name);
    fs::write(&path, serde_json::to_string_pretty(wallet)?)
}

/// Load bond from path (handles both absolute and relative paths)
pub fn load_bond(path: &str) -> Option<Bond> {
    // Try path as-is first, then with data/ prefix
    let paths_to_try = [path.to_string(), bond_path(path)];
    
    for p in &paths_to_try {
        if let Ok(content) = fs::read_to_string(p) {
            match serde_json::from_str(&content) {
                Ok(bond) => return Some(bond),
                Err(e) => {
                    println!("❌ Error parsing bond from {}: {}", p, e);
                    return None;
                }
            }
        }
    }
    println!("❌ Bond file not found: {}", path);
    None
}

/// Save bond to data directory
pub fn save_bond(filename: &str, bond: &Bond) -> std::io::Result<String> {
    ensure_data_dir();
    let path = bond_path(filename);
    fs::write(&path, serde_json::to_string_pretty(bond)?)?;
    Ok(path)
}

// === Tree State for merkle commitments ===

use crate::merkle::FixedMerkleTree;

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct TreeState {
    /// List of commitment strings in insertion order (stored as Fr debug format)
    pub commitments: Vec<String>,
}

impl TreeState {
    pub fn load() -> Self {
        let path = tree_state_path();
        match fs::read_to_string(&path) {
            Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
            Err(_) => TreeState::default(),
        }
    }
    
    pub fn save(&self) {
        ensure_data_dir();
        let path = tree_state_path();
        let _ = fs::write(&path, serde_json::to_string_pretty(self).unwrap());
    }
    
    pub fn add_commitment(&mut self, commitment_fr: Fr) -> usize {
        let index = self.commitments.len();
        // Store as the Fr debug format for consistency
        self.commitments.push(format!("{}", commitment_fr));
        self.save();
        index
    }
    
    pub fn find_commitment(&self, commitment_str: &str) -> Option<usize> {
        self.commitments.iter().position(|c| c == commitment_str)
    }
    
    /// Build a merkle tree from stored commitments
    pub fn build_tree(&self) -> FixedMerkleTree {
        let mut tree = FixedMerkleTree::new();
        for comm_str in &self.commitments {
            if let Some(fr) = parse_commitment(comm_str) {
                tree.insert(fr);
            }
        }
        tree
    }
}
