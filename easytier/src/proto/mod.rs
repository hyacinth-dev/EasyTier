pub mod rpc_impl;
pub mod rpc_types;

pub mod cli;
pub mod common;
pub mod error;
pub mod peer_rpc;
pub mod web;


const DESCRIPTOR_POOL_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/file_descriptor_set.bin"));
