#![feature(iterator_step_by)]
#![feature(rustc_private)]

#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate rustc_serialize;

mod ndsbf;
mod ndsk2;

use std::env;
use std::io::prelude::*;
use std::fs::File;

use ndsbf::Blowfish;
use ndsk2::Key2;
use rustc_serialize::hex::{ToHex, FromHex};

#[derive(Deserialize, Debug)]
#[serde(tag = "type")]
enum Block {
    #[serde(rename = "command")]
    Command { command: String, response: Option<String> },
    #[serde(rename = "reset")]
    Reset { comment: String },
    #[serde(rename = "comment")]
    Comment { comment: String }
}

enum EncLevel {
    Raw, Key1, Key2
}

struct State {
    bf: Blowfish,
    k2: Key2,
    k2_seed: u8,
    enc: EncLevel
}

fn uu8b(b: &[u8]) -> u64 {
    if b.len() < 8 {
        panic!("u8 slice of length {} passed to uu8b", b.len());
    }

    u64::from_be(unsafe { *(b.as_ptr() as *const u64) })
}

fn be_bits(i: &[u8], j: u32, k: u32) -> u64 {
    (uu8b(i) >> j) & ((1u64 << k) - 1)
}

fn do_block(block: &Block, state: &mut State) {
    match *block {
        Block::Command { ref command, ref response } => do_cmd(command, response.as_ref().map(|x| &**x), state),
        Block::Reset { ref comment } => {
            println!("RESET: {}", comment);
            state.enc = EncLevel::Raw;
        }
        Block::Comment { comment: ref _comment } => {
            if _comment.contains("!= low 520)") {
                state.k2.dobytes(&mut [0u8; 520]);
                println!("advancing KEY2 by 520 bytes");
            }
            //println!("comment: {}", _comment);
        }
    }
}

fn do_cmd(cmd: &str, resp: Option<&str>, state: &mut State) {
    macro_rules! pcmd {
        ($cmd:expr, p $($y:expr), +) => ({
            print!("{} CMD: {}: ", match state.enc {
                EncLevel::Raw => "RAW",
                EncLevel::Key1 => "KEY1",
                EncLevel::Key2 => "KEY2"
            }, $cmd);
            println!($($y), +);
        });
        ($($y:expr), +) => ({
            pcmd!(cmd, p $($y),+);
        });
    }

    let cmdb = match cmd.from_hex() {
        Ok(a) => a,
        Err(e) => {
            println!("Invalid hex string \"{}\" in JSON: {}", cmd, e);
            return;
        }
    };
    let resb = match resp {
        Some(hex) => match hex.from_hex() {
            Ok(a) => a,
            Err(e) => {
                println!("Invalid hex string \"{}\" in JSON: {}", cmd, e);
                vec![0u8; 0]
            }
        }
        None => vec![0u8; 0]
    };
    match state.enc {
        EncLevel::Raw => {
            let cmd0 = cmdb[0];
            match cmd0 {
                0x9F => pcmd!("dummy"),
                0 if resb.len() > 0x13 => {
                    let gamecode = &resb[0xC..0x10];
                    let k2hdrbyte = resb[0x13] & 0x7;
                    state.bf.init(gamecode, 2);
                    state.k2_seed = k2hdrbyte;
                    pcmd!("header; gamecode = {}, k2 seed = {}", gamecode.to_hex(), k2hdrbyte);
                }
                0x90 => {
                    pcmd!("get chipid = {}", resb.to_hex());
                }
                0x3C if cmdb.len() >= 8 => {
                    let i = be_bits(&cmdb[..], 44, 12);
                    let j = be_bits(&cmdb[..], 32, 12);
                    let k = be_bits(&cmdb[..], 8, 20);
                    pcmd!("switch to KEY1; i = 0x{:X}, j = 0x{:X}, k = 0x{:X}", i, j, k);
                    state.enc = EncLevel::Key1;
                }
                _ => pcmd!("unknown (response length 0x{:X}) = {}", resb.len(), resp.unwrap_or(""))
            }
        }
        EncLevel::Key1 => {
            let mut cmdr = [0u8; 8];
            state.bf.decrypt_block(&cmdb[0..8], &mut cmdr);
            let cmd0 = cmdr[0] >> 4;
            if cmd0 == 4 {
                let k2seed = be_bits(&cmdr[..], 20, 24);
                state.k2.init(k2seed as u32, state.k2_seed);
                pcmd!(cmdr.to_hex(), p "key2 seed: 0x{:X}", k2seed);
            } else {
                let mut resr = resb;
                state.k2.dobytes(&mut resr[..]);

                match cmd0 {
                    1 if resr.len() >= 0x910 => {
                        pcmd!(cmdr.to_hex(), p "get chipid = {}", resr[0x910..].to_hex())
                    }
                    2 => {
                        let ofs = be_bits(&cmdr[..], 44, 16);
                        pcmd!(cmdr.to_hex(), p "get secure area @ 0x{:X}000", ofs);
                    }
                    0xA => {
                        pcmd!(cmdr.to_hex(), p "switch to KEY2");
                        state.enc = EncLevel::Key2;
                    }
                    _ => {
                        pcmd!(cmdr.to_hex(), p "unknown");
                    }
                }
            }
        }
        EncLevel::Key2 => {
            let mut cmdr = cmdb;
            let mut resr = resb;
            state.k2.dobytes(&mut cmdr[..]);
            state.k2.dobytes(&mut resr[..]);
            let cmd0 = cmdr[0];
            match cmd0 {
                0xB7 if resr.len() == 0x200 => {
                    let adr = be_bits(&cmdr[..], 24, 32);
                    pcmd!(cmdr.to_hex(), p "load ROM 0x200 @ 0x{:X}", adr);
                }
                0xB8 if resr.len() == 4 => pcmd!(cmdr.to_hex(), p "get chipid = {}", resr.to_hex()),
                0x66 if resr.len() == 4 => {
                    pcmd!(cmdr.to_hex(), p "r4isdhc switch from KEY2 to RAW = raw {}, key2 decrypted {}", resp.unwrap_or("wtf?"), resr.to_hex());
                    state.enc = EncLevel::Raw;
                }
                _ if resr.len() == 4 => {
                    pcmd!(cmdr.to_hex(), p "corrupt get chipid = {}", resr.to_hex());
                }
                _ if resr.len() == 0x200 => {
                    pcmd!(cmdr.to_hex(), p "corrupt load ROM");
                }
                _ => {
                    pcmd!(cmdr.to_hex(), p "unknown");
                }
            }
        }

    }
}

fn main() {
    let jsonfn = match env::args().skip(1).next() {
        Some(f) => f,
        None => {
            println!("Usage: ladecrypt <file.json>");
            return;
        }
    };
    let mut jsonf = match File::open(&jsonfn) {
        Ok(f) => f,
        Err(e) => {
            println!("Error opening file {}: {}", jsonfn, e);
            return;
        }
    };
    let mut json = String::new();
    match jsonf.read_to_string(&mut json) {
        Ok(_) => (),
        Err(e) => {
            println!("Error reading file {}: {}", jsonfn, e);
            return;
        }
    }
    let blocks: Vec<Block> = match serde_json::from_str(&json) {
        Ok(b) => b,
        Err(e) => {
            println!("Error parsing file {}: {}", jsonfn, e);
            return;
        }
    };
    let mut state = State {
        bf: Blowfish::new(), k2: Key2::new(), enc: EncLevel::Raw, k2_seed: 0xFF
    };
    for block in &blocks {
        do_block(block, &mut state);
    }
}
