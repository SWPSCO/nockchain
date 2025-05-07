use std::error::Error;
use std::collections::HashMap;
use std::thread;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::fs;
use std::path::Path;

use nockchain::NockchainCli;
use clap::Parser;

fn main() -> Result<(), Box<dyn Error>> {
   println!("Nockchain wrapper");
   
   let config_path = "crates/ncwrap/src/vals.json";
   let cli = parse_json_config(config_path)?;
   
   println!("\nRunning `nockchain -- {}`\n", 
       build_cli_string(&cli));
   
   let running = Arc::new(Mutex::new(true));
   let r = Arc::clone(&running);
   
   let npc_socket = cli.npc_socket.clone();
   
   let handle = thread::spawn(move || {
       while *r.lock().unwrap() {
           if Path::new(&npc_socket).exists() {
               match fs::remove_file(&npc_socket) {
                   Ok(_) => println!("Removed existing socket file: {}", npc_socket),
                   Err(e) => println!("Failed to remove socket file: {}", e),
               }
           }
           
           let rt = tokio::runtime::Runtime::new().unwrap();
           
           rt.block_on(async {
               println!("Starting nockchain instance");
               
               sword::check_endian();
               crown::kernel::boot::init_default_tracing(&cli.crown_cli);
               let prover_hot_state = zkvm_jetpack::hot::produce_prover_hot_state();
               
               match nockchain::init_with_kernel(
                   Some(cli.clone()), 
                   kernels::dumb::KERNEL, 
                   prover_hot_state.as_slice()
               ).await {
                   Ok(nockapp) => {
                       println!("Nockchain initialized successfully");
                       match nockapp.run().await {
                           Ok(_) => println!("Nockchain stopped normally"),
                           Err(e) => println!("Nockchain error: {}", e),
                       }
                   },
                   Err(e) => println!("Failed to initialize nockchain: {}", e),
               }
           });
           
           println!("Nockchain process terminated, restarting in 3 seconds...");
           thread::sleep(Duration::from_secs(3));
       }
       
       let mut guard = r.lock().unwrap();
       *guard = false;
   });
   
   println!("Nockchain started. Press Enter to stop.");
   
   let mut buffer = String::new();
   io::stdin().read_line(&mut buffer)?;
   
   println!("Stopping nockchain...");
   {
       let mut guard = running.lock().unwrap();
       *guard = false;
   }
   
   handle.join().unwrap();
   
   println!("Exiting wrapper");
   Ok(())
}

fn parse_json_config(config_path: &str) -> Result<NockchainCli, Box<dyn Error>> {
   // read json
   let content = std::fs::read_to_string(config_path)?;
   let mut cli = NockchainCli::parse_from(Vec::<String>::new());
   
   for line in content.lines() {
       let line = line.trim();
       if line.starts_with("//") || line.is_empty() {
           continue;
       }
       
       if let Some(pos) = line.find(':') {
           let key = line[0..pos].trim().trim_matches('"');
           let mut value = line[pos+1..].trim().trim_matches(',');
           
           if value.starts_with('"') && value.ends_with('"') {
               value = &value[1..value.len()-1];
           }

           match key {
               "npc_socket" => {
                   if value != "null" && !value.is_empty() {
                       cli.npc_socket = value.to_string();
                   }
               },
               "mine" => {
                   if value != "null" {
                       cli.mine = value == "true";
                   }
               },
               "mining_pubkey" => {
                   if value != "null" && !value.is_empty() {
                       cli.mining_pubkey = Some(value.to_string());
                   }
               },
               "genesis_watcher" => {
                   if value != "null" {
                       cli.genesis_watcher = value == "true";
                   }
               },
               "genesis_leader" => {
                   if value != "null" {
                       cli.genesis_leader = value == "true";
                   }
               },
               "fakenet" => {
                   if value != "null" {
                       cli.fakenet = value == "true";
                   }
               },
               "genesis_message" => {
                   if value != "null" && !value.is_empty() {
                       cli.genesis_message = value.to_string();
                   }
               },
               "btc_node_url" => {
                   if value != "null" && !value.is_empty() {
                       cli.btc_node_url = value.to_string();
                   }
               },
               "btc_username" => {
                   if value != "null" && !value.is_empty() {
                       cli.btc_username = Some(value.to_string());
                   }
               },
               "btc_password" => {
                   if value != "null" && !value.is_empty() {
                       cli.btc_password = Some(value.to_string());
                   }
               },
               "btc_auth_cookie" => {
                   if value != "null" && !value.is_empty() {
                       cli.btc_auth_cookie = Some(value.to_string());
                   }
               },
               "no_default_peers" => {
                   if value != "null" {
                       cli.no_default_peers = value == "true";
                   }
               },
               "new_peer_id" => {
                   if value != "null" {
                       cli.new_peer_id = value == "true";
                   }
               },
               "max_established_incoming" => {
                   if value != "null" && !value.is_empty() {
                       if let Ok(n) = value.parse::<u32>() {
                           cli.max_established_incoming = Some(n);
                       }
                   }
               },
               "max_established_outgoing" => {
                   if value != "null" && !value.is_empty() {
                       if let Ok(n) = value.parse::<u32>() {
                           cli.max_established_outgoing = Some(n);
                       }
                   }
               },
               "peer" => {
                   if value.starts_with('[') && value.ends_with(']') {
                       let inner = &value[1..value.len()-1].trim();
                       if !inner.is_empty() {
                           let peer_values: Vec<String> = inner
                               .split(',')
                               .map(|s| s.trim().trim_matches('"').to_string())
                               .collect();
                           cli.peer = peer_values;
                       }
                   } else if value != "null" && !value.is_empty() {
                       cli.peer.push(value.to_string());
                   }
               },
               "bind" => {
                   if value.starts_with('[') && value.ends_with(']') {
                       let inner = &value[1..value.len()-1].trim();
                       if !inner.is_empty() {
                           let bind_values: Vec<String> = inner
                               .split(',')
                               .map(|s| s.trim().trim_matches('"').to_string())
                               .collect();
                           cli.bind = bind_values;
                       }
                   } else if value != "null" && !value.is_empty() {
                       cli.bind.push(value.to_string());
                   }
               },
               _ => {}
           }
       }
   }
   
   Ok(cli)
}

fn build_cli_string(cli: &NockchainCli) -> String {
   let mut param_map = HashMap::new();
   
   let default_npc_socket = "nockchain.sock";
   let default_mine = false;
   let default_genesis_watcher = false;
   let default_genesis_leader = false;
   let default_fakenet = false;
   let default_genesis_message = "Hail Zorp";
   let default_btc_node_url = "http://127.0.0.1:8332";
   let default_no_default_peers = false;
   let default_new_peer_id = false;
   
   param_map.insert("npc-socket", Box::new(move |c: &NockchainCli| -> Option<String> {
       if c.npc_socket != default_npc_socket {
           Some(format!("\"{}\"", c.npc_socket))
       } else {
           None
       }
   }) as Box<dyn Fn(&NockchainCli) -> Option<String>>);
   
   param_map.insert("genesis-message", Box::new(move |c: &NockchainCli| -> Option<String> {
       if c.genesis_message != default_genesis_message {
           Some(format!("\"{}\"", c.genesis_message))
       } else {
           None
       }
   }) as Box<dyn Fn(&NockchainCli) -> Option<String>>);
   
   param_map.insert("btc-node-url", Box::new(move |c: &NockchainCli| -> Option<String> {
       if c.btc_node_url != default_btc_node_url {
           Some(format!("\"{}\"", c.btc_node_url))
       } else {
           None
       }
   }) as Box<dyn Fn(&NockchainCli) -> Option<String>>);
   
   param_map.insert("mine", Box::new(move |c: &NockchainCli| -> Option<String> {
       if c.mine != default_mine {
           Some(String::new())
       } else {
           None
       }
   }) as Box<dyn Fn(&NockchainCli) -> Option<String>>);
   
   param_map.insert("genesis-watcher", Box::new(move |c: &NockchainCli| -> Option<String> {
       if c.genesis_watcher != default_genesis_watcher {
           Some(String::new())
       } else {
           None
       }
   }) as Box<dyn Fn(&NockchainCli) -> Option<String>>);
   
   param_map.insert("genesis-leader", Box::new(move |c: &NockchainCli| -> Option<String> {
       if c.genesis_leader != default_genesis_leader {
           Some(String::new())
       } else {
           None
       }
   }) as Box<dyn Fn(&NockchainCli) -> Option<String>>);
   
   param_map.insert("fakenet", Box::new(move |c: &NockchainCli| -> Option<String> {
       if c.fakenet != default_fakenet {
           Some(String::new())
       } else {
           None
       }
   }) as Box<dyn Fn(&NockchainCli) -> Option<String>>);
   
   param_map.insert("no-default-peers", Box::new(move |c: &NockchainCli| -> Option<String> {
       if c.no_default_peers != default_no_default_peers {
           Some(String::new())
       } else {
           None
       }
   }) as Box<dyn Fn(&NockchainCli) -> Option<String>>);
   
   param_map.insert("new-peer-id", Box::new(move |c: &NockchainCli| -> Option<String> {
       if c.new_peer_id != default_new_peer_id {
           Some(String::new())
       } else {
           None
       }
   }) as Box<dyn Fn(&NockchainCli) -> Option<String>>);
   
   param_map.insert("mining-pubkey", Box::new(|c: &NockchainCli| -> Option<String> {
       c.mining_pubkey.as_ref().map(|s| format!("\"{}\"", s))
   }) as Box<dyn Fn(&NockchainCli) -> Option<String>>);
   
   param_map.insert("btc-username", Box::new(|c: &NockchainCli| -> Option<String> {
       c.btc_username.as_ref().map(|s| format!("\"{}\"", s))
   }) as Box<dyn Fn(&NockchainCli) -> Option<String>>);
   
   param_map.insert("btc-password", Box::new(|c: &NockchainCli| -> Option<String> {
       c.btc_password.as_ref().map(|s| format!("\"{}\"", s))
   }) as Box<dyn Fn(&NockchainCli) -> Option<String>>);
   
   param_map.insert("btc-auth-cookie", Box::new(|c: &NockchainCli| -> Option<String> {
       c.btc_auth_cookie.as_ref().map(|s| format!("\"{}\"", s))
   }) as Box<dyn Fn(&NockchainCli) -> Option<String>>);
   
   param_map.insert("allowed-peers-path", Box::new(|c: &NockchainCli| -> Option<String> {
       c.allowed_peers_path.as_ref().map(|s| format!("\"{}\"", s))
   }) as Box<dyn Fn(&NockchainCli) -> Option<String>>);
   
   param_map.insert("max-established-incoming", Box::new(|c: &NockchainCli| -> Option<String> {
       c.max_established_incoming.map(|n| n.to_string())
   }) as Box<dyn Fn(&NockchainCli) -> Option<String>>);
   
   param_map.insert("max-established-outgoing", Box::new(|c: &NockchainCli| -> Option<String> {
       c.max_established_outgoing.map(|n| n.to_string())
   }) as Box<dyn Fn(&NockchainCli) -> Option<String>>);

   let mut parts = Vec::new();
   for (param, value_fn) in &param_map {
       if let Some(value) = value_fn(cli) {
           if value.is_empty() {
               parts.push(format!("--{}", param));
           } else {
               parts.push(format!("--{} {}", param, value));
           }
       }
   }
   
   for peer in &cli.peer {
       parts.push(format!("--peer \"{}\"", peer));
   }
   
   for bind in &cli.bind {
       parts.push(format!("--bind \"{}\"", bind));
   }
   
   parts.join(" ")
}