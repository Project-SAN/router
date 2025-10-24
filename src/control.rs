use crate::arp;
use crate::config::{Ipv4Network, RouterConfig};
use crate::ip;
use serde_yaml;
use std::io::{self, BufRead};
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::thread;

pub fn spawn_control_plane(initial_config: RouterConfig) {
    let state = Arc::new(Mutex::new(ControlState::new(initial_config)));
    let dispatcher = state.clone();

    thread::spawn(move || {
        eprintln!(
            "control plane ready. commands: show interfaces | show arp | show config | set interface <name> address <cidr> | write | discard | help | exit"
        );

        let stdin = io::stdin();
        for line in stdin.lock().lines() {
            let Ok(cmd) = line.map(|s| s.trim().to_string()) else {
                continue;
            };
            if cmd.is_empty() {
                continue;
            }
            if let Err(err) = handle_command(&cmd, &dispatcher) {
                println!("error: {}", err);
            }
        }
    });
}

fn handle_command(cmd: &str, state: &Arc<Mutex<ControlState>>) -> Result<(), String> {
    let mut parts = cmd.split_whitespace();
    let Some(first) = parts.next() else {
        return Ok(());
    };

    match first {
        "show" => {
            match parts.next() {
                Some("interfaces") => {
                    show_interfaces();
                    Ok(())
                }
                Some("arp") => {
                    show_arp();
                    Ok(())
                }
                Some("config") => show_config(state),
                other => Err(format!("unknown show target `{}`", other.unwrap_or(""))),
            }
        }
        "set" => handle_set(parts, state),
        "write" => write_config(state),
        "discard" => discard_changes(state),
        "help" => {
            print_help();
            Ok(())
        }
        "exit" | "quit" => {
            println!("Type Ctrl+C to stop the router");
            Ok(())
        }
        other => {
            Err(format!("unknown command `{}`", other))
        }
    }
}

fn show_interfaces() {
    match ip::get_net_devices() {
        Ok(devs) => {
            println!("interfaces:");
            for dev in devs {
                println!(
                    "  {name}: mac={mac} ip={ip} netmask={mask} broadcast={bcast}",
                    name = dev.name,
                    mac = format_mac(&dev.macaddr),
                    ip = ip::print_ip_addr(dev.ipdev.address),
                    mask = ip::print_ip_addr(dev.ipdev.netmask),
                    bcast = ip::print_ip_addr(dev.ipdev.broadcast),
                );
            }
        }
        Err(err) => println!("failed to fetch interfaces: {}", err),
    }
}

fn show_arp() {
    let entries = arp::snapshot_arp_table();
    if entries.is_empty() {
        println!("ARP table is empty");
        return;
    }
    println!("ARP table:");
    for entry in entries {
        println!(
            "  {ip} -> {mac} (via {iface})",
            ip = ip::print_ip_addr(entry.ip_addr),
            mac = format_mac(&entry.mac_addr),
            iface = entry.netdev.name
        );
    }
}

fn show_config(state: &Arc<Mutex<ControlState>>) -> Result<(), String> {
    let guard = state.lock().map_err(|_| "control state poisoned".to_string())?;
    let yaml = serde_yaml::to_string(&guard.working).map_err(|e| e.to_string())?;
    println!("{}", yaml);
    if guard.dirty {
        println!("(uncommitted changes present)");
    }
    Ok(())
}

fn handle_set<'a>(mut parts: impl Iterator<Item = &'a str>, state: &Arc<Mutex<ControlState>>) -> Result<(), String> {
    let Some(category) = parts.next() else {
        return Err("set what? try `set interface <name> address <cidr>`".into());
    };
    match category {
        "interface" => set_interface(parts, state),
        other => Err(format!("set {} not supported", other)),
    }
}

fn set_interface<'a>(mut parts: impl Iterator<Item = &'a str>, state: &Arc<Mutex<ControlState>>) -> Result<(), String> {
    let Some(name) = parts.next() else {
        return Err("missing interface name".into());
    };
    let Some(field) = parts.next() else {
        return Err("missing interface attribute".into());
    };

    match field {
        "address" => {
            let Some(cidr) = parts.next() else {
                return Err("missing CIDR".into());
            };
            let network = parse_cidr(cidr)?;
            let mut guard = state.lock().map_err(|_| "control state poisoned".to_string())?;
            let dev = guard
                .working
                .devices
                .iter_mut()
                .find(|d| d.name == name)
                .ok_or_else(|| format!("interface `{}` not found", name))?;
            dev.ipv4.clear();
            dev.ipv4.push(network);
            guard.dirty = true;
            println!("updated {} address to {}", name, cidr);
            Ok(())
        }
        other => Err(format!("interface field `{}` not supported", other)),
    }
}

fn write_config(state: &Arc<Mutex<ControlState>>) -> Result<(), String> {
    let mut guard = state.lock().map_err(|_| "control state poisoned".to_string())?;
    let yaml = serde_yaml::to_string(&guard.working).map_err(|e| e.to_string())?;
    std::fs::write(&guard.working.config_path, yaml).map_err(|e| e.to_string())?;
    guard.saved = guard.working.clone();
    guard.dirty = false;
    println!("configuration written to {:?}", guard.saved.config_path);
    Ok(())
}

fn discard_changes(state: &Arc<Mutex<ControlState>>) -> Result<(), String> {
    let mut guard = state.lock().map_err(|_| "control state poisoned".to_string())?;
    guard.working = guard.saved.clone();
    guard.dirty = false;
    println!("reverted to last saved configuration");
    Ok(())
}

fn parse_cidr(cidr: &str) -> Result<Ipv4Network, String> {
    let (addr_str, prefix_str) = cidr
        .split_once('/')
        .ok_or_else(|| format!("CIDR `{}` must contain '/'", cidr))?;
    let addr: Ipv4Addr = addr_str
        .parse()
        .map_err(|e| format!("invalid IPv4 `{}`: {}", addr_str, e))?;
    let prefix: u8 = prefix_str
        .parse()
        .map_err(|e| format!("invalid prefix `{}`: {}", prefix_str, e))?;
    Ok(Ipv4Network { address: addr, prefix })
}

fn print_help() {
    println!("available commands:");
    println!("  show interfaces");
    println!("  show arp");
    println!("  show config");
    println!("  set interface <name> address <cidr>");
    println!("  write");
    println!("  discard");
    println!("  exit (Ctrl+C to stop daemon)");
}

fn format_mac(mac: &[u8; 6]) -> String {
    mac.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(":")
}

struct ControlState {
    working: RouterConfig,
    saved: RouterConfig,
    dirty: bool,
}

impl ControlState {
    fn new(config: RouterConfig) -> Self {
        Self {
            working: config.clone(),
            saved: config,
            dirty: false,
        }
    }
}
