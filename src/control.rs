use crate::arp;
use crate::ip;
use std::io::{self, BufRead};
use std::thread;

pub fn spawn_control_plane() {
    thread::spawn(|| {
        eprintln!("control plane ready. commands: show interfaces | show arp | help | exit");
        let stdin = io::stdin();
        for line in stdin.lock().lines() {
            let Ok(cmd) = line.map(|s| s.trim().to_string()) else {
                continue;
            };
            if cmd.is_empty() {
                continue;
            }
            match cmd.as_str() {
                "show interfaces" => show_interfaces(),
                "show arp" => show_arp(),
                "help" => print_help(),
                "exit" | "quit" => {
                    println!("Type Ctrl+C to stop the router");
                }
                other => {
                    println!("unknown command `{}`", other);
                    print_help();
                }
            }
        }
    });
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
        Err(err) => {
            println!("failed to fetch interfaces: {}", err);
        }
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

fn print_help() {
    println!("available commands:");
    println!("  show interfaces");
    println!("  show arp");
    println!("  exit (Ctrl+C to actually stop)");
}

fn format_mac(mac: &[u8; 6]) -> String {
    mac.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(":")
}
