use clap::Parser;
use router::config::{self, CliOverrides};
use router::ip;
use router::runtime;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to the router configuration file (YAML)
    #[arg(short, long, value_name = "FILE", default_value = "config/router.yaml")]
    config: PathBuf,

    /// Override the operating mode defined in the configuration
    #[arg(short, long, value_name = "MODE")]
    mode: Option<String>,

    /// Override the debug/log level defined in the configuration
    #[arg(long, value_name = "LEVEL")]
    debug: Option<String>,
}

fn main() {
    let args = Args::parse();
    let overrides = CliOverrides {
        mode: args.mode.clone(),
        debug_level: args.debug.clone(),
    };

    let router_config =
        match config::init_router_config(&args.config, overrides) {
            Ok(cfg) => cfg,
            Err(err) => {
                eprintln!("failed to load configuration: {err}");
                std::process::exit(1);
            }
        };

    println!(
        "configuration loaded from {:?}: mode={}, debug_level={}, devices={}, routes={}",
        router_config.config_path,
        router_config.mode,
        router_config.debug_level,
        router_config.devices.len(),
        router_config.routes.len()
    );

    if let Err(err) = runtime::initialize_network_state(router_config) {
        eprintln!("failed to initialize network state: {err}");
        std::process::exit(1);
    }

    if let Ok(devices) = ip::get_net_devices() {
        for dev in devices {
            println!(
                "initialized device: {} addr={:08x} mask={:08x} nat_out={:08x}",
                dev.name, dev.ipdev.address, dev.ipdev.netmask, dev.ipdev.natdev.outside_ip_addr
            );
        }
    }

    match runtime::runtime_device_descriptors() {
        Ok(ifaces) => {
            for (name, fd) in ifaces {
                println!("raw socket ready on {} (fd={})", name, fd);
            }
        }
        Err(err) => {
            eprintln!("warning: unable to list raw sockets: {err}");
        }
    }

    if runtime::has_runtime_devices() {
        if let Err(err) = runtime::run_event_loop(&router_config.mode) {
            eprintln!("event loop terminated with error: {err}");
            std::process::exit(1);
        }
    } else {
        println!("no runtime devices initialised; exiting");
    }
}
