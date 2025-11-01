# Router Usage Guide

## Overview

This router binary provides a userspace implementation of an IPv4 router with
basic L2/L3 handling, ARP resolution, static routing, and IPv4 NAT
functionality. It is driven by a YAML configuration file and operates directly
on raw sockets, so root privileges are required when running on a real host or
inside Linux network namespaces.

## Supported Capabilities

- **Ethernet / ARP**
  - Receives frames on configured interfaces, maintains an ARP table, issues ARP
    requests, and responds to ARP queries for configured IP addresses.
- **IPv4 forwarding**
  - Parses IPv4 packets, decrements TTL, and forwards based on a static routing
    table. `ICMP Time Exceeded` is generated when TTL reaches zero, and `ICMP
    Destination Unreachable` is generated when no route matches.
- **NAT (IPv4)**
  - Stateful source NAT for UDP and TCP sessions initiated from inside
    interfaces.
  - Shared NAT state per configured outside IP, with automatic port allocation
    in the range `20000-59999`.
  - ICMP NAT is intentionally not supported (packets are left untouched).
- **ICMP handling**
  - Time Exceeded and Destination Unreachable responses as described above.
  - Other ICMP message types pass through without special processing.
- **Control plane helpers**
  - A simple control plane thread accepts commands (e.g. `show interfaces`,
    `show arp`, `show config`) on standard input for debugging.

## Command Line Interface

The `router` binary exposes a `clap`-based CLI (see `src/main.rs`):

```text
Usage: router [OPTIONS]

Options:
  -c, --config <FILE>  Path to the router configuration (default: config/router.yaml)
  -m, --mode <MODE>    Override the operating mode defined in the config
      --debug <LEVEL>  Override the debug/log level (info, debug, etc.)
  -h, --help           Print help information
  -V, --version        Print version information
```

## Configuration File

The configuration is parsed from YAML into the structures defined in
`src/config.rs`. A minimal example is available at `config/router.yaml`. The
top-level structure is:

```yaml
mode: router                # Optional (defaults to "router")
debug_level: info           # Optional (defaults to "info")

devices:                    # Required - list of logical interfaces
  - name: rt-lan
    enabled: true
    ignore: false
    mac: "aa:bb:cc:dd:ee:01"
    ipv4:
      - "192.168.10.1/24"   # Primary IPv4 address with prefix length
    mtu: 1500
    nat:
      role: inside          # inside | outside
      outside_ip: null      # Optional override of outside IP

routes:                     # Optional static routes
  - destination: "0.0.0.0/0"
    next_hop: "203.0.113.1"
    interface: "rt-wan"
    metric: 10
```

### Device fields

| Field    | Description |
|----------|-------------|
| `name`   | Linux interface name (must exist when router starts). |
| `enabled`, `ignore` | Allow disabling interfaces without removing them from config. |
| `mac`    | Optional MAC override; defaults to zeros if omitted. |
| `ipv4`   | One or more CIDR strings; the first entry is treated as primary. |
| `nat`    | Optional NAT configuration (see below). |

### NAT roles

- `inside`: Packets originating from this interface are eligible for NAT.
  - `outside_ip` should reference the primary address of a corresponding
    outside device. If omitted, the router attempts to infer it from any
    configured outside interface.
- `outside`: Holds the public/outside address. Packets arriving on outside
  interfaces are checked against the shared NAT table for reverse translations.

### Routes

Each entry maps to `RouteConfig` in `src/config.rs` and results in a radix-tree
entry inside `ip::RouteTable`. If `next_hop` is omitted, the route is treated as
directly connected.

## Running the Router

1. Build the binary: `cargo build --bin router`
2. Run with elevated privileges (needed for raw sockets). Example using network
   namespaces:

   ```bash
   sudo ip netns exec rtr \
     /path/to/router/target/debug/router --config /path/to/config/router.yaml
   ```

3. Check logs:
   - Standard output includes initialization details, interface registration,
     and NAT events.
   - Additional debug statements (`ethernet_output`, `transmit_frame`) show raw
     frame transmission when running the debugging build.

## Testing and Verification

### Unit Tests

Run quick unit tests (no privileges required):

```bash
cargo test
```

### Integration Test with Network Namespaces

The end-to-end NAT and ICMP workflow is exercised in `tests/netns.rs`. This test
creates three namespaces (`client`, `rtr`, `upstream`), wires them together with
veth pairs, and verifies:

- UDP flow from the client is NATed and observed by tcpdump.
- Upstream replies reach the client via the translated port.
- TTL expiry yields `ICMP Time Exceeded`.
- Missing route returns `ICMP Destination Unreachable`.

To run:

```bash
RUN_NETNS_TESTS=1 cargo test --test netns
```

The test invokes `sudo` internally, so it prompts for the password. It also
allows the TTL and unreachable pings to fail internally while keeping the test
passing.

### Manual verification script

`verify_nat_icmp.sh` reproduces the integration test scenario with more verbose
logging. Run it as your regular user account (the script invokes `sudo` for the
commands that require root privileges, and therefore prompts for your password
when needed):

```bash
bash verify_nat_icmp.sh
```

It outputs tcpdump captures, netcat logs, and ICMP results for inspection, then
cleans up namespaces.

## Limitations

- Operating in userspace requires raw socket access; performance is limited
  compared to kernel-space routers.
- NAT only translates UDP and TCP. ICMP NAT is not implemented.
- Configuration is static; no dynamic routing protocols are supported.
- Ethernet frame sizes below 60 bytes are padded automatically.

## Troubleshooting Tips

- Ensure the router process is running inside the correct namespace and has
  permission to create raw sockets (`CAP_NET_RAW`).
- If the integration test cannot run due to `sudo` restrictions, adjust the
  environment to allow `sudo` commands inside the test (e.g. disable
  `no_new_privs`).
- Logs reside in `/tmp/router.log` inside the router namespace when launched by
  the tests or verification script.

## Repository Structure Highlights

- `src/`: Core implementation (ARP, IP, NAT, runtime, control plane).
- `config/`: Example configuration files.
- `tests/netns.rs`: Integration test orchestrating Linux namespaces.
- `verify_nat_icmp.sh`: Shell script variant of the integration test.

Use this document as a starting point for deploying or extending the router in
custom lab environments.
