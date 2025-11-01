use std::process::Command;
use std::thread::sleep;
use std::time::Duration;

macro_rules! run {
    ($($arg:tt)*) => {{
        let status = Command::new("bash")
            .arg("-lc")
            .arg(format!($($arg)*))
            .status()
            .expect("failed to spawn command");
        assert!(status.success(), "command failed: {}", stringify!($($arg)*));
    }};
}

fn needs_root() {
    if std::env::var("RUN_NETNS_TESTS").ok().as_deref() != Some("1") {
        eprintln!("SKIP: set RUN_NETNS_TESTS=1 to run namespace tests");
        std::process::exit(0);
    }
}

#[test]
fn nat_udp_roundtrip_and_icmp() {
    needs_root();

    // ensure clean slate
    run!("sudo ip netns del client 2>/dev/null || true");
    run!("sudo ip netns del upstream 2>/dev/null || true");
    run!("sudo ip netns del rtr 2>/dev/null || true");

    run!("cargo build --bin router");

    // create namespaces and links
    run!("sudo ip netns add rtr");
    run!("sudo ip netns add client");
    run!("sudo ip netns add upstream");

    run!("sudo ip link add veth-lan type veth peer name veth-lan-rtr");
    run!("sudo ip link add veth-wan type veth peer name veth-wan-rtr");

    run!("sudo ip link set veth-lan netns client");
    run!("sudo ip link set veth-lan-rtr netns rtr");
    run!("sudo ip link set veth-wan netns upstream");
    run!("sudo ip link set veth-wan-rtr netns rtr");

    // router namespace setup
    run!("sudo ip netns exec rtr ip link set lo up");
    run!("sudo ip netns exec rtr ip link set veth-lan-rtr name rt-lan");
    run!("sudo ip netns exec rtr ip link set veth-wan-rtr name rt-wan");
    run!("sudo ip netns exec rtr ip link set rt-lan address aa:bb:cc:dd:ee:01");
    run!("sudo ip netns exec rtr ip link set rt-wan address aa:bb:cc:dd:ee:02");
    run!("sudo ip netns exec rtr ip addr add 192.168.10.1/24 dev rt-lan");
    run!("sudo ip netns exec rtr ip addr add 203.0.113.2/30 dev rt-wan");
    run!("sudo ip netns exec rtr ip link set rt-lan up");
    run!("sudo ip netns exec rtr ip link set rt-wan up");
    run!("sudo ip netns exec rtr sysctl -w net.ipv4.ip_forward=0 > /dev/null");
    run!("sudo ip netns exec rtr iptables -F FORWARD");
    run!("sudo ip netns exec rtr iptables -P FORWARD DROP");

    // client namespace
    run!("sudo ip netns exec client ip link set lo up");
    run!("sudo ip netns exec client ip link set veth-lan up");
    run!("sudo ip netns exec client ip addr add 192.168.10.10/24 dev veth-lan");
    run!("sudo ip netns exec client ip route add default via 192.168.10.1");

    // upstream namespace
    run!("sudo ip netns exec upstream ip link set lo up");
    run!("sudo ip netns exec upstream ip link set veth-wan up");
    run!("sudo ip netns exec upstream ip addr add 203.0.113.1/30 dev veth-wan");
    run!("sudo ip netns exec upstream ip route add 192.168.10.0/24 via 203.0.113.2");

    // start router
    let router_bin = format!("{}/target/debug/router", env!("CARGO_MANIFEST_DIR"));
    let router_cfg = format!("{}/config/router.yaml", env!("CARGO_MANIFEST_DIR"));
    run!(
        "sudo ip netns exec rtr bash -lc \"nohup stdbuf -oL -eL '{}' --config '{}' > /tmp/router.log 2>&1 &\"",
        router_bin,
        router_cfg
    );

    sleep(Duration::from_secs(2));

    fn wait_for_pid_by_pgrep(ns: &str, pattern: &str) -> String {
        for _ in 0..20 {
            let output = Command::new("sudo")
                .args(["ip", "netns", "exec", ns, "pgrep", "-f", pattern])
                .output()
                .expect("failed to invoke pgrep");
            if output.status.success() {
                if let Some(pid) = String::from_utf8_lossy(&output.stdout)
                    .lines()
                    .map(str::trim)
                    .find(|line| !line.is_empty())
                {
                    return pid.to_string();
                }
            }
            sleep(Duration::from_millis(500));
        }

        let log_output = Command::new("sudo")
            .args(["ip", "netns", "exec", ns, "cat", "/tmp/router.log"])
            .output()
            .ok();
        let log_snippet = log_output
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
            .unwrap_or_else(|| "<unable to read log>".into());
        panic!(
            "failed to find process `{}` (log snippet: {})",
            pattern, log_snippet
        );
    }

    let router_pid = wait_for_pid_by_pgrep("rtr", &router_bin);

    // start tcpdump and UDP listener upstream
    run!("sudo ip netns exec upstream bash -lc \"tcpdump -nn -l -i veth-wan udp > /tmp/upstream_udp.log 2>&1 &\"");
    let tcpdump_pid = wait_for_pid_by_pgrep("upstream", "tcpdump");

    run!("sudo ip netns exec upstream bash -lc \"nc -u -l -p 8080 > /tmp/upstream_server.log 2>&1 &\"");
    let udpserver_pid = wait_for_pid_by_pgrep("upstream", "nc -u -l -p 8080");

    // send UDP from client
    run!("sudo ip netns exec client bash -lc \"echo 'hello from client' | nc -u -p 40001 -w3 203.0.113.1 8080\"");
    sleep(Duration::from_secs(2));

    // parse NAT port from tcpdump log
    let nat_port_output = Command::new("bash")
        .arg("-lc")
        .arg(
            "sudo ip netns exec upstream bash -lc \"python3 - <<'PY'\nimport re\ntry:\n    with open('/tmp/upstream_udp.log') as f:\n        for line in f:\n            m = re.search(r'203\\\\.0\\\\.113\\\\.2\\\\.(\\\\d+)\\\\s*>\\\\s*203\\\\.0\\\\.113\\\\.1\\\\.8080', line)\n            if m:\n                print(m.group(1))\n                break\nexcept FileNotFoundError:\n    pass\nPY\n\"",
        )
        .output()
        .expect("failed to parse NAT port");
    let nat_port = String::from_utf8_lossy(&nat_port_output.stdout)
        .trim()
        .to_string();
    assert!(!nat_port.is_empty(), "no NAT port observed in tcpdump log");

    // reply through NAT
    run!(
        "sudo ip netns exec upstream bash -lc \"echo 'hello from upstream' | nc -u -w2 203.0.113.2 {}\"",
        nat_port
    );

    // ICMP behaviour
    run!("sudo ip netns exec client ping -c1 -t1 203.0.113.1");
    run!("sudo ip netns exec client ping -c1 198.18.0.1");

    // teardown
    run!(
        "sudo ip netns exec upstream kill {} 2>/dev/null || true",
        tcpdump_pid
    );
    run!(
        "sudo ip netns exec upstream kill {} 2>/dev/null || true",
        udpserver_pid
    );
    run!(
        "sudo ip netns exec rtr kill {} 2>/dev/null || true",
        router_pid
    );

    run!("sudo ip netns del client");
    run!("sudo ip netns del upstream");
    run!("sudo ip netns del rtr");
}
