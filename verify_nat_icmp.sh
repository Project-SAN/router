#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROUTER_BIN="$REPO_DIR/target/debug/router"
ROUTER_CFG="$REPO_DIR/config/router.yaml"

cleanup_namespaces() {
  for ns in client upstream rtr; do
    sudo ip netns del "$ns" 2>/dev/null || true
  done
}

cleanup() {
  echo "[*] cleaning up background processes and namespaces..."

  if [[ -n "${UDP_SERVER_PID:-}" ]]; then
    sudo ip netns exec upstream kill "$UDP_SERVER_PID" 2>/dev/null || true
  fi
  if [[ -n "${TCPDUMP_PID:-}" ]]; then
    sudo ip netns exec upstream kill "$TCPDUMP_PID" 2>/dev/null || true
  fi
  if [[ -n "${ROUTER_PID:-}" ]]; then
    sudo ip netns exec rtr kill "$ROUTER_PID" 2>/dev/null || true
  fi
  if [[ -n "${CLIENT_NC_JOB:-}" ]]; then
    kill "$CLIENT_NC_JOB" 2>/dev/null || true
  fi

  cleanup_namespaces
  echo "[*] cleanup complete."
}
# trap cleanup EXIT

echo "[*] removing any previous namespaces..."
cleanup_namespaces

echo "[*] building router binary..."
cargo build --bin router

echo "[*] provisioning namespaces and veth pairs..."
sudo ip netns add rtr
sudo ip netns add client
sudo ip netns add upstream

sudo ip link add veth-lan type veth peer name veth-lan-rtr
sudo ip link add veth-wan type veth peer name veth-wan-rtr

sudo ip link set veth-lan netns client
sudo ip link set veth-lan-rtr netns rtr
sudo ip link set veth-wan netns upstream
sudo ip link set veth-wan-rtr netns rtr

sudo ip netns exec rtr ip link set lo up
sudo ip netns exec rtr ip link set veth-lan-rtr name rt-lan
sudo ip netns exec rtr ip link set veth-wan-rtr name rt-wan
sudo ip netns exec rtr ip link set rt-lan address aa:bb:cc:dd:ee:01
sudo ip netns exec rtr ip link set rt-wan address aa:bb:cc:dd:ee:02
sudo ip netns exec rtr ip addr add 192.168.10.1/24 dev rt-lan
sudo ip netns exec rtr ip addr add 203.0.113.2/30 dev rt-wan
sudo ip netns exec rtr ip link set rt-lan up
sudo ip netns exec rtr ip link set rt-wan up
sudo ip netns exec rtr sysctl -w net.ipv4.ip_forward=0 >/dev/null
sudo ip netns exec rtr iptables -F FORWARD
sudo ip netns exec rtr iptables -P FORWARD DROP

sudo ip netns exec client ip link set lo up
sudo ip netns exec client ip link set veth-lan up
sudo ip netns exec client ip addr add 192.168.10.10/24 dev veth-lan
sudo ip netns exec client ip route add default via 192.168.10.1

sudo ip netns exec upstream ip link set lo up
sudo ip netns exec upstream ip link set veth-wan up
sudo ip netns exec upstream ip addr add 203.0.113.1/30 dev veth-wan
sudo ip netns exec upstream ip route add 192.168.10.0/24 via 203.0.113.2

echo "[*] starting router inside namespace..."
sudo ip netns exec rtr bash -lc "nohup stdbuf -oL -eL '$ROUTER_BIN' --config '$ROUTER_CFG' > /tmp/router.log 2>&1 & echo \$! > /tmp/router.pid"
ROUTER_PID="$(sudo ip netns exec rtr cat /tmp/router.pid)"
sleep 2
echo "    router PID: $ROUTER_PID"

echo "[*] starting upstream tcpdump and UDP listener..."
sudo ip netns exec upstream bash -lc "rm -f /tmp/upstream_udp.log /tmp/upstream_server.log"
sudo ip netns exec upstream bash -lc "stdbuf -oL -eL tcpdump -nn -l -i veth-wan udp > /tmp/upstream_udp.log 2>&1 & echo \$! > /tmp/tcpdump.pid"
TCPDUMP_PID="$(sudo ip netns exec upstream cat /tmp/tcpdump.pid)"
sudo ip netns exec upstream bash -lc "nc -u -l -p 8080 > /tmp/upstream_server.log 2>&1 & echo \$! > /tmp/udpserver.pid"
UDP_SERVER_PID="$(sudo ip netns exec upstream cat /tmp/udpserver.pid)"
sleep 1

echo "[*] sending UDP payload from client (source port 40001)..."
sudo ip netns exec client bash -lc "echo 'hello from client' | nc -u -p 40001 -w5 203.0.113.1 8080" \
  > /tmp/client_nc.log 2>&1 &
CLIENT_NC_JOB=$!
sleep 2

echo "[*] extracting NAT-assigned port from tcpdump..."
NAT_PORT=""
for _ in {1..10}; do
NAT_PORT="$(sudo ip netns exec upstream bash -lc "python3 - <<'PY'
import re
for line in open('/tmp/upstream_udp.log', 'r'):
    m = re.search(r'203\\.0\\.113\\.2\\.(\\d+)\\s*>\\s*203\\.0\\.113\\.1\\.8080', line)
    if m:
        print(m.group(1))
        break
PY
")"
NAT_PORT="$(echo "$NAT_PORT" | tr -d '\n\r')"
if [[ -n "$NAT_PORT" ]]; then
  break
fi
sleep 1
done
if [[ -z "$NAT_PORT" ]]; then
  echo "!! failed to find NAT port in tcpdump output"
  echo "---- current tcpdump log ----"
  sudo ip netns exec upstream cat /tmp/upstream_udp.log || true
  echo "-----------------------------"
  echo "---- router log ----"
  sudo ip netns exec rtr cat /tmp/router.log || true
  echo "-----------------------------"
  exit 1
fi
echo "    observed NAT port: $NAT_PORT"

echo "[*] replying from upstream via NAT port..."
sudo ip netns exec upstream bash -lc "echo 'hello from upstream' | nc -u -w2 203.0.113.2 '$NAT_PORT'"

echo "[*] waiting for client netcat to finish..."
wait "$CLIENT_NC_JOB" || true
echo "---- client netcat output ----"
cat /tmp/client_nc.log || true
echo "--------------------------------"

echo "---- upstream server log ----"
sudo ip netns exec upstream cat /tmp/upstream_server.log || true
echo "--------------------------------"

echo "---- upstream tcpdump log ----"
sudo ip netns exec upstream cat /tmp/upstream_udp.log || true
echo "--------------------------------"

echo "[*] ICMP Time Exceeded test (TTL=1)..."
sudo ip netns exec client ping -c1 -t1 203.0.113.1 || true

echo "[*] ICMP Destination Unreachable test..."
sudo ip netns exec client ping -c1 198.18.0.1 || true

echo "[*] tests complete. Router log (first 20 lines):"
sudo ip netns exec rtr head -n 20 /tmp/router.log || true
echo "[*] full router log is at /tmp/router.log inside namespace 'rtr'."
