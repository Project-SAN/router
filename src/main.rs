use std::fs;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use clap::{value_parser, Args as ClapArgs, Parser, Subcommand, ValueEnum};
use hex::FromHex;
use hornet::policy::client::{HttpProofService, ProofRequest, ProofService};
use hornet::policy::{decode_metadata_tlv, PolicyCapsule, PolicyMetadata, PolicyRegistry};
use hornet::time::TimeProvider;
use hornet::types::Error as HornetError;
use router::nat::{nat_exec, NatDevice, NatDirectionType, NatPacketHeader, NatProtocolType};
use router::{
    ethernet,
    net::{self, NetDevice},
};

/// ルータ CLI（通常機能 + HORNET PoC）
#[derive(Parser, Debug)]
#[command(author, version, about = "Project-SAN Router CLI", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: TopCommand,
}

#[derive(Subcommand, Debug)]
enum TopCommand {
    /// 従来の L2/L3 ルータ操作
    Router(RouterArgs),
    /// HORNET ポリシー連携フロー
    Hornet(HornetArgs),
}

#[derive(ClapArgs, Debug)]
struct RouterArgs {
    #[command(subcommand)]
    action: RouterCommand,
}

#[derive(Subcommand, Debug)]
enum RouterCommand {
    /// 既存のチュートリアル用モード
    Legacy {
        #[arg(long, default_value = "ch1")]
        mode: String,
    },
    /// システム上のネットワークインターフェース一覧を表示
    Interfaces,
    /// NAT 変換の動作をシミュレーション
    Nat {
        #[arg(value_enum)]
        direction: CliNatDirection,
        #[arg(value_enum)]
        protocol: CliNatProtocol,
        #[arg(long, value_parser = value_parser!(Ipv4Addr))]
        local_ip: Ipv4Addr,
        #[arg(long)]
        local_port: Option<u16>,
        #[arg(long, value_parser = value_parser!(Ipv4Addr))]
        global_ip: Ipv4Addr,
        #[arg(long)]
        global_port: Option<u16>,
        #[arg(long, value_parser = value_parser!(Ipv4Addr))]
        remote_ip: Ipv4Addr,
        #[arg(long)]
        remote_port: Option<u16>,
    },
    /// 指定インターフェースで Ethernet フレームを受信して表示
    Sniff {
        #[arg(long)]
        iface: String,
        #[arg(long)]
        limit: Option<usize>,
    },
}

#[derive(ValueEnum, Clone, Debug)]
enum CliNatDirection {
    Incoming,
    Outgoing,
}

#[derive(ValueEnum, Clone, Debug)]
enum CliNatProtocol {
    Tcp,
    Udp,
}

#[derive(ClapArgs, Debug)]
struct HornetArgs {
    /// PA の証明 API エンドポイント (POST)
    #[arg(long, default_value = "http://127.0.0.1:8080/plonk/prove")]
    pa_endpoint: String,
    /// PolicyMetadata のエンコード済みバイト列（16進）
    #[arg(long, conflicts_with = "metadata_path")]
    metadata_hex: Option<String>,
    /// PolicyMetadata を格納したファイルパス（バイナリ or TLV or 16進文字列）
    #[arg(long, conflicts_with = "metadata_hex")]
    metadata_path: Option<PathBuf>,
    #[command(subcommand)]
    action: HornetCommand,
}

#[derive(Subcommand, Debug)]
enum HornetCommand {
    /// PA API を呼び出してカプセルを取得し、HORNET 形式ペイロードを生成
    Build {
        /// ユーザペイロード（UTF-8）
        message: String,
    },
    /// カプセル付ペイロードを検証し、残りのアプリケーションペイロードを表示
    Verify {
        /// 16 進表現されたペイロード (カプセル + 平文)
        packet_hex: String,
    },
    /// Build → Verify をまとめて実施してフローを確認
    RoundTrip {
        /// ユーザペイロード（UTF-8）
        message: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        TopCommand::Router(args) => run_router(args),
        TopCommand::Hornet(args) => run_hornet(args),
    }
}

fn run_router(args: RouterArgs) -> Result<()> {
    match args.action {
        RouterCommand::Legacy { mode } => run_legacy_mode(mode),
        RouterCommand::Interfaces => show_interfaces(),
        RouterCommand::Nat {
            direction,
            protocol,
            local_ip,
            local_port,
            global_ip,
            global_port,
            remote_ip,
            remote_port,
        } => run_nat_simulation(
            direction,
            protocol,
            local_ip,
            local_port,
            global_ip,
            global_port,
            remote_ip,
            remote_port,
        ),
        RouterCommand::Sniff { iface, limit } => run_sniff(iface, limit),
    }
}

fn run_hornet(args: HornetArgs) -> Result<()> {
    let metadata = load_metadata(&args)?;
    let mut router = HornetRouter::new(metadata, args.pa_endpoint)?;

    match args.action {
        HornetCommand::Build { message } => {
            let packet = router.build_packet(message.as_bytes())?;
            println!("{}", hex::encode(packet));
        }
        HornetCommand::Verify { packet_hex } => {
            let mut bytes = Vec::from_hex(packet_hex.trim())
                .map_err(|err| anyhow!("payload の 16 進デコードに失敗しました: {err}"))?;
            let (capsule, payload) = router.verify_packet(&mut bytes)?;
            println!(
                "Policy {} を検証しました。残ペイロード: {}",
                hex::encode(capsule.policy_id),
                String::from_utf8_lossy(&payload)
            );
        }
        HornetCommand::RoundTrip { message } => {
            let packet = router.build_packet(message.as_bytes())?;
            let mut bytes = packet.clone();
            let (_, plain) = router.verify_packet(&mut bytes)?;
            println!(
                "ラウンドトリップ成功。入力: \"{}\" → 出力: \"{}\"",
                message,
                String::from_utf8_lossy(&plain)
            );
        }
    }
    Ok(())
}

/// 簡易 HORNET ルータ。PoC 用にポリシーをハードコードし、検証のみを行う。
struct HornetRouter {
    registry: PolicyRegistry,
    policy: PolicyMetadata,
    proof_service: HttpProofService,
}

impl HornetRouter {
    fn new(policy: PolicyMetadata, endpoint: String) -> Result<Self> {
        let mut registry = PolicyRegistry::new();
        registry.register(policy.clone()).map_err(into_anyhow)?;
        Ok(Self {
            registry,
            policy,
            proof_service: HttpProofService::new(endpoint),
        })
    }

    /// ユーザペイロードにカプセルを先頭付与したバイト列を生成
    fn build_packet(&self, payload: &[u8]) -> Result<Vec<u8>> {
        let aux = build_aux_data();
        let request = ProofRequest {
            policy: &self.policy,
            payload,
            aux: aux.as_slice(),
            non_membership: None,
        };
        let capsule = self
            .proof_service
            .obtain_proof(&request)
            .map_err(into_anyhow)?;
        let mut packet = capsule.encode();
        packet.extend_from_slice(payload);
        Ok(packet)
    }

    /// カプセル付ペイロードを検証し、剥がしたカプセルと残りペイロードを返す
    fn verify_packet(&mut self, packet: &mut Vec<u8>) -> Result<(PolicyCapsule, Vec<u8>)> {
        let (capsule, consumed) = self.registry.enforce(packet).map_err(into_anyhow)?;
        let remaining = packet[consumed..].to_vec();
        Ok((capsule, remaining))
    }
}

/// HORNET の TimeProvider 実装
struct SystemClock;

impl TimeProvider for SystemClock {
    fn now_coarse(&self) -> u32 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32
    }
}

fn into_anyhow(err: HornetError) -> anyhow::Error {
    anyhow!("hornet error: {err:?}")
}

fn load_metadata(args: &HornetArgs) -> Result<PolicyMetadata> {
    if let Some(hex_str) = &args.metadata_hex {
        let bytes = Vec::from_hex(hex_str.trim())
            .map_err(|err| anyhow!("metadata_hex のデコードに失敗しました: {err}"))?;
        return parse_metadata(bytes.as_slice());
    }

    if let Some(path) = &args.metadata_path {
        let raw = fs::read(path).with_context(|| {
            format!("metadata_path の読み込みに失敗しました: {}", path.display())
        })?;
        return if looks_like_hex(&raw) {
            let filtered: String = raw
                .iter()
                .filter_map(|b| {
                    let c = *b as char;
                    if c.is_ascii_hexdigit() {
                        Some(c)
                    } else if c.is_ascii_whitespace() {
                        None
                    } else {
                        None
                    }
                })
                .collect();
            let bytes = Vec::from_hex(filtered)
                .map_err(|err| anyhow!("metadata_path の 16 進デコードに失敗しました: {err}"))?;
            parse_metadata(bytes.as_slice())
        } else {
            parse_metadata(raw.as_slice())
        };
    }

    Ok(default_metadata())
}

fn parse_metadata(data: &[u8]) -> Result<PolicyMetadata> {
    PolicyMetadata::parse(data)
        .or_else(|_| decode_metadata_tlv(data))
        .map_err(into_anyhow)
}

fn looks_like_hex(raw: &[u8]) -> bool {
    raw.iter()
        .all(|b| b.is_ascii_hexdigit() || b.is_ascii_whitespace())
}

fn build_aux_data() -> Vec<u8> {
    let clock = SystemClock;
    clock.now_coarse().to_be_bytes().to_vec()
}

/// metadata を指定しない場合の簡易デフォルト（検証はスキップされる）
fn default_metadata() -> PolicyMetadata {
    let clock = SystemClock;
    PolicyMetadata {
        policy_id: [0x11; 32],
        version: 1,
        expiry: clock.now_coarse() + 3600,
        flags: 0,
        verifier_blob: Vec::new(),
    }
}

fn run_legacy_mode(mode: String) -> Result<()> {
    match mode.as_str() {
        "ch1" => {
            println!("Running chapter 1 (legacy router demo)");
            Ok(())
        }
        "ch2" => {
            println!("Running chapter 2 (legacy router demo)");
            Ok(())
        }
        other => Err(anyhow!("未知の legacy モードです: {other}")),
    }
}

fn show_interfaces() -> Result<()> {
    let infos = net::list_interfaces()?;
    println!("利用可能なインターフェース:");
    for info in infos {
        let mac = info
            .mac
            .map(|m| ethernet::format_mac(&m))
            .unwrap_or_else(|| "(mac不明)".to_string());
        if info.addresses.is_empty() {
            println!("- {} {}", info.name, mac);
        } else {
            println!("- {} {} [{}]", info.name, mac, info.addresses.join(", "));
        }
    }
    Ok(())
}

fn run_nat_simulation(
    direction: CliNatDirection,
    protocol: CliNatProtocol,
    local_ip: Ipv4Addr,
    local_port: Option<u16>,
    global_ip: Ipv4Addr,
    global_port: Option<u16>,
    remote_ip: Ipv4Addr,
    remote_port: Option<u16>,
) -> Result<()> {
    let nat_proto = match protocol {
        CliNatProtocol::Tcp => NatProtocolType::Tcp,
        CliNatProtocol::Udp => NatProtocolType::Udp,
    };

    match direction {
        CliNatDirection::Outgoing => run_nat_outgoing(
            nat_proto,
            local_ip,
            local_port,
            global_ip,
            remote_ip,
            remote_port,
        ),
        CliNatDirection::Incoming => run_nat_incoming(
            nat_proto,
            local_ip,
            local_port,
            global_ip,
            global_port,
            remote_ip,
            remote_port,
        ),
    }
}

fn run_nat_outgoing(
    protocol: NatProtocolType,
    local_ip: Ipv4Addr,
    local_port: Option<u16>,
    global_ip: Ipv4Addr,
    remote_ip: Ipv4Addr,
    remote_port: Option<u16>,
) -> Result<()> {
    let local_port = local_port.ok_or_else(|| anyhow!("--local-port を指定してください"))?;
    let remote_port = remote_port.ok_or_else(|| anyhow!("--remote-port を指定してください"))?;

    let mut nat_device = NatDevice {
        outside_ip_addr: u32::from(global_ip),
        ..Default::default()
    };
    let mut ip_header = router::nat::IpHeader {
        header_checksum: 0,
        src_addr: u32::from(local_ip),
        dest_addr: u32::from(remote_ip),
    };
    let l4_payload = build_segment(protocol, local_port, remote_port);
    let packet = NatPacketHeader {
        packet: l4_payload.as_slice(),
    };
    let translated = nat_exec(
        &mut ip_header,
        packet,
        &mut nat_device,
        protocol,
        NatDirectionType::Outgoing,
    )
    .map_err(anyhow::Error::msg)?;

    let mapped = nat_device
        .nat_entry
        .get_nat_entry_by_local(protocol, u32::from(local_ip), local_port)
        .ok_or_else(|| anyhow!("NAT エントリが作成されませんでした"))?;

    println!(
        "NAT 登録: {}:{} -> {}:{}",
        format_ipv4(mapped.local_ip_addr),
        mapped.local_port,
        format_ipv4(mapped.global_ip_addr),
        mapped.global_port
    );
    println!(
        "変換後 IP: src={} dst={}",
        format_ipv4(ip_header.src_addr),
        format_ipv4(ip_header.dest_addr)
    );
    let (src_port, dst_port) = decode_ports(protocol, &translated)?;
    println!("変換後 L4: src_port={} dst_port={}", src_port, dst_port);
    println!("L4 ペイロード(hex): {}", hex::encode(&translated));
    Ok(())
}

fn run_nat_incoming(
    protocol: NatProtocolType,
    local_ip: Ipv4Addr,
    local_port: Option<u16>,
    global_ip: Ipv4Addr,
    global_port: Option<u16>,
    remote_ip: Ipv4Addr,
    remote_port: Option<u16>,
) -> Result<()> {
    let local_port = local_port.ok_or_else(|| anyhow!("--local-port を指定してください"))?;
    let global_port = global_port.ok_or_else(|| anyhow!("--global-port を指定してください"))?;
    let remote_port = remote_port.ok_or_else(|| anyhow!("--remote-port を指定してください"))?;

    let mut nat_device = NatDevice {
        outside_ip_addr: u32::from(global_ip),
        ..Default::default()
    };
    let entry = {
        let slot = nat_device
            .nat_entry
            .create_nat_entry(protocol)
            .ok_or_else(|| anyhow!("NAT テーブルが満杯です"))?;
        slot.global_ip_addr = u32::from(global_ip);
        slot.global_port = global_port;
        slot.local_ip_addr = u32::from(local_ip);
        slot.local_port = local_port;
        slot.clone()
    };

    let mut ip_header = router::nat::IpHeader {
        header_checksum: 0,
        src_addr: u32::from(remote_ip),
        dest_addr: u32::from(global_ip),
    };
    let l4_payload = build_segment(protocol, remote_port, global_port);
    let packet = NatPacketHeader {
        packet: l4_payload.as_slice(),
    };
    let translated = nat_exec(
        &mut ip_header,
        packet,
        &mut nat_device,
        protocol,
        NatDirectionType::Incoming,
    )
    .map_err(anyhow::Error::msg)?;

    println!(
        "既存 NAT エントリ: {}:{} <- {}:{}",
        format_ipv4(entry.local_ip_addr),
        entry.local_port,
        format_ipv4(entry.global_ip_addr),
        entry.global_port
    );
    println!(
        "変換後 IP: src={} dst={}",
        format_ipv4(ip_header.src_addr),
        format_ipv4(ip_header.dest_addr)
    );
    let (src_port, dst_port) = decode_ports(protocol, &translated)?;
    println!("変換後 L4: src_port={} dst_port={}", src_port, dst_port);
    println!("L4 ペイロード(hex): {}", hex::encode(&translated));
    Ok(())
}

fn build_segment(protocol: NatProtocolType, src_port: u16, dst_port: u16) -> Vec<u8> {
    match protocol {
        NatProtocolType::Udp => {
            let mut buf = vec![0u8; 8];
            buf[0..2].copy_from_slice(&src_port.to_be_bytes());
            buf[2..4].copy_from_slice(&dst_port.to_be_bytes());
            buf[4..6].copy_from_slice(&(8u16).to_be_bytes());
            buf
        }
        NatProtocolType::Tcp => {
            let mut buf = vec![0u8; 20];
            buf[0..2].copy_from_slice(&src_port.to_be_bytes());
            buf[2..4].copy_from_slice(&dst_port.to_be_bytes());
            buf[12] = 5 << 4; // data offset
            buf
        }
        NatProtocolType::Icmp => Vec::new(),
    }
}

fn decode_ports(protocol: NatProtocolType, payload: &[u8]) -> Result<(u16, u16)> {
    match protocol {
        NatProtocolType::Udp | NatProtocolType::Tcp => {
            if payload.len() < 4 {
                return Err(anyhow!("L4 ペイロードが短すぎます"));
            }
            let src = u16::from_be_bytes([payload[0], payload[1]]);
            let dst = u16::from_be_bytes([payload[2], payload[3]]);
            Ok((src, dst))
        }
        NatProtocolType::Icmp => Err(anyhow!("ICMP は未対応です")),
    }
}

fn format_ipv4(ip: u32) -> String {
    Ipv4Addr::from(ip).to_string()
}

fn run_sniff(iface: String, limit: Option<usize>) -> Result<()> {
    let mut device =
        NetDevice::open(&iface).with_context(|| format!("{} をオープンできません", iface))?;
    println!(
        "sniffing on {} (MAC {})",
        device.name,
        ethernet::format_mac(&device.mac)
    );
    let mut buffer = vec![0u8; 2048];
    let mut received = 0usize;
    loop {
        let n = device.recv(&mut buffer)?;
        if n == 0 {
            std::thread::sleep(Duration::from_millis(10));
            continue;
        }
        ethernet::process_frame(&mut device, &buffer[..n]);
        received += 1;
        if let Some(max) = limit {
            if received >= max {
                break;
            }
        }
    }
    Ok(())
}
