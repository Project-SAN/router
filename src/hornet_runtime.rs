use crate::config::HornetConfig;
use crate::hornet::time::TimeProvider;
use crate::hornet::{
    forward::Forward,
    node::ReplayCache,
    policy::{self, PolicyMetadata, PolicyRegistry},
    routing::{self, RouteElem},
    setup,
    setup::directory,
    types::{self, Ahdr, Chdr, Error as HornetError, PacketType, RoutingSegment},
    wire, StdClock,
};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Mutex, OnceLock};
use std::time::SystemTime;

#[derive(Debug)]
pub enum InitError {
    AlreadyInitialized,
    Config(String),
    Io(std::io::Error),
    Hornet(HornetError),
}

impl From<std::io::Error> for InitError {
    fn from(value: std::io::Error) -> Self {
        InitError::Io(value)
    }
}

impl From<HornetError> for InitError {
    fn from(value: HornetError) -> Self {
        InitError::Hornet(value)
    }
}

impl fmt::Display for InitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InitError::AlreadyInitialized => write!(f, "hornet runtime is already initialized"),
            InitError::Config(msg) => write!(f, "{msg}"),
            InitError::Io(err) => write!(f, "I/O error: {err}"),
            InitError::Hornet(err) => write!(f, "hornet error: {err:?}"),
        }
    }
}

impl std::error::Error for InitError {}

#[derive(Debug)]
pub enum ProcessError {
    Hornet(HornetError),
    Routing(String),
    Malformed(&'static str),
    Config(String),
}

impl fmt::Display for ProcessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProcessError::Hornet(err) => write!(f, "hornet error: {err:?}"),
            ProcessError::Routing(msg) => write!(f, "{msg}"),
            ProcessError::Malformed(msg) => write!(f, "{msg}"),
            ProcessError::Config(msg) => write!(f, "{msg}"),
        }
    }
}

impl From<HornetError> for ProcessError {
    fn from(value: HornetError) -> Self {
        ProcessError::Hornet(value)
    }
}

pub enum ProcessOutcome {
    NotHandled,
    Forward(ForwardPacket),
    Consumed,
}

pub struct ForwardPacket {
    pub next_addr: Ipv4Addr,
    pub next_port: u16,
    pub source_port: u16,
    pub wire_payload: Vec<u8>,
}

pub struct HornetRuntime {
    config: HornetConfig,
    listen_addr_v4: Option<Ipv4Addr>,
    listen_port: u16,
    _node_secret: [u8; 32],
    sv: types::Sv,
    replay: ReplayCache,
    registry: PolicyRegistry,
    last_directory_refresh: Option<SystemTime>,
    circuits: HashMap<CircuitKey, CircuitState>,
}

impl HornetRuntime {
    pub fn new(config: &HornetConfig) -> Result<Self, InitError> {
        let listen_port = config.listen_port;
        let listen_addr_v4 = match config.listen_addr {
            IpAddr::V4(addr) => {
                if addr.is_unspecified() {
                    None
                } else {
                    Some(addr)
                }
            }
            IpAddr::V6(_) => {
                return Err(InitError::Config(
                    "IPv6 addresses are not yet supported for hornet.listen_addr".into(),
                ))
            }
        };

        let node_secret_path = config
            .node_secret_path
            .as_ref()
            .ok_or_else(|| InitError::Config("hornet.node_secret_path must be set".into()))?;
        let secret_bytes = fs::read(node_secret_path)?;
        if secret_bytes.len() != 32 {
            return Err(InitError::Config(format!(
                "hornet node secret must be 32 bytes, got {}",
                secret_bytes.len()
            )));
        }
        let mut node_secret = [0u8; 32];
        node_secret.copy_from_slice(&secret_bytes);

        let sv_seed_hex = config
            .sv_seed_hex
            .as_ref()
            .ok_or_else(|| InitError::Config("hornet.sv_seed must be set".into()))?;
        let sv_bytes = hex_to_bytes(sv_seed_hex)?;
        if sv_bytes.len() != 16 {
            return Err(InitError::Config(format!(
                "hornet.sv_seed must encode 16 bytes, got {}",
                sv_bytes.len()
            )));
        }
        let mut sv_raw = [0u8; 16];
        sv_raw.copy_from_slice(&sv_bytes);
        let sv = types::Sv(sv_raw);

        let mut runtime = Self {
            config: config.clone(),
            listen_addr_v4,
            listen_port,
            _node_secret: node_secret,
            sv,
            replay: ReplayCache::new(),
            registry: PolicyRegistry::new(),
            last_directory_refresh: None,
            circuits: HashMap::new(),
        };
        runtime.reload_directory()?;
        Ok(runtime)
    }

    fn reload_directory(&mut self) -> Result<(), InitError> {
        let Some(path) = self.config.directory_file.as_deref() else {
            return Ok(());
        };

        let secret_hex = self.config.directory_secret_hex.as_ref().ok_or_else(|| {
            InitError::Config(
                "hornet.directory_secret is required when directory_file is set".into(),
            )
        })?;

        let secret = hex_to_bytes(secret_hex)?;
        let body = fs::read_to_string(path)?;
        let announcement = directory::from_signed_json(&body, &secret)?;
        for meta in announcement.policies() {
            self.registry.register(meta.clone())?;
        }
        self.last_directory_refresh = Some(SystemTime::now());
        Ok(())
    }

    pub fn handle_udp_packet(
        &mut self,
        src_ip: Ipv4Addr,
        src_port: u16,
        dst_ip: Ipv4Addr,
        dst_port: u16,
        payload: &[u8],
    ) -> Result<ProcessOutcome, ProcessError> {
        if !self.config.enabled {
            return Ok(ProcessOutcome::NotHandled);
        }
        if dst_port != self.listen_port {
            return Ok(ProcessOutcome::NotHandled);
        }
        if let Some(bind) = self.listen_addr_v4 {
            if dst_ip != bind {
                return Ok(ProcessOutcome::NotHandled);
            }
        }
        if payload.is_empty() {
            return Err(ProcessError::Malformed("empty HORNET payload"));
        }

        let (mut chdr, mut ahdr, mut body) = wire::decode(payload).map_err(ProcessError::Hornet)?;
        match chdr.typ {
            PacketType::Setup => {
                self.process_setup(&chdr, &ahdr, &body, src_ip, src_port, dst_ip, dst_port)
            }
            PacketType::Data => self.process_data(&mut chdr, &mut ahdr, &mut body),
        }
    }

    fn process_data(
        &mut self,
        chdr: &mut Chdr,
        ahdr: &mut Ahdr,
        payload: &mut Vec<u8>,
    ) -> Result<ProcessOutcome, ProcessError> {
        let clock = StdClock;
        let mut forwarder = RouterForward::new(self.listen_port);
        let mut node_ctx = crate::hornet::node::NodeCtx {
            sv: self.sv,
            now: &clock,
            forward: &mut forwarder,
            replay: &mut self.replay,
            policy: Some(&mut self.registry),
        };
        crate::hornet::node::forward::process_data(&mut node_ctx, chdr, ahdr, payload)
            .map_err(ProcessError::Hornet)?;
        match forwarder.into_packet()? {
            Some(packet) => Ok(ProcessOutcome::Forward(packet)),
            None => Ok(ProcessOutcome::Consumed),
        }
    }

    fn process_setup(
        &mut self,
        chdr: &Chdr,
        ahdr: &Ahdr,
        payload: &[u8],
        src_ip: Ipv4Addr,
        src_port: u16,
        dst_ip: Ipv4Addr,
        dst_port: u16,
    ) -> Result<ProcessOutcome, ProcessError> {
        let clock = StdClock;
        let exp = types::Exp(clock.now_coarse());
        let ahdr_res = crate::hornet::packet::ahdr::proc_ahdr(&self.sv, ahdr, exp)?;

        let mut setup_pkt = decode_setup_payload(chdr, payload)?;

        let mut tlvs = collect_metadata_tlvs(&ahdr.bytes);
        tlvs.extend(collect_metadata_tlvs(payload));

        let mut seen = HashSet::new();
        let mut registered_ids = Vec::new();
        for tlv in tlvs {
            let meta = policy::decode_metadata_tlv(&tlv).map_err(ProcessError::Hornet)?;
            if seen.insert(meta.policy_id) {
                if self.registry.get(&meta.policy_id).is_none() {
                    self.registry
                        .register(meta.clone())
                        .map_err(ProcessError::Hornet)?;
                }
                registered_ids.push(meta.policy_id);
            }
        }

        let si = setup::node_process_with_policy(
            &mut setup_pkt,
            &self._node_secret,
            &self.sv,
            &ahdr_res.r,
            Some(&mut self.registry),
        )
        .map_err(ProcessError::Hornet)?;

        let key = CircuitKey {
            src_ip,
            src_port,
            dst_ip,
            dst_port,
        };
        let exp = crate::hornet::packet::chdr::chdr_exp(chdr).map(|exp| exp.0);
        let now = SystemTime::now();
        self.circuits
            .entry(key)
            .and_modify(|state| {
                state.last_setup = now;
                state.exp = exp.or(state.exp);
                for id in &registered_ids {
                    if !state.policies.contains(id) {
                        state.policies.push(*id);
                    }
                }
                state.forward_keys.push(si);
            })
            .or_insert_with(|| CircuitState {
                last_setup: now,
                exp,
                policies: registered_ids.clone(),
                forward_keys: vec![si],
            });

        let mut forward_payload = encode_setup_payload(&setup_pkt)?;
        let mut forwarder = RouterForward::new(self.listen_port);
        forwarder
            .send(
                &ahdr_res.r,
                &setup_pkt.chdr,
                &ahdr_res.ahdr_next,
                &mut forward_payload,
            )
            .map_err(ProcessError::Hornet)?;
        match forwarder.into_packet()? {
            Some(packet) => Ok(ProcessOutcome::Forward(packet)),
            None => Ok(ProcessOutcome::Consumed),
        }
    }
}

static RUNTIME: OnceLock<Mutex<HornetRuntime>> = OnceLock::new();

pub fn init(config: &HornetConfig) -> Result<(), InitError> {
    if !config.enabled {
        return Ok(());
    }
    let runtime = HornetRuntime::new(config)?;
    RUNTIME
        .set(Mutex::new(runtime))
        .map_err(|_| InitError::AlreadyInitialized)
}

pub fn handle_udp_packet(
    src_ip: Ipv4Addr,
    src_port: u16,
    dst_ip: Ipv4Addr,
    dst_port: u16,
    payload: &[u8],
) -> Option<Result<ProcessOutcome, ProcessError>> {
    with_runtime(|rt| rt.handle_udp_packet(src_ip, src_port, dst_ip, dst_port, payload))
}

fn with_runtime<F, T>(f: F) -> Option<T>
where
    F: FnOnce(&mut HornetRuntime) -> T,
{
    let runtime = RUNTIME.get()?;
    let mut guard = runtime.lock().ok()?;
    Some(f(&mut guard))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct CircuitKey {
    src_ip: Ipv4Addr,
    src_port: u16,
    dst_ip: Ipv4Addr,
    dst_port: u16,
}

struct CircuitState {
    last_setup: SystemTime,
    exp: Option<u32>,
    policies: Vec<[u8; 32]>,
    forward_keys: Vec<types::Si>,
}

fn collect_metadata_tlvs(buf: &[u8]) -> Vec<Vec<u8>> {
    const MIN_METADATA_LEN: usize = 32 + 2 + 4 + 2 + 4;
    let mut out = Vec::new();
    let mut idx = 0usize;
    while idx + 3 <= buf.len() {
        if buf[idx] == policy::POLICY_METADATA_TLV {
            let len = u16::from_be_bytes([buf[idx + 1], buf[idx + 2]]) as usize;
            let total = 3 + len;
            if len >= MIN_METADATA_LEN && idx + total <= buf.len() {
                let candidate = &buf[idx..idx + total];
                if PolicyMetadata::parse(&candidate[3..]).is_ok() {
                    out.push(candidate.to_vec());
                    idx += total;
                    continue;
                }
            }
        }
        idx += 1;
    }
    out
}

pub fn decode_setup_payload(chdr: &Chdr, body: &[u8]) -> Result<setup::SetupPacket, ProcessError> {
    const ALPHA_LEN: usize = crate::hornet::sphinx::GROUP_LEN;
    const GAMMA_LEN: usize = crate::hornet::sphinx::MU_LEN;
    const HEADER_FIXED: usize = ALPHA_LEN + GAMMA_LEN + 2 + 2 + 2 + 2 + 2;
    if body.len() < HEADER_FIXED {
        return Err(ProcessError::Malformed("setup payload too short"));
    }
    let mut idx = 0usize;
    let mut alpha = [0u8; ALPHA_LEN];
    alpha.copy_from_slice(&body[idx..idx + ALPHA_LEN]);
    idx += ALPHA_LEN;

    let mut gamma = [0u8; GAMMA_LEN];
    gamma.copy_from_slice(&body[idx..idx + GAMMA_LEN]);
    idx += GAMMA_LEN;

    let rmax = read_be_u16(&body[idx..idx + 2]) as usize;
    idx += 2;
    let hops = read_be_u16(&body[idx..idx + 2]) as usize;
    idx += 2;
    let stage = read_be_u16(&body[idx..idx + 2]) as usize;
    idx += 2;

    let beta_len = read_be_u16(&body[idx..idx + 2]) as usize;
    idx += 2;
    if idx + beta_len > body.len() {
        return Err(ProcessError::Malformed("setup beta truncated"));
    }
    let beta = body[idx..idx + beta_len].to_vec();
    idx += beta_len;

    if idx + 2 > body.len() {
        return Err(ProcessError::Malformed("setup payload length missing"));
    }
    let payload_len = read_be_u16(&body[idx..idx + 2]) as usize;
    idx += 2;
    if idx + payload_len > body.len() {
        return Err(ProcessError::Malformed("setup payload truncated"));
    }
    let payload_bytes = body[idx..idx + payload_len].to_vec();

    if payload_len != rmax.saturating_mul(types::C_BLOCK) {
        return Err(ProcessError::Malformed("setup payload length mismatch"));
    }

    let header = crate::hornet::sphinx::Header {
        alpha,
        beta,
        gamma,
        rmax,
        hops,
        stage,
    };

    let payload = crate::hornet::packet::payload::Payload {
        bytes: payload_bytes,
        rmax,
    };

    Ok(setup::SetupPacket {
        chdr: Chdr {
            typ: chdr.typ,
            hops: chdr.hops,
            specific: chdr.specific,
        },
        shdr: header,
        payload,
        rmax,
        tlvs: Vec::new(),
    })
}

pub fn encode_setup_payload(pkt: &setup::SetupPacket) -> Result<Vec<u8>, ProcessError> {
    const ALPHA_LEN: usize = crate::hornet::sphinx::GROUP_LEN;
    const GAMMA_LEN: usize = crate::hornet::sphinx::MU_LEN;

    let rmax_u16 =
        u16::try_from(pkt.shdr.rmax).map_err(|_| ProcessError::Malformed("rmax too large"))?;
    let hops_u16 =
        u16::try_from(pkt.shdr.hops).map_err(|_| ProcessError::Malformed("hops too large"))?;
    let stage_u16 =
        u16::try_from(pkt.shdr.stage).map_err(|_| ProcessError::Malformed("stage too large"))?;
    let beta_len_u16 = u16::try_from(pkt.shdr.beta.len())
        .map_err(|_| ProcessError::Malformed("beta too large"))?;
    let payload_len_u16 = u16::try_from(pkt.payload.bytes.len())
        .map_err(|_| ProcessError::Malformed("payload too large"))?;

    let mut out = Vec::with_capacity(
        ALPHA_LEN + GAMMA_LEN + 10 + pkt.shdr.beta.len() + pkt.payload.bytes.len(),
    );
    out.extend_from_slice(&pkt.shdr.alpha);
    out.extend_from_slice(&pkt.shdr.gamma);
    out.extend_from_slice(&rmax_u16.to_be_bytes());
    out.extend_from_slice(&hops_u16.to_be_bytes());
    out.extend_from_slice(&stage_u16.to_be_bytes());
    out.extend_from_slice(&beta_len_u16.to_be_bytes());
    out.extend_from_slice(&pkt.shdr.beta);
    out.extend_from_slice(&payload_len_u16.to_be_bytes());
    out.extend_from_slice(&pkt.payload.bytes);
    Ok(out)
}

fn read_be_u16(buf: &[u8]) -> u16 {
    u16::from_be_bytes([buf[0], buf[1]])
}

struct RouterForward {
    source_port: u16,
    packet: Result<Option<ForwardPacket>, ProcessError>,
}

impl RouterForward {
    fn new(source_port: u16) -> Self {
        Self {
            source_port,
            packet: Ok(None),
        }
    }

    fn into_packet(self) -> Result<Option<ForwardPacket>, ProcessError> {
        self.packet
    }
}

impl Forward for RouterForward {
    fn send(
        &mut self,
        rseg: &RoutingSegment,
        chdr: &Chdr,
        ahdr: &Ahdr,
        payload: &mut Vec<u8>,
    ) -> types::Result<()> {
        if !self
            .packet
            .as_ref()
            .map(|opt| opt.is_none())
            .unwrap_or(false)
        {
            return Err(types::Error::NotImplemented);
        }
        let elems = routing::elems_from_segment(rseg)?;
        let next = elems
            .iter()
            .find_map(|elem| match elem {
                RouteElem::NextHop {
                    addr: routing::IpAddr::V4(ip),
                    port,
                } => Some((Ipv4Addr::from(*ip), *port)),
                _ => None,
            })
            .ok_or(types::Error::NotImplemented)?;

        let wire_payload = wire::encode(chdr, ahdr, payload);
        self.packet = Ok(Some(ForwardPacket {
            next_addr: next.0,
            next_port: next.1,
            source_port: self.source_port,
            wire_payload,
        }));
        Ok(())
    }
}

fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, InitError> {
    let trimmed = hex.trim();
    if trimmed.len() % 2 != 0 {
        return Err(InitError::Config(format!(
            "hex string `{}` must have even length",
            trimmed
        )));
    }
    let mut out = Vec::with_capacity(trimmed.len() / 2);
    let mut chars = trimmed.chars();
    while let Some(high) = chars.next() {
        let Some(low) = chars.next() else {
            return Err(InitError::Config(
                "hex string length mismatch while decoding".into(),
            ));
        };
        let byte = (hex_digit(high)? << 4) | hex_digit(low)?;
        out.push(byte);
    }
    Ok(out)
}

fn hex_digit(c: char) -> Result<u8, InitError> {
    match c {
        '0'..='9' => Ok((c as u8) - b'0'),
        'a'..='f' => Ok((c as u8) - b'a' + 10),
        'A'..='F' => Ok((c as u8) - b'A' + 10),
        _ => Err(InitError::Config(format!("invalid hex character `{}`", c))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hornet::policy::{self, PolicyMetadata};
    use crate::hornet::routing::{IpAddr, RouteElem};
    use crate::hornet::types::{Exp, RoutingSegment, Sv};
    use rand_core::{CryptoRng, RngCore};
    use tempfile::NamedTempFile;

    struct XorShift64(u64);
    impl RngCore for XorShift64 {
        fn next_u32(&mut self) -> u32 {
            self.next_u64() as u32
        }
        fn next_u64(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            self.try_fill_bytes(dest).unwrap()
        }
        fn try_fill_bytes(
            &mut self,
            dest: &mut [u8],
        ) -> core::result::Result<(), rand_core::Error> {
            let mut n = 0;
            while n < dest.len() {
                let v = self.next_u64().to_le_bytes();
                let take = core::cmp::min(8, dest.len() - n);
                dest[n..n + take].copy_from_slice(&v[..take]);
                n += take;
            }
            Ok(())
        }
    }
    impl CryptoRng for XorShift64 {}

    fn to_hex(bytes: &[u8]) -> String {
        const TABLE: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            out.push(TABLE[(b >> 4) as usize] as char);
            out.push(TABLE[(b & 0x0f) as usize] as char);
        }
        out
    }

    fn make_config(temp_secret: &NamedTempFile, sv: [u8; 16], listen_port: u16) -> HornetConfig {
        HornetConfig {
            enabled: true,
            listen_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            listen_port,
            node_secret_path: Some(temp_secret.path().to_path_buf()),
            sv_seed_hex: Some(to_hex(&sv)),
            directory_file: None,
            directory_secret_hex: None,
            policy_cache_ttl: 60,
        }
    }

    fn write_secret(file: &NamedTempFile, secret: &[u8]) {
        use std::io::Write;
        let mut writer = file.as_file_mut();
        writer.write_all(secret).unwrap();
        writer.flush().unwrap();
    }

    fn mk_route_segment() -> RoutingSegment {
        let elem = RouteElem::NextHop {
            addr: IpAddr::V4([10, 0, 0, 1]),
            port: 30000,
        };
        routing::segment_from_elems(&[elem])
    }

    #[test]
    fn setup_payload_roundtrip() {
        let mut rng = XorShift64(0x1234_5678_90ab_cdef);
        let nodes = vec![gen_node(&mut rng, 0x9000)];
        let pubs: Vec<[u8; 32]> = nodes.iter().map(|n| n.1).collect();
        let exp = Exp(1_234_000);
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        seed[0] &= 248;
        seed[31] &= 127;
        seed[31] |= 64;

        let mut state = setup::source_init(&seed, &pubs, 1, exp, &mut rng);
        let meta = PolicyMetadata {
            policy_id: [0x11; 32],
            version: 1,
            expiry: exp.0,
            flags: 0,
            verifier_blob: vec![0xAA, 0xBB],
        };
        state.attach_policy_metadata(&meta);

        let encoded = encode_setup_payload(&state.packet).expect("encode");
        let decoded = decode_setup_payload(&state.packet.chdr, &encoded).expect("decode");
        assert_eq!(decoded.shdr.rmax, state.packet.shdr.rmax);
        assert_eq!(decoded.shdr.stage, state.packet.shdr.stage);
        assert_eq!(decoded.payload.bytes, state.packet.payload.bytes);
    }

    #[test]
    fn process_setup_forwards_and_updates_state() {
        let mut rng = XorShift64(0x2222_aaaa_3333_bbbb);
        let node = gen_node(&mut rng, 0x7000);
        let pubs = vec![node.1];
        let exp = Exp(2_345_678);
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        seed[0] &= 248;
        seed[31] &= 127;
        seed[31] |= 64;

        let mut state = setup::source_init(&seed, &pubs, 1, exp, &mut rng);
        let meta = PolicyMetadata {
            policy_id: [0x22; 32],
            version: 1,
            expiry: exp.0,
            flags: 0,
            verifier_blob: vec![0x10, 0x20],
        };
        state.attach_policy_metadata(&meta);

        let mut route_seg = mk_route_segment();
        let fs = crate::hornet::packet::core::create(
            &Sv(node.2 .0),
            &state.keys_f[0],
            &route_seg,
            &state.packet.chdr,
        )
        .expect("fs");
        let mut rng2 = XorShift64(0x5555_6666_7777_8888);
        let ahdr = crate::hornet::packet::ahdr::create_ahdr(
            &state.keys_f,
            &[fs],
            state.packet.rmax,
            &mut rng2,
        )
        .expect("ahdr");

        let payload = encode_setup_payload(&state.packet).expect("encode");
        let wire_buf = wire::encode(&state.packet.chdr, &ahdr, &payload);

        let temp_secret = NamedTempFile::new().expect("temp");
        write_secret(&temp_secret, &node.0);
        let cfg = make_config(&temp_secret, node.2 .0, 40000);
        let mut runtime = HornetRuntime::new(&cfg).expect("runtime");

        let outcome = runtime
            .handle_udp_packet(
                Ipv4Addr::new(192, 0, 2, 10),
                12345,
                Ipv4Addr::LOCALHOST,
                40000,
                &wire_buf,
            )
            .expect("process");
        match outcome {
            ProcessOutcome::Forward(pkt) => {
                assert_eq!(pkt.next_addr, Ipv4Addr::new(10, 0, 0, 1));
                assert_eq!(pkt.next_port, 30000);
                assert!(!pkt.wire_payload.is_empty());
            }
            other => panic!("unexpected outcome: {:?}", other),
        }
    }

    fn gen_node(rng: &mut XorShift64, seed: u64) -> ([u8; 32], [u8; 32], Sv) {
        let mut sk = [0u8; 32];
        rng.fill_bytes(&mut sk);
        sk[0] &= 248;
        sk[31] &= 127;
        sk[31] |= 64;
        let pk = x25519_dalek::x25519(sk, x25519_dalek::X25519_BASEPOINT_BYTES);
        let mut sv = [0u8; 16];
        let mut sv_rng = XorShift64(seed);
        sv_rng.fill_bytes(&mut sv);
        (sk, pk, Sv(sv))
    }
}
