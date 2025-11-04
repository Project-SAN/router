use crate::config::HornetConfig;
use crate::hornet::time::TimeProvider;
use crate::hornet::{
    forward::Forward,
    node::ReplayCache,
    policy::{self, PolicyId, PolicyMetadata, PolicyRegistry},
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
    pub interface: Option<String>,
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
    policy_routes: HashMap<PolicyId, RouteOverride>,
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
            policy_routes: HashMap::new(),
        };
        runtime.reload_directory()?;
        runtime.apply_static_policy_routes();
        Ok(runtime)
    }

    fn reload_directory(&mut self) -> Result<(), InitError> {
        self.policy_routes.clear();
        let Some(path) = self.config.directory_file.as_deref() else {
            self.apply_static_policy_routes();
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
        self.apply_directory_routes(announcement.routes());
        self.last_directory_refresh = Some(SystemTime::now());
        self.apply_static_policy_routes();
        Ok(())
    }

    fn apply_directory_routes(&mut self, routes: &[directory::RouteAnnouncement]) {
        for route in routes {
            self.policy_routes.insert(
                route.policy_id,
                RouteOverride {
                    segment: route.segment.clone(),
                    interface: route.interface.clone(),
                },
            );
        }
    }

    fn apply_static_policy_routes(&mut self) {
        for route in &self.config.policy_routes {
            self.policy_routes.insert(
                route.policy_id,
                RouteOverride {
                    segment: route.segment.clone(),
                    interface: route.interface.clone(),
                },
            );
        }
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
        let key = CircuitKey {
            src_ip,
            src_port,
            dst_ip,
            dst_port,
        };
        match chdr.typ {
            PacketType::Setup => self.process_setup(&chdr, &ahdr, &body, key),
            PacketType::Data => self.process_data(&mut chdr, &mut ahdr, &mut body, key),
        }
    }

    fn process_data(
        &mut self,
        chdr: &mut Chdr,
        ahdr: &mut Ahdr,
        payload: &mut Vec<u8>,
        key: CircuitKey,
    ) -> Result<ProcessOutcome, ProcessError> {
        let clock = StdClock;
        let route_override = self
            .circuits
            .get(&key)
            .and_then(|state| state.route_override.clone());
        let mut forwarder = RouterForward::new(self.listen_port, route_override);
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
        key: CircuitKey,
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

        let exp = crate::hornet::packet::chdr::chdr_exp(chdr).map(|exp| exp.0);
        let now = SystemTime::now();
        let route_override = registered_ids
            .iter()
            .find_map(|id| self.policy_routes.get(id))
            .cloned();

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
                state.route_override = route_override.clone();
            })
            .or_insert_with(|| CircuitState {
                last_setup: now,
                exp,
                policies: registered_ids.clone(),
                forward_keys: vec![si],
                route_override: route_override.clone(),
            });

        let mut forward_payload = encode_setup_payload(&setup_pkt)?;
        let chosen_segment = route_override
            .as_ref()
            .map(|r| r.segment.clone())
            .unwrap_or_else(|| ahdr_res.r.clone());
        let mut forwarder = RouterForward::new(self.listen_port, route_override);
        forwarder
            .send(
                &chosen_segment,
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
    route_override: Option<RouteOverride>,
}

#[derive(Clone)]
struct RouteOverride {
    segment: RoutingSegment,
    interface: Option<String>,
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

    let mut tlvs = Vec::new();
    if idx + 2 <= body.len() {
        let tlv_count = read_be_u16(&body[idx..idx + 2]) as usize;
        idx += 2;
        for _ in 0..tlv_count {
            if idx + 2 > body.len() {
                break;
            }
            let tlv_len = read_be_u16(&body[idx..idx + 2]) as usize;
            idx += 2;
            let avail = body.len().saturating_sub(idx);
            let take = core::cmp::min(tlv_len, avail);
            tlvs.push(body[idx..idx + take].to_vec());
            idx += take;
        }
    }

    Ok(setup::SetupPacket {
        chdr: Chdr {
            typ: chdr.typ,
            hops: chdr.hops,
            specific: chdr.specific,
        },
        shdr: header,
        payload,
        rmax,
        tlvs,
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
        ALPHA_LEN
            + GAMMA_LEN
            + 10
            + pkt.shdr.beta.len()
            + pkt.payload.bytes.len()
            + 2
            + pkt.tlvs.iter().map(|tlv| 2 + tlv.len()).sum::<usize>(),
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
    let tlv_count = u16::try_from(pkt.tlvs.len())
        .map_err(|_| ProcessError::Malformed("too many TLVs in setup packet"))?;
    out.extend_from_slice(&tlv_count.to_be_bytes());
    for tlv in &pkt.tlvs {
        let len =
            u16::try_from(tlv.len()).map_err(|_| ProcessError::Malformed("setup TLV too large"))?;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(tlv);
    }
    Ok(out)
}

fn read_be_u16(buf: &[u8]) -> u16 {
    u16::from_be_bytes([buf[0], buf[1]])
}

struct RouterForward {
    source_port: u16,
    override_route: Option<RouteOverride>,
    packet: Result<Option<ForwardPacket>, ProcessError>,
}

impl RouterForward {
    fn new(source_port: u16, override_route: Option<RouteOverride>) -> Self {
        Self {
            source_port,
            override_route,
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
        let selected_segment = self
            .override_route
            .as_ref()
            .map(|route| route.segment.clone())
            .unwrap_or_else(|| rseg.clone());
        let elems = routing::elems_from_segment(&selected_segment)?;
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
            interface: self
                .override_route
                .as_ref()
                .and_then(|route| route.interface.clone()),
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
    use crate::config::HornetPolicyRoute;
    use crate::hornet::policy::{PolicyCapsule, PolicyMetadata};
    use crate::hornet::routing::{IpAddr as RoutingIpAddr, RouteElem};
    use crate::hornet::types::{Ahdr, Exp, Nonce, RoutingSegment, Sv};
    use hornet::source;
    use rand_core::{CryptoRng, RngCore};
    use std::net::IpAddr as StdIpAddr;
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
            listen_addr: StdIpAddr::V4(Ipv4Addr::UNSPECIFIED),
            listen_port,
            node_secret_path: Some(temp_secret.path().to_path_buf()),
            sv_seed_hex: Some(to_hex(&sv)),
            directory_file: None,
            directory_secret_hex: None,
            policy_cache_ttl: 60,
            policy_routes: Vec::new(),
        }
    }

    fn write_secret(file: &NamedTempFile, secret: &[u8]) {
        std::fs::write(file.path(), secret).expect("write secret");
    }

    fn mk_route_segment(ip: [u8; 4], port: u16) -> RoutingSegment {
        let elem = RouteElem::NextHop {
            addr: RoutingIpAddr::V4(ip),
            port,
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
        dbg!(state.packet.tlvs.iter().map(|tlv| tlv.len()).collect::<Vec<_>>());
        dbg!(state.packet.shdr.beta.len());
        dbg!(state.packet.payload.bytes.len());
        assert_eq!(state.packet.tlvs.len(), 1);

        let encoded = encode_setup_payload(&state.packet).expect("encode");
        dbg!(encoded.len());
        println!(
            "tail bytes: {:?}",
            &encoded[encoded.len().saturating_sub(64)..]
        );
        let decoded = decode_setup_payload(&state.packet.chdr, &encoded).expect("decode");
        assert_eq!(decoded.shdr.rmax, state.packet.shdr.rmax);
        assert_eq!(decoded.shdr.stage, state.packet.shdr.stage);
        assert_eq!(decoded.payload.bytes, state.packet.payload.bytes);
        assert_eq!(decoded.tlvs, state.packet.tlvs);
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

        let route_seg = mk_route_segment([10, 0, 0, 1], 30000);
        let fs =
            crate::hornet::packet::core::create(&Sv(node.2 .0), &state.keys_f[0], &route_seg, exp)
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
        let mut cfg = make_config(&temp_secret, node.2 .0, 40000);
        cfg.policy_routes.push(HornetPolicyRoute {
            policy_id: meta.policy_id,
            segment: route_seg.clone(),
            interface: Some("wan0".to_string()),
        });
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
                assert_eq!(pkt.interface.as_deref(), Some("wan0"));
            }
            ProcessOutcome::Consumed => {
                panic!("expected forward outcome for setup hop")
            }
            ProcessOutcome::NotHandled => {
                panic!("setup hop was not handled")
            }
        }
    }

    #[test]
    fn end_to_end_setup_and_data_multi_hop() {
        let mut rng = XorShift64(0x5151_a1a1_b2b2_c3c3);
        let nodes = vec![gen_node(&mut rng, 0x1000), gen_node(&mut rng, 0x2000)];
        let pubs: Vec<[u8; 32]> = nodes.iter().map(|n| n.1).collect();
        let exp = Exp(4_200_000);
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        seed[0] &= 248;
        seed[31] &= 127;
        seed[31] |= 64;

        let rmax = pubs.len();
        let mut state = setup::source_init(&seed, &pubs, rmax, exp, &mut rng);
        let meta = PolicyMetadata {
            policy_id: [0x33; 32],
            version: 1,
            expiry: exp.0,
            flags: 0,
            verifier_blob: Vec::new(),
        };
        state.attach_policy_metadata(&meta);

        let route_seg1 = mk_route_segment([10, 0, 0, 2], 45000);
        let route_seg2 = mk_route_segment([203, 0, 113, 9], 55000);

        let fs1 =
            crate::hornet::packet::core::create(&nodes[0].2, &state.keys_f[0], &route_seg1, exp)
                .expect("fs1");
        let fs2 =
            crate::hornet::packet::core::create(&nodes[1].2, &state.keys_f[1], &route_seg2, exp)
                .expect("fs2");
        let mut rng_hdr = XorShift64(0x3333_4444_5555_6666);
        let ahdr_setup = crate::hornet::packet::ahdr::create_ahdr(
            &state.keys_f,
            &[fs1.clone(), fs2.clone()],
            state.packet.rmax,
            &mut rng_hdr,
        )
        .expect("ahdr setup");

        let setup_payload = encode_setup_payload(&state.packet).expect("encode setup");
        let wire_setup = wire::encode(&state.packet.chdr, &ahdr_setup, &setup_payload);

        let temp_secret1 = NamedTempFile::new().expect("temp1");
        let temp_secret2 = NamedTempFile::new().expect("temp2");
        write_secret(&temp_secret1, &nodes[0].0);
        write_secret(&temp_secret2, &nodes[1].0);

        let mut cfg1 = make_config(&temp_secret1, nodes[0].2 .0, 40000);
        cfg1.policy_routes.push(HornetPolicyRoute {
            policy_id: meta.policy_id,
            segment: route_seg1.clone(),
            interface: Some("wan0".to_string()),
        });
        let mut cfg2 = make_config(&temp_secret2, nodes[1].2 .0, 45000);
        cfg2.policy_routes.push(HornetPolicyRoute {
            policy_id: meta.policy_id,
            segment: route_seg2.clone(),
            interface: None,
        });

        let mut runtime1 = HornetRuntime::new(&cfg1).expect("runtime1");
        let mut runtime2 = HornetRuntime::new(&cfg2).expect("runtime2");

        let forwarded_setup = runtime1
            .handle_udp_packet(
                Ipv4Addr::new(192, 0, 2, 1),
                41000,
                Ipv4Addr::LOCALHOST,
                40000,
                &wire_setup,
            )
            .expect("setup hop1");
        let wire_to_second = match forwarded_setup {
            ProcessOutcome::Forward(pkt) => {
                assert_eq!(pkt.next_addr, Ipv4Addr::new(10, 0, 0, 2));
                assert_eq!(pkt.next_port, 45000);
                assert_eq!(pkt.interface.as_deref(), Some("wan0"));
                pkt.wire_payload
            }
            ProcessOutcome::Consumed => panic!("expected forward outcome on hop1"),
            ProcessOutcome::NotHandled => panic!("setup hop1 not handled"),
        };
        let outcome_second = runtime2
            .handle_udp_packet(
                Ipv4Addr::new(10, 0, 0, 2),
                45000,
                Ipv4Addr::LOCALHOST,
                45000,
                &wire_to_second,
            )
            .expect("setup hop2");
        assert!(matches!(outcome_second, ProcessOutcome::Consumed));

        let mut nonce = Nonce([0u8; 16]);
        rng.fill_bytes(&mut nonce.0);
        let mut chdr_data = crate::hornet::packet::chdr::data_header(rmax as u8, nonce);
        let mut rng_data = XorShift64(0x7777_8888_9999_aaaa);
        let ahdr_data = crate::hornet::packet::ahdr::create_ahdr(
            &state.keys_f,
            &[fs1, fs2],
            state.packet.rmax,
            &mut rng_data,
        )
        .expect("ahdr data");

        let capsule = PolicyCapsule {
            policy_id: meta.policy_id,
            version: 1,
            proof: Vec::new(),
            commitment: Vec::new(),
            aux: Vec::new(),
        };
        let mut data_payload = capsule.encode();
        data_payload.extend_from_slice(b"payload");
        let mut iv0 = Nonce([0u8; 16]);
        rng.fill_bytes(&mut iv0.0);
        source::build(
            &mut chdr_data,
            &Ahdr { bytes: Vec::new() },
            &state.keys_f,
            &mut iv0,
            &mut data_payload,
        )
        .expect("encrypt data");
        let wire_data = wire::encode(&chdr_data, &ahdr_data, &data_payload);

        let forwarded_data = runtime1
            .handle_udp_packet(
                Ipv4Addr::new(192, 0, 2, 1),
                41000,
                Ipv4Addr::LOCALHOST,
                40000,
                &wire_data,
            )
            .expect("data hop1");
        let payload_second = match forwarded_data {
            ProcessOutcome::Forward(pkt) => {
                assert_eq!(pkt.next_addr, Ipv4Addr::new(10, 0, 0, 2));
                assert_eq!(pkt.next_port, 45000);
                pkt.wire_payload
            }
            ProcessOutcome::Consumed => panic!("expected forward outcome on data hop1"),
            ProcessOutcome::NotHandled => panic!("data hop1 not handled"),
        };
        let outcome_final = runtime2
            .handle_udp_packet(
                Ipv4Addr::new(10, 0, 0, 2),
                45000,
                Ipv4Addr::LOCALHOST,
                45000,
                &payload_second,
            )
            .expect("data hop2");
        assert!(matches!(outcome_final, ProcessOutcome::Consumed));
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
