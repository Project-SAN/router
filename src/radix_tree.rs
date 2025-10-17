#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IpRouteEntry {
    pub nexthop: u32,
    pub valid: bool,
}

#[derive(Clone, Debug, Default)]
pub struct RadixTreeNode {
    depth: u8,
    node0: Option<Box<RadixTreeNode>>,
    node1: Option<Box<RadixTreeNode>>,
    data: Option<IpRouteEntry>,
}

impl RadixTreeNode {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn radix_tree_add(&mut self, prefix_ip: u32, prefix_len: u32, entry_data: IpRouteEntry) {
        let mut current = self;
        for i in 1..=prefix_len {
            let bit_is_one = ((prefix_ip >> (32 - i)) & 0x01) == 1;
            if bit_is_one {
                if current.node1.is_none() {
                    current.node1 = Some(Box::new(RadixTreeNode { depth: i as u8, ..Default::default() }));
                }
                current = current.node1.as_mut().unwrap();
            } else {
                if current.node0.is_none() {
                    current.node0 = Some(Box::new(RadixTreeNode { depth: i as u8, ..Default::default() }));
                }
                current = current.node0.as_mut().unwrap();
            }
        }
        current.data = Some(entry_data);
    }

    pub fn radix_tree_search(&self, ip: u32) -> IpRouteEntry {
        let mut current = self;
        let mut result: Option<IpRouteEntry> = None;

        for i in 1..=32 {
            if let Some(d) = &current.data {
                result = Some(d.clone());
            }
            let bit_is_one = ((ip >> (32 - i)) & 0x01) == 1;
            current = if bit_is_one {
                match current.node1.as_deref() {
                    Some(next) => next,
                    None => return result.unwrap_or_default(),
                }
            } else {
                match current.node0.as_deref() {
                    Some(next) => next,
                    None => return result.unwrap_or_default(),
                }
            };
        }
        result.unwrap_or_default()
    }
}