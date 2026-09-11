//! Election Parameters (tag 5) and Election Parameters v2 (tag 24).
//!
//! AWDL has no configured master. Every node advertises a **metric** and the address of
//! whoever it currently believes is master, and the cluster converges on the strongest
//! claim. There is no handshake and no acknowledgement: a node simply starts naming a
//! different master, and its neighbours follow or do not.
//!
//! Both tags are present in every frame observed — a device advertises v1 and v2
//! simultaneously, presumably so older peers can still follow it. They do not carry the
//! same fields, and v2 is not merely v1 with more bits, so both are decoded.

use crate::le;

/// Election Parameters (tag 5). The original form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElectionParams {
    /// Non-zero means a private election, which appends two more fields.
    pub flags: u8,
    pub id: u16,
    /// Hops to the master. 0 means "I am the master".
    pub distance: u8,
    /// The node this one is following.
    pub master: [u8; 6],
    /// The master's metric, as this node understands it.
    pub master_metric: u32,
    /// This node's own metric — its claim to the job.
    pub self_metric: u32,
    /// Present only in a private election.
    pub private_master: Option<[u8; 6]>,
}

impl ElectionParams {
    pub const MIN_LEN: usize = 19;

    pub fn parse(v: &[u8]) -> Option<ElectionParams> {
        if v.len() < Self::MIN_LEN {
            return None;
        }
        let flags = le::u8(v, 0)?;
        Some(ElectionParams {
            flags,
            id: le::u16(v, 1)?,
            distance: le::u8(v, 3)?,
            // v[4] is unnamed upstream and left undecoded rather than guessed at.
            master: v.get(5..11)?.try_into().ok()?,
            master_metric: le::u32(v, 11)?,
            self_metric: le::u32(v, 15)?,
            // A private election appends two unknown bytes then a second address.
            private_master: if flags != 0 {
                v.get(21..27).and_then(|b| b.try_into().ok())
            } else {
                None
            },
        })
    }

    /// Whether this node is claiming the job rather than following someone.
    pub fn claims_mastership(&self) -> bool {
        self.distance == 0
    }
}

/// Election Parameters v2 (tag 24).
///
/// Carries counters v1 has no room for. `master_counter` and `self_counter` are the
/// interesting pair: an election is decided on (counter, metric, address) in that
/// order, so a node with a higher counter wins regardless of metric — which is what
/// stops a cluster oscillating between two nodes with similar metrics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElectionParamsV2 {
    pub master: [u8; 6],
    /// A second address whose role is not documented. Observed equal to the sender's
    /// own address in every frame checked, but that is an observation and not a rule.
    pub other: [u8; 6],
    pub master_counter: u32,
    pub distance: u32,
    pub master_metric: u32,
    pub self_metric: u32,
    pub self_counter: u32,
}

impl ElectionParamsV2 {
    pub const MIN_LEN: usize = 40;

    pub fn parse(v: &[u8]) -> Option<ElectionParamsV2> {
        if v.len() < Self::MIN_LEN {
            return None;
        }
        Some(ElectionParamsV2 {
            master: v.get(0..6)?.try_into().ok()?,
            other: v.get(6..12)?.try_into().ok()?,
            master_counter: le::u32(v, 12)?,
            distance: le::u32(v, 16)?,
            master_metric: le::u32(v, 20)?,
            self_metric: le::u32(v, 24)?,
            // v[28..32] unknown, v[32..36] reserved upstream.
            self_counter: le::u32(v, 36)?,
        })
    }

    pub fn claims_mastership(&self) -> bool {
        self.distance == 0
    }

    /// Would this node's claim beat `other`'s?
    ///
    /// Ordering is (counter, metric, address) — counter first, which is the part that
    /// matters: a node that has simply been master for longer wins even against a
    /// better metric, and that is what keeps a cluster from flapping between two
    /// similar candidates.
    ///
    /// Derived from the field layout and from the paper, **not yet confirmed against a
    /// contested election in a capture.** Treat as a hypothesis until it is.
    pub fn beats(&self, other: &ElectionParamsV2, self_addr: [u8; 6], other_addr: [u8; 6]) -> bool {
        (self.self_counter, self.self_metric, self_addr)
            > (other.self_counter, other.self_metric, other_addr)
    }
}
