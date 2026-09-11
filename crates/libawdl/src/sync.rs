//! Synchronization Parameters (tag 4) and Channel Sequence (tag 18).
//!
//! These two carry the answer to the question that decides whether an AWDL
//! implementation can run on hardware other than Apple's and Google's: **how tight does
//! the timing have to be, and what is the radio expected to do about it.**
//!
//! Everything here is decoded from the wire. Where a field's meaning is inferred rather
//! than measured, it says so.

use crate::le;

/// One Availability Window, in microseconds.
///
/// AWDL counts in Time Units: 1 TU = 1024 µs. The 2018 paper states an AW of 16 TU,
/// which is 16384 µs. **Do not hardcode that** — `aw_period` is on the wire precisely
/// because it is a parameter, and confirming it against real devices is the point.
pub const TU_US: u32 = 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncParams {
    /// Channel this frame went out on.
    pub tx_channel: u8,
    pub tx_counter: u16,
    /// Channel the current master is on.
    pub master_channel: u8,
    pub guard_time: u8,
    /// Availability Window period, in TU. The paper says 16.
    pub aw_period: u16,
    /// How often action frames are sent, in TU.
    pub action_frame_period: u16,
    pub flags: u16,
    pub aw_ext_length: u16,
    pub aw_common_length: u16,
    /// TU left in the current window — the field a joining node uses to work out where
    /// in the schedule it has arrived.
    pub aw_remaining: u16,
    pub ext_min: u8,
    pub ext_max_multicast: u8,
    pub ext_max_unicast: u8,
    pub ext_max_af: u8,
    /// The master this node is synchronised to. All-zero when it believes it is master.
    pub master: [u8; 6],
    pub presence_mode: u8,
    /// Monotonic AW counter. The clock the whole cluster agrees on.
    pub aw_counter: u16,
    /// Offset between this node's schedule and an access point's beacon.
    ///
    /// **This field is the clearest evidence that AWDL is designed to coexist with an
    /// infrastructure association rather than merely tolerate one** — there is no
    /// reason to carry an AP's beacon offset unless you intend to line up with it. It
    /// was 0 in all 278 frames of the first capture, which is consistent with those
    /// devices not currently time-sharing with an AP, and is a measurement to repeat
    /// against a device that definitely is.
    pub ap_beacon_alignment_delta: u16,
    /// A second channel sequence, carried INSIDE this tag.
    ///
    /// A frame therefore describes its schedule twice, in two different encodings: the
    /// one here has been observed as `Legacy`, while tag 18 carries `OpClass` for the
    /// same frame. They are not redundant — the Legacy list reports 151 where the
    /// OpClass list reports 149 or 153, which is the 40 MHz centre against the 20 MHz
    /// control channel. An implementation that reads only one of them gets a
    /// self-consistent and incomplete picture of where the peer actually listens.
    pub channel_sequence: Option<ChannelSequence>,
}

impl SyncParams {
    /// Smallest length that can hold every fixed field above. The embedded channel
    /// sequence follows and makes real tags considerably longer — 73 bytes observed.
    pub const MIN_LEN: usize = 33;

    pub fn parse(v: &[u8]) -> Option<SyncParams> {
        if v.len() < Self::MIN_LEN {
            return None;
        }
        Some(SyncParams {
            tx_channel: le::u8(v, 0)?,
            tx_counter: le::u16(v, 1)?,
            master_channel: le::u8(v, 3)?,
            guard_time: le::u8(v, 4)?,
            aw_period: le::u16(v, 5)?,
            action_frame_period: le::u16(v, 7)?,
            flags: le::u16(v, 9)?,
            aw_ext_length: le::u16(v, 11)?,
            aw_common_length: le::u16(v, 13)?,
            aw_remaining: le::u16(v, 15)?,
            ext_min: le::u8(v, 17)?,
            ext_max_multicast: le::u8(v, 18)?,
            ext_max_unicast: le::u8(v, 19)?,
            ext_max_af: le::u8(v, 20)?,
            master: v.get(21..27)?.try_into().ok()?,
            presence_mode: le::u8(v, 27)?,
            // v[28] is unnamed and has been observed non-zero; left undecoded rather
            // than given a speculative name.
            aw_counter: le::u16(v, 29)?,
            ap_beacon_alignment_delta: le::u16(v, 31)?,
            channel_sequence: v.get(33..).and_then(ChannelSequence::parse),
        })
    }

    /// Availability Window length in microseconds, from the wire rather than the paper.
    pub fn aw_period_us(&self) -> u32 {
        u32::from(self.aw_period) * TU_US
    }

    /// Whether this node claims to be the master of its own cluster.
    pub fn is_self_master(&self) -> bool {
        self.master == [0u8; 6]
    }
}

/// How the channel list is encoded. The list length depends on this, so guessing it
/// misreads every channel rather than failing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChanEncoding {
    /// One byte per slot: the channel number.
    ChannelNumber,
    /// Two bytes per slot: flags then channel number.
    Legacy,
    /// Two bytes per slot: channel number then operating class.
    OpClass,
    Unknown(u8),
}

impl ChanEncoding {
    fn from(v: u8) -> ChanEncoding {
        match v {
            0 => ChanEncoding::ChannelNumber,
            1 => ChanEncoding::Legacy,
            3 => ChanEncoding::OpClass,
            other => ChanEncoding::Unknown(other),
        }
    }

    fn stride(self) -> Option<usize> {
        match self {
            ChanEncoding::ChannelNumber => Some(1),
            ChanEncoding::Legacy | ChanEncoding::OpClass => Some(2),
            ChanEncoding::Unknown(_) => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelSequence {
    pub encoding: ChanEncoding,
    pub duplicate: u8,
    pub step_count: u8,
    /// 0xffff means "repeat current".
    pub fill_channel: u16,
    /// The slots, in order. This is the schedule: which channel the node is listening
    /// on during each Availability Window of the cycle.
    ///
    /// A slot of 0 means the node is not present at all during that window. In the
    /// first capture most slots were 0 — one device was on-channel for only 5 of its
    /// 16 windows — so "how many slots does it occupy" is a first-class question and
    /// not an edge case.
    pub channels: Vec<u8>,
    /// The second byte of each slot, kept raw.
    ///
    /// Its meaning depends on [`ChanEncoding`]: an operating class under `OpClass`, a
    /// flags byte carrying band/bandwidth/control-channel position under `Legacy`.
    /// Kept undecoded because the two need separate confirmation against captures, and
    /// a shared accessor would invite reading one as the other.
    pub qualifiers: Vec<u8>,
}

impl ChannelSequence {
    pub fn parse(v: &[u8]) -> Option<ChannelSequence> {
        // THE COUNT IS STORED MINUS ONE. A 16-slot sequence is written as 15, and
        // reading it literally silently drops the last slot -- which shows up as a
        // sequence that almost matches a peer's.
        let count = usize::from(le::u8(v, 0)?) + 1;
        let encoding = ChanEncoding::from(le::u8(v, 1)?);
        let duplicate = le::u8(v, 2)?;
        let step_count = le::u8(v, 3)?;
        let fill_channel = le::u16(v, 4)?;

        let stride = encoding.stride()?;
        let list = v.get(6..6 + count * stride)?;
        // Legacy puts flags first and the channel second; OpClass is the other way
        // round. Getting this backwards yields plausible-looking garbage rather than
        // an error, which is the worst kind of wrong.
        let (chan_idx, qual_idx) = match encoding {
            ChanEncoding::Legacy => (1, 0),
            _ => (0, 1),
        };
        let channels = list.chunks_exact(stride).map(|c| c[chan_idx]).collect();
        let qualifiers = list
            .chunks_exact(stride)
            .map(|c| if stride > 1 { c[qual_idx] } else { 0 })
            .collect();

        Some(ChannelSequence {
            encoding,
            duplicate,
            step_count,
            fill_channel,
            channels,
            qualifiers,
        })
    }

    /// Slots where the node is present at all. Channel 0 means absent.
    pub fn occupied_slots(&self) -> usize {
        self.channels.iter().filter(|c| **c != 0).count()
    }

    /// The distinct channels this node actually visits, excluding "absent".
    pub fn distinct(&self) -> Vec<u8> {
        let mut v: Vec<u8> = self.channels.iter().copied().filter(|c| *c != 0).collect();
        v.sort_unstable();
        v.dedup();
        v
    }

    /// How many slots sit on `channel`, out of the whole sequence.
    ///
    /// This is the overlap calculation: two nodes can only talk during windows where
    /// they are both on the same channel, so a node at 16/16 on 149 and a peer at 4/16
    /// on 149 have an upper bound of 4/16 = 25% of windows in common.
    pub fn slots_on(&self, channel: u8) -> usize {
        self.channels.iter().filter(|c| **c == channel).count()
    }
}
