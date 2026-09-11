//! The AWDL action frame: how you tell an AWDL frame from every other frame in the air.
//!
//! AWDL rides inside an 802.11 **vendor-specific action frame**. Four things have to
//! line up, and checking fewer than all four is how a capture ends up full of other
//! vendors' traffic:
//!
//! ```text
//!   802.11 type/subtype   management / action        (0 / 13)
//!   category              0x7f  vendor specific
//!   OUI                   00:17:f2                   Apple
//!   awdl type             0x08                       Apple's own sub-protocol tag
//! ```
//!
//! The OUI alone is not enough. Apple puts several protocols behind `00:17:f2`, and
//! the type byte after it is what says AWDL rather than something else.

use crate::le;
use crate::tlv::Tlvs;

/// IEEE 802.11 action category for vendor-specific frames.
pub const CATEGORY_VENDOR_SPECIFIC: u8 = 0x7f;

/// Apple's OUI, as it appears on the wire.
pub const OUI_APPLE: [u8; 3] = [0x00, 0x17, 0xf2];

/// The byte after the OUI that distinguishes AWDL from Apple's other vendor frames.
pub const AWDL_TYPE: u8 = 0x08;

/// Periodic Synchronization Frame — sent frequently, carries timing.
pub const SUBTYPE_PSF: u8 = 0;
/// Master Indication Frame — sent by the elected master, carries the full parameter set.
pub const SUBTYPE_MIF: u8 = 3;

pub fn subtype_name(s: u8) -> &'static str {
    match s {
        SUBTYPE_PSF => "PSF",
        SUBTYPE_MIF => "MIF",
        _ => "unknown",
    }
}

/// AWDL's 12-byte fixed header, which precedes the TLVs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fixed {
    pub version_major: u8,
    pub version_minor: u8,
    pub subtype: u8,
    /// Time the PHY actually started transmitting, in TU-derived units.
    pub phy_tx_time: u32,
    /// Time the sender *intended* to transmit.
    pub target_tx_time: u32,
}

impl Fixed {
    /// How late the frame went out.
    ///
    /// This is the single most interesting number in the header for synchronisation
    /// work: it is the sender telling you its own transmit jitter, and it is what any
    /// receiver has to compensate for to stay in the cluster. Wraps like the counters
    /// it is derived from, hence the wrapping subtraction.
    pub fn tx_delay(&self) -> u32 {
        self.phy_tx_time.wrapping_sub(self.target_tx_time)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionFrame<'a> {
    pub fixed: Fixed,
    /// The TLV region, unparsed. Iterate it with `tlvs()`.
    pub tagged: &'a [u8],
}

impl<'a> ActionFrame<'a> {
    /// Parse an AWDL action frame from an 802.11 **frame body** (i.e. after the 24-byte
    /// management header).
    ///
    /// Returns None for any frame that is not AWDL. That is the common case by a wide
    /// margin — most of the air is not AWDL — so this is a filter, not an error path.
    pub fn parse(body: &'a [u8]) -> Option<ActionFrame<'a>> {
        if le::u8(body, 0)? != CATEGORY_VENDOR_SPECIFIC {
            return None;
        }
        if body.get(1..4)? != OUI_APPLE {
            return None;
        }
        // The AWDL fixed header begins at the type byte, which is also the first byte
        // of the 12-byte block Wireshark labels "fixed parameters".
        let t = le::u8(body, 4)?;
        if t != AWDL_TYPE {
            return None;
        }
        let version = le::u8(body, 5)?;
        let fixed = Fixed {
            // Version is a packed pair of nibbles: 0x10 is 1.0, not 16.
            version_major: version >> 4,
            version_minor: version & 0x0f,
            subtype: le::u8(body, 6)?,
            // body[7] is reserved and has been zero in everything seen so far.
            phy_tx_time: le::u32(body, 8)?,
            target_tx_time: le::u32(body, 12)?,
        };
        Some(ActionFrame { fixed, tagged: body.get(16..)? })
    }

    pub fn tlvs(&self) -> Tlvs<'a> {
        Tlvs::new(self.tagged)
    }
}
