//! The parser against a frame that actually came off a radio.
//!
//! The synthetic tests in `parse.rs` pin the framing. This one pins the parser against
//! hardware, which catches a different class of mistake: a field that is right in
//! theory and wrong in the air, and a radiotap header shaped the way a real driver
//! shapes it rather than the way the spec's example does.
//!
//! Every expected value below was independently confirmed with `tshark -Y awdl` on the
//! same capture, so this asserts agreement with Wireshark, not merely self-consistency.

mod fixture_frame;

use libawdl::action::{ActionFrame, SUBTYPE_MIF};
use libawdl::dot11::{Dot11, FrameControl};
use libawdl::radiotap::Radiotap;

#[test]
fn a_real_frame_from_a_real_apple_device_parses() {
    let pkt = fixture_frame::FRAME;

    let rt = Radiotap::parse(pkt).expect("radiotap from a live mt76 capture");
    assert_eq!(rt.freq, Some(5745), "captured on channel 149");
    assert!(rt.signal_dbm.is_some_and(|s| s < 0), "a real signal is negative dBm");

    let body80211 = rt.payload(pkt).unwrap();
    assert!(FrameControl::parse(body80211).unwrap().is_action());

    let d = Dot11::parse(body80211).unwrap();
    let af = ActionFrame::parse(d.body(body80211).unwrap()).expect("is AWDL");

    assert_eq!(af.fixed.subtype, SUBTYPE_MIF, "a Master Indication Frame");

    // AWDL SENDERS USE RANDOMISED MAC ADDRESSES. Every sender in this capture has the
    // locally-administered bit set, which is worth asserting: anything keyed on a
    // stable hardware address will work on a bench and fail in the field.
    assert_eq!(d.src.0[0] & 0x02, 0x02, "locally administered (randomised) address");

    // The tag region has to consume exactly, with nothing left over.
    let mut tlvs = af.tlvs();
    let tags: Vec<u8> = tlvs.by_ref().map(|t| t.tag).collect();
    assert_eq!(tlvs.stop(), Some(libawdl::tlv::Stop::Clean), "tags consume the region exactly");

    for required in [4u8, 5, 6, 18, 21] {
        assert!(
            tags.contains(&required),
            "a MIF carries tag {required} ({})",
            libawdl::tlv::tag_name(required)
        );
    }
}

/// Tags 32 and 33 are on the wire and are in no published table.
///
/// Wireshark's own enum stops at 24 (Election Parameters v2), yet both appear 184 times
/// each in a 45-second capture — confirmed by `tshark -e awdl.tag.number`, so this is
/// not our parser inventing them. Recorded as a test so that if a future change starts
/// silently dropping unknown tags, this fails instead of the finding quietly vanishing.
#[test]
fn undocumented_tags_are_preserved_not_discarded() {
    let pkt = fixture_frame::FRAME;
    let rt = Radiotap::parse(pkt).unwrap();
    let body80211 = rt.payload(pkt).unwrap();
    let d = Dot11::parse(body80211).unwrap();
    let af = ActionFrame::parse(d.body(body80211).unwrap()).unwrap();

    let unknown: Vec<u8> = af.tlvs().map(|t| t.tag).filter(|t| *t > 24).collect();
    assert!(
        !unknown.is_empty(),
        "this capture carries tags beyond the published set; if that stops being true, \
         say so deliberately rather than deleting the test"
    );
    for t in unknown {
        assert_eq!(libawdl::tlv::tag_name(t), "unrecognised");
    }
}
