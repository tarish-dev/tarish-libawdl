# Findings

Each entry names the capture it came from. A claim with no capture behind it says so.

---

## 1. The parser agrees with Wireshark, frame for frame and tag for tag

`captures/awdl-149.pcap` — 45s, channel 149, Raspberry Pi 400 + ALFA AWUS036ACM (`mt76x2u`).

|  | marsad | `tshark -Y awdl` |
|---|---|---|
| frames in capture | 6584 | 6584 |
| identified as AWDL | **278** | **278** |

The TLV histogram is identical too, tag for tag:

```
 154 [ 0] SSTH Request           278 [12] Data Path State
 576 [ 2] Service Response       192 [16] Arpa
 278 [ 4] Sync Parameters        278 [17] IEEE 802.11 Container
 278 [ 5] Election Parameters    278 [18] Channel Sequence
 278 [ 6] Service Parameters     278 [21] Version
 278 [ 7] HT Capabilities        278 [24] Election Parameters v2
                                 184 [32] undocumented
                                 184 [33] undocumented
```

This matters more than it looks. Independent agreement on **which 278 of 6584 frames are
AWDL** is what makes every later measurement worth reporting. Without it, a parser that
quietly drops a frame class produces clean, confident, wrong numbers.

## 2. Tags 32 and 33 are on the wire and in no published table

Wireshark's enum ends at 24 (`AWDL_ELECTION_PARAMETERS_V2_TLV`). Tags **32** and **33**
appear 184 times each in 45 seconds, in MIFs from current Apple devices. `tshark
-e awdl.tag.number` reports them too, so this is not our parser inventing them — it is
Wireshark having no name for them.

Contents undecoded. Two tags appearing at identical counts, in the same frames, is the
sort of pairing that usually means a capability/operation pair (as 7/8 are), but that is
a guess and is flagged as one.

The 2018 paper does not describe them. This is the first concrete instance of the drift
the research brief warned about: **do not assume the paper still describes what Apple
ships.**

## 3. AWDL is in the air with nobody touching anything

Nobody opened a share sheet during this capture. Three Apple devices were nonetheless
sending AWDL continuously:

```
06:37:6f:45:5c:68    94 frames
1a:90:37:31:e6:58   107 frames
ee:4b:4f:cc:5b:12    77 frames
```

269 MIF to 9 PSF. So Master Indication Frames are the steady state, not an artefact of an
active transfer, and a passive listener sees a device's full parameter set — channel
sequence, election state, services — without any interaction at all.

Useful consequence: **channel 149 is already the right place to listen in this region**,
and no Apple device needs to be doing anything for the experiment to run.

## 4. Every AWDL sender uses a randomised MAC

All three senders have the locally-administered bit set (`0x02` in the first octet):
`06:`, `1a:`, `ee:`. There is no hardware address to key on. Anything that identifies a
peer by MAC will work on a bench, where addresses happen to be stable for a while, and
fail in the field. Asserted in `crates/awdl/tests/real_capture.rs` so it cannot be
forgotten.

## 5. Half the air is ACKs, which is not the same as unparseable

The first version of `marsad stats` reported 3158 of 6584 frames "unparsed", which looked
alarming and was an artefact: it demanded a full 24-byte management header before it
would say what a frame was, and a control frame is ten bytes with no third address.

Corrected breakdown of the same capture:

```
6584 frames: 278 AWDL, 6306 other 802.11, 0 not 802.11
  other control      6287
  other management     19
```

Zero unaccounted for. The lesson is worth keeping: a classifier that cannot distinguish
"too short for the header I wanted" from "not 802.11" will make a healthy capture look
broken.

## 6. The paper's timing claims hold on 2026 devices — and there is more in the frame than it describes

`captures/awdl-149.pcap`, all 278 AWDL frames. Cross-checked against `tshark -V`.

| Claim (Stute et al., 2018) | Verdict | Evidence |
|---|---|---|
| Availability Window is 16 TU | **confirmed** | `aw_period = 16` in 278/278 frames; 16 x 1024 = 16384 us |
| Channel sequence has 16 slots | **confirmed** | count field is 15, and the count is stored **minus one** |
| Social channels 6 / 44 / 149 | **confirmed for this region** | only 6 and 149 in use; 44 never appears, consistent with Qatar mapping to 149 |

### A frame carries its schedule TWICE, in two different encodings

This is not in the paper and is the kind of thing that makes an implementation subtly
wrong rather than broken. **Synchronization Parameters (tag 4) embeds a complete channel
sequence of its own**, in addition to the standalone Channel Sequence (tag 18). In the
same frame:

```
tag 4  (Legacy encoding)    0, 0, 151, 0, 0, 151, 0, 0, 6, 0, 151, 0, 0, 151, 0, 0
tag 18 (OpClass encoding)   0, 0, 149, 0, 0, 149, 0, 0, 6, 0, 149, 0, 0, 149, 0, 0
```

Identical occupancy, different channel numbers: **151 is the 40 MHz centre, 149 and 153
are its 20 MHz halves.** The two encodings also order their bytes differently — Legacy is
`flags, channel`, OpClass is `channel, opclass` — so reading one as the other produces
plausible garbage rather than an error.

Occupancy matched slot-for-slot across the whole capture (3/16, 4/16, 5/16, 6/16 and 9/16,
with identical frame counts on both), which is what establishes they describe one schedule
rather than two.

### A device is absent for most of its own schedule

Occupancy ranged from **3 of 16 slots to 9 of 16**. Channel 0 means "not present", and
most slots are 0.

This is the number that governs throughput between two peers, and it is not the link rate.
Two nodes can only exchange anything during windows where **both** are present **and** on
the same channel. A peer at 3/16 imposes a hard ceiling of 18% of airtime on anyone
talking to it, however fast the modulation.

It also explains the earlier iPhone measurement from the Android work — 4 of 16 slots
split across 149 and 6, against our own devices at 16/16 on one channel, giving roughly
19% overlap and 2.6-4.7 MB/s. That figure was previously attributed to the radio. It is
the schedule.

### `AP Beacon alignment delta` exists

A named field in Synchronization Parameters, immediately after the AW sequence number.
**There is no reason to carry an access point's beacon offset unless you intend to line
up with it**, which is direct evidence that AWDL is designed to time-share with an
infrastructure association rather than merely tolerate one — the question the research
brief flags as highest value.

It was **0 in all 278 frames**, consistent with these particular devices not currently
time-sharing with an AP. That is a measurement to repeat against a device that
demonstrably is, and until then the field's existence is the finding, not its value.

**What this does NOT yet show.** Channel 153 appears in some sequences alongside 149, and
there is an AP on 153 nearby, so it is tempting to read that as the AP's channel appearing
in the slots. It is more likely the other half of the 149+153 bond centred on 151 — the
Legacy sequence reports 151 in exactly those slots. Not claimed either way.

## 7. Every device keeps slot 8 on channel 6, without exception — and this corrects what we do

Across all 278 frames and both channel sequences in each — **556 sequences** — channel 6
appears exactly once, and always at **slot index 8**, the midpoint of the 16-slot cycle:

```
$ tshark ... | awk '{for(i=1;i<=NF;i++) if($i==6) print i-1}' | sort -n | uniq -c
   556 8
```

Three different devices, every frame, no exceptions. The operating-class histogram agrees
independently: class `0x51` (2.4 GHz) appears exactly 278 times, once per frame.

**This is a cross-band rendezvous, and it is almost certainly deliberate.** A device whose
useful traffic is on 5 GHz still guarantees it is listening on the 2.4 GHz social channel
for one window in every sixteen. That is how a 5 GHz device meets a 2.4 GHz-only device,
and how devices in different regulatory domains — Europe on 44, Qatar on 149 — still find
each other. A fixed slot index means no negotiation is needed: everyone is there at the
same point in the cycle.

### What this corrects on our side

`tarishd`'s `channels_for()` picks **one band**:

```rust
0              => vec![CHANNELS_24, CHANNELS_5],   // 2.4 first when unknown
f if f >= 5000 => vec![CHANNELS_24, CHANNELS_5],   // Wi-Fi on 5 -> AWDL on 2.4
_              => vec![CHANNELS_5,  CHANNELS_24],  // Wi-Fi on 2.4 -> AWDL on 5
```

with `CHANNELS_24 = [6]` and `CHANNELS_5 = [149, 44]`. The list is a **preference order**
— the first set that starts is the one used — so a device ends up wholly on 2.4 **or**
wholly on 5 GHz. It never occupies both, and our own devices were previously measured at
16/16 slots on a single channel.

That is why a 4383 forced to 2.4 GHz and a 4390 on 149 cannot discover each other, which
was written up as an unavoidable trade-off for the operator to settle.

**It is not a trade-off. Apple solved it, and the solution is one slot.**

The concrete experiment, which needs no new code: pass a **combined** list such as
`[149, 6]` to `mosey_start_5` rather than one band's set, and capture the channel
sequence that results. If `libmosey` builds a mixed sequence, the cross-band cliff
disappears and the per-mode channel choice proposed in BUILD-NOTES 59 stops needing a
decision at all. If it does not, we have learned something specific about what `libmosey`
will and will not schedule — which is equally useful, and is exactly the kind of thing our
own implementation would then do differently.

### And it re-explains an old measurement

The iPhone figure from the Android work — 2.6-4.7 MB/s, 4 of 16 slots split across 149
and 6 — was attributed to the radio. It is the schedule. Our device at 16/16 on one
channel is already maximally available, so the ceiling is the peer's occupancy and not
anything we can tune. **Slot occupancy, not link rate, is what governs AWDL throughput**,
and any future capacity claim should be stated in slots.

---

## Setup

Moved to [SETUP.md](SETUP.md), with the rig, the build steps and the traps.

