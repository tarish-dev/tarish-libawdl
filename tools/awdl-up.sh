#!/bin/sh
# Bring the ALFA up as an AWDL-capable monitor interface.
#
#   ./awdl-up.sh [channel]      default 149 (the AWDL social channel for QA)
#
# THE MANAGED INTERFACE MUST BE DOWN. This is the whole trick, and getting it
# wrong fails in a way that looks like broken hardware: OWL starts, reports
# "Channel NN is available for frame injection", creates awdl0, and then every
# send() returns EAGAIN --
#
#     ERROR: unable to inject packet (send: Resource temporarily unavailable)
#
# with nothing in dmesg. The adapter is fine; aireplay-ng -9 gets 30/30 on the
# same radio. mt76 will not transmit from a monitor vif while another vif on the
# same phy is up, and will not let you set the channel either ("Device or
# resource busy"). Flipping the primary interface to type monitor fails the same
# way; it has to be a separate vif with the managed one down.
#
# THE PHY INDEX IS NOT STABLE. It was phy2 before a reboot and phy1 after, so it
# is derived from the interface rather than hardcoded -- a hardcoded one fails
# with "No such device (-19)", which reads like the adapter is missing.
#
# THE REGULATORY DOMAIN DOES NOT SURVIVE A REBOOT. It comes back as country 00,
# which marks every 5 GHz channel PASSIVE-SCAN/no-IR -- the radio may listen on
# 44 and 149 but not transmit. Only channel 6 is open. Re-set it every time.
set -e
WLAN=wlx00c0cab0604c
CHAN=${1:-149}
PHY=$(basename $(readlink -f /sys/class/net/$WLAN/phy80211))

# rfkill soft-blocks every radio after a reboot until a country is set; without
# this, bringing the interface up fails with "Operation not possible due to RF-kill".
sudo rfkill unblock all
sudo iw reg set QA
sudo ip link set $WLAN down 2>/dev/null || true
sudo iw dev mon0 del 2>/dev/null || true
sudo iw phy $PHY interface add mon0 type monitor
sudo ip link set mon0 up
sudo iw dev mon0 set channel $CHAN
echo "mon0 up on $PHY, channel $CHAN, $WLAN down"
