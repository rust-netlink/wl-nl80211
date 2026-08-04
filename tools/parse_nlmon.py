#!/usr/bin/env python3
"""Parse a pcap captured on an nlmon (LINKTYPE_NETLINK=158) interface and
print generic-netlink (nl80211) messages: nlmsghdr type, genl cmd, flags.
Usage: parse_nlmon.py <pcap> [cmd_filter...]
"""

import struct, sys


def iter_packets(path):
    with open(path, "rb") as f:
        magic = f.read(4)
        if magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"):
            endian = "<" if magic == b"\xd4\xc3\xb2\xa1" else ">"
            f.seek(0)
            gh = f.read(24)
            if len(gh) < 24:
                return
            while True:
                rec = f.read(16)
                if len(rec) < 16:
                    return
                ts_sec, ts_usec, incl, orig = struct.unpack(endian + "IIII", rec)
                data = f.read(incl)
                if len(data) < incl:
                    return
                yield data
        elif magic == b"\x0a\x0d\x0d\x0a":
            while True:
                bh = f.read(8)
                if len(bh) < 8:
                    return
                btype, blen = struct.unpack("<II", bh)
                body = f.read(blen - 12)
                if len(body) < blen - 12:
                    return
                if btype == 6:  # EPB
                    iface, tshi, tslo, caplen, origlen = struct.unpack(
                        "<IIIII", body[:20]
                    )
                    yield body[20 : 20 + caplen]
                f.read(4)
        else:
            sys.exit("unsupported pcap format")


NL80211_CMDS = {
    37: "AUTHENTICATE",
    38: "ASSOCIATE",
    46: "CONNECT",
    48: "DISCONNECT",
    11: "NEW_KEY",
    10: "SET_KEY",
    59: "FRAME",
    129: "CONTROL_PORT_FRAME",
    127: "EXTERNAL_AUTH",
    139: "CONTROL_PORT_FRAME_TX_STATUS",
    1: "GET_WIPHY",
    3: "NEW_WIPHY",
    5: "GET_INTERFACE",
    7: "NEW_INTERFACE",
    8: "DEL_INTERFACE",
    29: "TRIGGER_SCAN",
    33: "NEW_SCAN_RESULTS",
    129: "EXTERNAL_AUTH",
    47: "GET_SCAN",
}

want = set(sys.argv[2:]) if len(sys.argv) > 2 else None
found = []
for data in iter_packets(sys.argv[1]):
    if len(data) < 4:
        continue
    family = struct.unpack_from("<H", data, 0)[0]
    off = 4  # nlmon cooked header: family(2) + pad(2)
    if family != 16:  # NETLINK_GENERIC
        continue
    while off + 16 <= len(data):
        nlen, ntype, nflags, nseq, npid = struct.unpack_from("<IHHII", data, off)
        if nlen < 16 or off + nlen > len(data):
            break
        payload = data[off + 16 : off + nlen]
        if len(payload) >= 4:
            cmd = payload[0]
            if cmd in NL80211_CMDS and (want is None or NL80211_CMDS[cmd] in want):
                found.append((nlen, ntype, nflags, nseq, cmd, data[off : off + nlen]))
        off += nlen

print(f"total matching messages: {len(found)}")
for nlen, ntype, nflags, nseq, cmd, raw in found:
    name = NL80211_CMDS[cmd]
    req = "REQ" if nflags & 0x01 else "   "
    ack = "ACK" if nflags & 0x02 else "   "
    print(
        f"  {name:18s} type=0x{ntype:02x} flags={nflags:04x} ({req}{ack}) seq={nseq} len={nlen}"
    )
