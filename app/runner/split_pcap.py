import argparse
import hashlib
from pathlib import Path
from typing import Tuple, Optional, Dict, Any, List


PCAP_GLOBAL_HDR_LEN = 24
PCAP_PKT_HDR_LEN = 16


def _hash_key(key: bytes) -> int:
    h = hashlib.sha1(key).digest()
    return int.from_bytes(h[:8], byteorder="big", signed=False)


def _fmt_ipv4(ip4: bytes) -> str:
    return ".".join(str(b) for b in ip4)


def _fmt_ipv6(ip6: bytes) -> str:
    parts = []
    for i in range(0, 16, 2):
        parts.append(f"{int.from_bytes(ip6[i:i+2], 'big'):04x}")
    return ":".join(parts)


def _ipv4_tuple(pkt: bytes) -> Optional[Tuple[bytes, bytes, int, int, int]]:
    if len(pkt) < 14 + 20:
        return None
    eth_type = int.from_bytes(pkt[12:14], "big")
    if eth_type != 0x0800:
        return None
    ip = pkt[14:]
    ver_ihl = ip[0]
    ver = ver_ihl >> 4
    if ver != 4:
        return None
    ihl = (ver_ihl & 0x0F) * 4
    if len(ip) < ihl:
        return None

    proto = ip[9]
    src_ip = ip[12:16]
    dst_ip = ip[16:20]

    if proto in (6, 17):
        if len(ip) < ihl + 4:
            return None
        l4 = ip[ihl:]
        src_port = int.from_bytes(l4[0:2], "big")
        dst_port = int.from_bytes(l4[2:4], "big")
    else:
        src_port = 0
        dst_port = 0

    return (src_ip, dst_ip, src_port, dst_port, proto)


def _ipv6_tuple(pkt: bytes) -> Optional[Tuple[bytes, bytes, int, int, int]]:
    if len(pkt) < 14 + 40:
        return None
    eth_type = int.from_bytes(pkt[12:14], "big")
    if eth_type != 0x86DD:
        return None
    ip = pkt[14:]
    ver = ip[0] >> 4
    if ver != 6:
        return None

    nxt = ip[6]
    src_ip = ip[8:24]
    dst_ip = ip[24:40]
    proto = nxt

    if proto in (6, 17):
        if len(ip) < 40 + 4:
            return None
        l4 = ip[40:]
        src_port = int.from_bytes(l4[0:2], "big")
        dst_port = int.from_bytes(l4[2:4], "big")
    else:
        src_port = 0
        dst_port = 0

    return (src_ip, dst_ip, src_port, dst_port, proto)


def tuple_for_packet(pkt: bytes) -> Tuple[bytes, Dict[str, Any]]:
    t4 = _ipv4_tuple(pkt)
    if t4 is not None:
        src_ip_b, dst_ip_b, sp, dp, pr = t4
        key = b"4" + src_ip_b + dst_ip_b + sp.to_bytes(2, "big") + dp.to_bytes(2, "big") + bytes([pr])
        return key, {
            "ip_ver": 4,
            "src_ip": _fmt_ipv4(src_ip_b),
            "dst_ip": _fmt_ipv4(dst_ip_b),
            "src_port": sp,
            "dst_port": dp,
            "proto": pr,
        }

    t6 = _ipv6_tuple(pkt)
    if t6 is not None:
        src_ip_b, dst_ip_b, sp, dp, pr = t6
        key = b"6" + src_ip_b + dst_ip_b + sp.to_bytes(2, "big") + dp.to_bytes(2, "big") + bytes([pr])
        return key, {
            "ip_ver": 6,
            "src_ip": _fmt_ipv6(src_ip_b),
            "dst_ip": _fmt_ipv6(dst_ip_b),
            "src_port": sp,
            "dst_port": dp,
            "proto": pr,
        }

    key = b"X" + pkt[:64]
    return key, {
        "ip_ver": 0,
        "src_ip": "-",
        "dst_ip": "-",
        "src_port": 0,
        "dst_port": 0,
        "proto": 0,
    }


def write_worker_map_log(out_path: Path, rows: List[Dict[str, Any]]) -> None:
    fields = ["worker", "ip_ver", "src_ip", "src_port", "dst_ip", "dst_port", "proto", "pkt_count"]
    types = ["count", "count", "string", "port", "string", "port", "count", "count"]

    with out_path.open("w", encoding="utf-8") as f:
        f.write("#separator \t\n")
        f.write("#set_separator ,\n")
        f.write("#empty_field (empty)\n")
        f.write("#unset_field -\n")
        f.write("#path worker_map\n")
        f.write("#open 0\n")
        f.write("#fields\t" + "\t".join(fields) + "\n")
        f.write("#types\t" + "\t".join(types) + "\n")

        for r in rows:
            line = [
                str(r["worker"]),
                str(r["ip_ver"]),
                str(r["src_ip"]),
                str(r["src_port"]),
                str(r["dst_ip"]),
                str(r["dst_port"]),
                str(r["proto"]),
                str(r["pkt_count"]),
            ]
            f.write("\t".join(line) + "\n")

        f.write("#close 0\n")


def split_pcap_flowhash(pcap_path: Path, out_dir: Path, workers: int) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    outs = []
    for i in range(workers):
        p = out_dir / f"worker{i+1}.pcap"
        f = p.open("wb")
        outs.append((p, f))

    flow_map: Dict[bytes, Dict[str, Any]] = {}

    try:
        data = pcap_path.read_bytes()
        if len(data) < PCAP_GLOBAL_HDR_LEN:
            raise ValueError("pcap too small")

        global_hdr = data[:PCAP_GLOBAL_HDR_LEN]
        for _, f in outs:
            f.write(global_hdr)

        off = PCAP_GLOBAL_HDR_LEN
        while off + PCAP_PKT_HDR_LEN <= len(data):
            pkt_hdr = data[off : off + PCAP_PKT_HDR_LEN]
            incl_len = int.from_bytes(pkt_hdr[8:12], "little")
            pkt_off = off + PCAP_PKT_HDR_LEN
            pkt_end = pkt_off + incl_len
            if pkt_end > len(data):
                break

            pkt = data[pkt_off:pkt_end]
            key, rep = tuple_for_packet(pkt)
            idx = _hash_key(key) % workers
            worker_id = idx + 1

            _, f = outs[idx]
            f.write(pkt_hdr)
            f.write(pkt)

            if key not in flow_map:
                flow_map[key] = {
                    "worker": worker_id,
                    "ip_ver": rep["ip_ver"],
                    "src_ip": rep["src_ip"],
                    "dst_ip": rep["dst_ip"],
                    "src_port": rep["src_port"],
                    "dst_port": rep["dst_port"],
                    "proto": rep["proto"],
                    "pkt_count": 1,
                }
            else:
                flow_map[key]["pkt_count"] += 1

            off = pkt_end

    finally:
        for _, f in outs:
            f.close()

    rows = list(flow_map.values())
    rows.sort(key=lambda r: (r["worker"], -int(r["pkt_count"]), r["ip_ver"], r["src_ip"], r["dst_ip"], r["proto"]))

    map_path = out_dir / "worker_map.log"
    write_worker_map_log(map_path, rows)
    return map_path


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--workers", type=int, default=7)
    args = ap.parse_args()

    split_pcap_flowhash(Path(args.pcap), Path(args.out_dir), args.workers)


if __name__ == "__main__":
    main()
