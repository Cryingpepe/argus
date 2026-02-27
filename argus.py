#!/usr/bin/env python3
"""Argus skeleton for CSE 363 HW1."""

import argparse
import re
import signal
import sys
from datetime import datetime
from typing import Optional, Tuple

from scapy.all import DNS, DNSQR, IP, Raw, TCP, UDP, conf, load_layer, sniff

AUTOMATION_RE = re.compile(r"(curl|wget|python|requests|urllib|httpx)", re.IGNORECASE)
INTERNAL_TLDS = (".local", ".corp", ".internal")
DEBUG = False
NO_MATCH_DEBUG_LIMIT = 25
_no_match_debug_count = 0


def debug_log(message: str) -> None:
    if DEBUG:
        print(f"[debug] {message}", file=sys.stderr, flush=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Argus: passive network sniffer for HTTP/TLS/DNS requests."
    )
    parser.add_argument("-i", "--interface", help="Live capture interface (e.g., eth0).")
    parser.add_argument(
        "-r",
        "--read",
        dest="tracefile",
        help="Read packets from a tcpdump/pcap trace file (overrides -i).",
    )
    parser.add_argument(
        "expression",
        nargs="*",
        help="Optional BPF filter expression (example: host 192.168.0.123).",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable packet-level debug logs on stderr.",
    )
    args = parser.parse_args()
    args.expression = " ".join(args.expression).strip()
    return args


def load_optional_layers() -> None:
    # Scapy may need these to parse HTTP/TLS convenience fields.
    for layer in ("http", "tls"):
        try:
            load_layer(layer)
        except Exception:
            pass


def format_timestamp(packet_time: float) -> str:
    dt = datetime.fromtimestamp(float(packet_time))
    return dt.strftime("%Y-%m-%d %H:%M:%S.%f")


def get_network_tuple(packet) -> Optional[Tuple[str, int, str, int]]:
    if IP not in packet:
        return None

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    src_port = 0
    dst_port = 0

    if TCP in packet:
        src_port = int(packet[TCP].sport)
        dst_port = int(packet[TCP].dport)
    elif UDP in packet:
        src_port = int(packet[UDP].sport)
        dst_port = int(packet[UDP].dport)

    return src_ip, src_port, dst_ip, dst_port


def build_prefix(packet, proto: str) -> Optional[str]:
    tuple_data = get_network_tuple(packet)
    if tuple_data is None:
        return None

    src_ip, src_port, dst_ip, dst_port = tuple_data
    ts = format_timestamp(packet.time)
    return f"{ts} {proto:<4} {src_ip}:{src_port} -> {dst_ip}:{dst_port}"


def decode_bytes(raw: bytes) -> str:
    return raw.decode("utf-8", errors="ignore")


def get_tcp_payload(packet) -> bytes:
    if TCP not in packet:
        return b""
    try:
        payload = bytes(packet[TCP].payload)
    except Exception:
        return b""
    return payload if payload else b""


def parse_http_request(packet) -> Optional[str]:
    if TCP not in packet:
        return None

    payload = get_tcp_payload(packet)
    if not payload:
        return None

    header_block = decode_bytes(payload)
    lines = header_block.splitlines()
    if not lines:
        return None

    request_line = lines[0].strip()
    parts = request_line.split()
    if len(parts) < 3:
        return None

    method = parts[0].upper()
    version = parts[2].upper()
    if method not in {"GET", "POST", "PUT"}:
        return None
    if not version.startswith("HTTP/"):
        return None

    uri = parts[1]
    host = "NO HOST"
    user_agent = ""

    for line in lines[1:]:
        if not line:
            break
        lower = line.lower()
        if lower.startswith("host:"):
            host = line.split(":", 1)[1].strip()
        elif lower.startswith("user-agent:"):
            user_agent = line.split(":", 1)[1].strip()

    prefix = build_prefix(packet, "HTTP")
    if prefix is None:
        return None

    output = f"{prefix} {host} {method} {uri}"
    if user_agent and AUTOMATION_RE.search(user_agent):
        output += f" AUTOMATION {user_agent}"
    return output


def get_dns_layer(packet) -> Optional[DNS]:
    # Keep DNS detection independent from destination port number.
    if DNS in packet:
        return packet[DNS]

    if UDP in packet and Raw in packet:
        try:
            return DNS(bytes(packet[Raw].load))
        except Exception:
            return None

    return None


def parse_dns_query(packet) -> Optional[str]:
    if UDP not in packet:
        return None

    dns = get_dns_layer(packet)
    if dns is None:
        return None

    if int(dns.qr) != 0:
        return None
    if int(dns.qdcount) < 1:
        return None

    qd = dns.qd
    if isinstance(qd, DNSQR):
        first_qd = qd
    else:
        try:
            first_qd = qd[0]
        except Exception:
            return None

    if not isinstance(first_qd, DNSQR):
        return None

    qtype = int(first_qd.qtype)
    if qtype != 1:
        return None

    qname = first_qd.qname
    if isinstance(qname, bytes):
        name = qname.decode("utf-8", errors="ignore")
    else:
        name = str(qname)
    name = name.rstrip(".")

    if not name:
        return None

    prefix = build_prefix(packet, "DNS")
    if prefix is None:
        return None

    output = f"{prefix} {name}"
    lname = name.lower()
    if lname.endswith(INTERNAL_TLDS):
        output += " INTERNAL"
    return output


def parse_sni_from_client_hello(payload: bytes) -> Optional[str]:
    if len(payload) < 5:
        return None
    if payload[0] != 0x16:
        return None

    record_len = int.from_bytes(payload[3:5], "big")
    if len(payload) < 5 + record_len:
        return None

    offset = 5
    while offset + 4 <= len(payload):
        hs_type = payload[offset]
        hs_len = int.from_bytes(payload[offset + 1 : offset + 4], "big")
        hs_start = offset + 4
        hs_end = hs_start + hs_len
        if hs_end > len(payload):
            return None

        if hs_type == 0x01:
            body = payload[hs_start:hs_end]
            return parse_sni_from_client_hello_body(body)

        offset = hs_end

    return None


def parse_sni_from_client_hello_body(body: bytes) -> str:
    if len(body) < 2 + 32 + 1:
        return ""

    offset = 0
    offset += 2 + 32

    session_id_len = body[offset]
    offset += 1 + session_id_len
    if offset + 2 > len(body):
        return ""

    cipher_len = int.from_bytes(body[offset : offset + 2], "big")
    offset += 2 + cipher_len
    if offset + 1 > len(body):
        return ""

    compression_len = body[offset]
    offset += 1 + compression_len
    if offset + 2 > len(body):
        return ""

    ext_total_len = int.from_bytes(body[offset : offset + 2], "big")
    offset += 2
    ext_end = offset + ext_total_len
    if ext_end > len(body):
        return ""

    while offset + 4 <= ext_end:
        ext_type = int.from_bytes(body[offset : offset + 2], "big")
        ext_len = int.from_bytes(body[offset + 2 : offset + 4], "big")
        offset += 4
        if offset + ext_len > ext_end:
            return ""

        if ext_type == 0x0000:
            ext_data = body[offset : offset + ext_len]
            if len(ext_data) < 2:
                return ""

            list_len = int.from_bytes(ext_data[0:2], "big")
            pos = 2
            list_end = min(len(ext_data), 2 + list_len)

            while pos + 3 <= list_end:
                name_type = ext_data[pos]
                name_len = int.from_bytes(ext_data[pos + 1 : pos + 3], "big")
                pos += 3
                if pos + name_len > list_end:
                    return ""
                if name_type == 0:
                    name_bytes = ext_data[pos : pos + name_len]
                    return name_bytes.decode("utf-8", errors="ignore")
                pos += name_len
            return ""

        offset += ext_len

    return ""


def parse_tls_client_hello(packet) -> Optional[str]:
    if TCP not in packet:
        return None

    payload = get_tcp_payload(packet)
    if not payload:
        return None

    sni = parse_sni_from_client_hello(payload)
    if sni is None:
        return None

    prefix = build_prefix(packet, "TLS")
    if prefix is None:
        return None

    return f"{prefix} {sni if sni else 'NO SNI'}"


def handle_packet(packet) -> None:
    global _no_match_debug_count

    for parser in (parse_dns_query, parse_http_request, parse_tls_client_hello):
        output = parser(packet)
        if output:
            print(output, flush=True)
            return

    if DEBUG and _no_match_debug_count < NO_MATCH_DEBUG_LIMIT:
        _no_match_debug_count += 1
        debug_log(f"no match: {packet.summary()}")


def run_live_capture(interface: Optional[str], bpf_filter: str) -> None:
    iface_name = interface if interface else str(conf.iface)
    debug_log(f"live capture interface={iface_name} bpf={bpf_filter or '<none>'}")
    sniff(
        iface=interface if interface else None,
        filter=bpf_filter if bpf_filter else None,
        prn=handle_packet,
        store=False,
    )


def run_trace_capture(tracefile: str, bpf_filter: str) -> None:
    debug_log(f"offline capture tracefile={tracefile} bpf={bpf_filter or '<none>'}")
    sniff(
        offline=tracefile,
        filter=bpf_filter if bpf_filter else None,
        prn=handle_packet,
        store=False,
    )


def main() -> int:
    global DEBUG

    load_optional_layers()
    args = parse_args()
    DEBUG = bool(args.debug)

    def _stop_signal_handler(signum, frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGINT, _stop_signal_handler)

    try:
        if args.tracefile:
            run_trace_capture(args.tracefile, args.expression)
        else:
            run_live_capture(args.interface, args.expression)
    except KeyboardInterrupt:
        pass
    except PermissionError:
        print("Permission denied. Try running with sudo/root privileges.", file=sys.stderr)
        return 1
    except FileNotFoundError as exc:
        print(f"Input file not found: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"Unexpected error: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
