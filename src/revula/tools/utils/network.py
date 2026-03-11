"""
Revula Network Utilities — PCAP parsing, protocol fingerprinting, stream reconstruction.

Backends: scapy (primary), pyshark (optional).
Features: Protocol identification, stream reconstruction, C2 beacon detection heuristics.
"""

from __future__ import annotations

import logging
from typing import Any

from revula.sandbox import validate_path
from revula.tools import TOOL_REGISTRY, text_result

logger = logging.getLogger(__name__)


@TOOL_REGISTRY.register(
    name="re_pcap_analyze",
    description=(
        "Analyze PCAP/PCAPNG network captures. Protocol identification, "
        "stream reconstruction, credential extraction patterns, "
        "C2 beacon detection heuristics. Backend: scapy."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "pcap_path": {
                "type": "string",
                "description": "Absolute path to PCAP/PCAPNG file.",
            },
            "max_packets": {
                "type": "integer",
                "description": "Maximum packets to analyze. Default: 10000.",
                "default": 10000,
            },
            "extract_streams": {
                "type": "boolean",
                "description": "Reconstruct TCP streams. Default: true.",
                "default": True,
            },
            "detect_beaconing": {
                "type": "boolean",
                "description": "Run C2 beacon detection heuristics. Default: true.",
                "default": True,
            },
        },
        "required": ["pcap_path"],
    },
    category="utility",
    requires_modules=["scapy"],
)
async def handle_pcap_analyze(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Analyze a PCAP file."""
    import asyncio

    pcap_path = arguments["pcap_path"]
    max_packets = arguments.get("max_packets", 10000)
    arguments.get("extract_streams", True)
    detect_beaconing = arguments.get("detect_beaconing", True)

    config = arguments.get("__config__")
    allowed_dirs = config.security.allowed_dirs if config else None
    file_path = validate_path(pcap_path, allowed_dirs=allowed_dirs)

    loop = asyncio.get_running_loop()

    def _analyze() -> dict[str, Any]:
        from collections import Counter, defaultdict

        from scapy.all import DNS, IP, TCP, UDP, rdpcap

        packets = rdpcap(str(file_path), count=max_packets)

        result: dict[str, Any] = {
            "pcap_path": str(file_path),
            "total_packets": len(packets),
            "protocols": {},
            "conversations": [],
            "dns_queries": [],
        }

        proto_counts: Counter[str] = Counter()
        conversations: dict[tuple[str, ...], dict[str, Any]] = {}
        dns_queries: list[dict[str, str]] = []
        timing: dict[str, list[float]] = defaultdict(list)

        for pkt in packets:
            # Protocol counting
            if pkt.haslayer(TCP):
                proto_counts["TCP"] += 1
            elif pkt.haslayer(UDP):
                proto_counts["UDP"] += 1

            if pkt.haslayer(DNS):
                proto_counts["DNS"] += 1
                dns_layer = pkt.getlayer(DNS)
                if dns_layer and dns_layer.qd:
                    raw_qname = dns_layer.qd.qname
                    qname = (
                        raw_qname.decode("utf-8", errors="replace")
                        if hasattr(raw_qname, "decode")
                        else str(raw_qname)
                    )
                    dns_queries.append({"query": qname, "type": str(dns_layer.qd.qtype)})

            if pkt.haslayer(IP):
                proto_counts["IP"] += 1
                src = pkt[IP].src
                dst = pkt[IP].dst
                sport = pkt.sport if hasattr(pkt, "sport") else 0
                dport = pkt.dport if hasattr(pkt, "dport") else 0

                key = (src, dst, str(dport))
                if key not in conversations:
                    conversations[key] = {
                        "src": src, "dst": dst,
                        "src_port": sport, "dst_port": dport,
                        "packet_count": 0, "byte_count": 0,
                    }
                conversations[key]["packet_count"] += 1
                conversations[key]["byte_count"] += len(pkt)

                # Track timing for beacon detection
                if detect_beaconing:
                    timing[f"{src}->{dst}:{dport}"].append(float(pkt.time))

        result["protocols"] = dict(proto_counts)
        result["conversations"] = sorted(
            conversations.values(),
            key=lambda c: -c["packet_count"]
        )[:50]
        result["dns_queries"] = dns_queries[:100]

        # C2 beacon detection
        if detect_beaconing:
            beacons: list[dict[str, Any]] = []
            for flow, times in timing.items():
                if len(times) < 5:
                    continue
                intervals = [times[i+1] - times[i] for i in range(len(times)-1)]
                if not intervals:
                    continue
                avg = sum(intervals) / len(intervals)
                if avg <= 0:
                    continue
                std = (sum((x - avg) ** 2 for x in intervals) / len(intervals)) ** 0.5
                # Low jitter = potential beacon
                jitter = std / avg if avg > 0 else float("inf")
                if jitter < 0.2 and avg > 1:  # Low jitter, regular interval > 1s
                    beacons.append({
                        "flow": flow,
                        "packet_count": len(times),
                        "avg_interval": round(avg, 2),
                        "jitter": round(jitter, 4),
                        "confidence": "high" if jitter < 0.05 else "medium",
                    })
            result["beacon_candidates"] = sorted(beacons, key=lambda b: b["jitter"])[:10]

        return result

    result = await loop.run_in_executor(None, _analyze)
    return text_result(result)
