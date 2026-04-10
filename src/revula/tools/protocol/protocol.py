"""
Revula Protocol RE — network protocol analysis, PCAP dissection,
protocol structure inference, and protocol fuzzing.
"""

from __future__ import annotations

import logging
import struct
from typing import Any

from revula.sandbox import safe_subprocess, validate_path
from revula.tools import TOOL_REGISTRY, error_result, text_result

logger = logging.getLogger(__name__)


@TOOL_REGISTRY.register(
    name="re_protocol_pcap",
    description=(
        "Analyze PCAP/PCAPNG captures: protocol breakdown, stream extraction, "
        "statistics, filtering, conversation analysis."
    ),
    category="protocol",
    requires_tools=["tshark", "capinfos"],
    input_schema={
        "type": "object",
        "required": ["pcap_path", "action"],
        "properties": {
            "pcap_path": {
                "type": "string",
                "description": "Path to PCAP/PCAPNG file.",
            },
            "action": {
                "type": "string",
                "enum": [
                    "summary", "protocols", "conversations",
                    "streams", "filter", "extract_files",
                    "dns_queries", "http_requests",
                ],
                "description": "PCAP analysis action.",
            },
            "filter": {
                "type": "string",
                "description": "Display filter (Wireshark syntax).",
            },
            "stream_index": {
                "type": "integer",
                "description": "TCP stream index for streams action.",
            },
            "max_packets": {
                "type": "integer",
                "description": "Max packets to analyze. Default: 1000.",
            },
        },
    },
)
async def handle_pcap(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """PCAP analysis via tshark."""
    pcap_path = arguments["pcap_path"]
    action = arguments["action"]
    display_filter = arguments.get("filter", "")
    stream_index = arguments.get("stream_index")
    max_packets = arguments.get("max_packets", 1000)
    config = arguments.get("__config__")
    allowed_dirs = config.security.allowed_dirs if config else None
    validate_path(pcap_path, allowed_dirs=allowed_dirs)

    if action == "summary":
        proc = await safe_subprocess(
            ["capinfos", pcap_path], timeout=30,
        )
        return text_result({
            "action": "summary",
            "output": proc.stdout[:5000] if proc.success else proc.stderr,
        })

    elif action == "protocols":
        proc = await safe_subprocess(
            ["tshark", "-r", pcap_path, "-q", "-z", "io,phs"],
            timeout=60,
        )
        return text_result({
            "action": "protocols",
            "hierarchy": proc.stdout[:5000] if proc.success else proc.stderr,
        })

    elif action == "conversations":
        proc = await safe_subprocess(
            ["tshark", "-r", pcap_path, "-q", "-z", "conv,tcp"],
            timeout=60,
        )
        return text_result({
            "action": "conversations",
            "tcp": proc.stdout[:5000] if proc.success else proc.stderr,
        })

    elif action == "streams":
        if stream_index is not None:
            proc = await safe_subprocess(
                ["tshark", "-r", pcap_path, "-q",
                 "-z", f"follow,tcp,ascii,{stream_index}"],
                timeout=60,
            )
        else:
            proc = await safe_subprocess(
                ["tshark", "-r", pcap_path, "-T", "fields",
                 "-e", "tcp.stream", "-Y", "tcp", "-c", str(max_packets)],
                timeout=60,
            )
        return text_result({
            "action": "streams",
            "output": proc.stdout[:8000] if proc.success else proc.stderr,
        })

    elif action == "filter":
        if not display_filter:
            return error_result("filter required for filter action")
        proc = await safe_subprocess(
            ["tshark", "-r", pcap_path, "-Y", display_filter,
             "-c", str(max_packets)],
            timeout=60,
        )
        return text_result({
            "action": "filter",
            "filter": display_filter,
            "output": proc.stdout[:8000] if proc.success else proc.stderr,
        })

    elif action == "extract_files":
        import tempfile
        export_dir = tempfile.mkdtemp(prefix="revula_pcap_exports_")
        proc = await safe_subprocess(
            ["tshark", "-r", pcap_path, "-q",
             "--export-objects", f"http,{export_dir}"],
            timeout=120,
        )
        return text_result({
            "action": "extract_files",
            "export_dir": export_dir,
            "output": proc.stdout[:5000] if proc.success else proc.stderr,
        })

    elif action == "dns_queries":
        proc = await safe_subprocess(
            ["tshark", "-r", pcap_path, "-Y", "dns.flags.response == 0",
             "-T", "fields", "-e", "dns.qry.name", "-e", "dns.qry.type",
             "-c", str(max_packets)],
            timeout=60,
        )
        queries = []
        if proc.success:
            for line in proc.stdout.strip().split("\n"):
                parts = line.split("\t")
                if len(parts) >= 1:
                    queries.append({
                        "domain": parts[0],
                        "type": parts[1] if len(parts) > 1 else "A",
                    })
        return text_result({
            "action": "dns_queries",
            "queries": queries[:200],
            "total": len(queries),
        })

    elif action == "http_requests":
        proc = await safe_subprocess(
            ["tshark", "-r", pcap_path, "-Y", "http.request",
             "-T", "fields",
             "-e", "http.request.method",
             "-e", "http.host",
             "-e", "http.request.uri",
             "-c", str(max_packets)],
            timeout=60,
        )
        requests = []
        if proc.success:
            for line in proc.stdout.strip().split("\n"):
                parts = line.split("\t")
                if len(parts) >= 3:
                    requests.append({
                        "method": parts[0],
                        "host": parts[1],
                        "uri": parts[2],
                    })
        return text_result({
            "action": "http_requests",
            "requests": requests[:200],
            "total": len(requests),
        })

    else:
        return error_result(f"Unknown PCAP action: {action}")


@TOOL_REGISTRY.register(
    name="re_protocol_dissect",
    description=(
        "Dissect and analyze unknown binary protocols: field inference, "
        "length/type detection, structure extraction from raw data."
    ),
    category="protocol",
    input_schema={
        "type": "object",
        "required": ["action"],
        "properties": {
            "action": {
                "type": "string",
                "enum": [
                    "analyze_packet", "find_length_fields",
                    "detect_structure", "compare_packets",
                ],
                "description": "Dissection action.",
            },
            "hex_data": {
                "type": "string",
                "description": "Hex-encoded packet data.",
            },
            "hex_packets": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Multiple hex packets for comparison.",
            },
        },
    },
)
async def handle_protocol_dissect(
    arguments: dict[str, Any],
) -> list[dict[str, Any]]:
    """Protocol structure dissection."""
    action = arguments["action"]
    hex_data = arguments.get("hex_data", "")
    hex_packets: list[str] = arguments.get("hex_packets", [])

    if action == "analyze_packet":
        if not hex_data:
            return error_result("hex_data required")
        data = bytes.fromhex(hex_data.replace(" ", ""))
        analysis = _analyze_packet(data)
        return text_result({"action": "analyze_packet", **analysis})

    elif action == "find_length_fields":
        if not hex_data:
            return error_result("hex_data required")
        data = bytes.fromhex(hex_data.replace(" ", ""))
        length_fields = _find_length_fields(data)
        return text_result({
            "action": "find_length_fields",
            "candidates": length_fields,
        })

    elif action == "detect_structure":
        if not hex_data:
            return error_result("hex_data required")
        data = bytes.fromhex(hex_data.replace(" ", ""))
        structure = _detect_structure(data)
        return text_result({"action": "detect_structure", "structure": structure})

    elif action == "compare_packets":
        if len(hex_packets) < 2:
            return error_result("At least 2 hex_packets required for comparison")
        packets = [bytes.fromhex(h.replace(" ", "")) for h in hex_packets]
        comparison = _compare_packets(packets)
        return text_result({"action": "compare_packets", **comparison})

    else:
        return error_result(f"Unknown dissect action: {action}")


@TOOL_REGISTRY.register(
    name="re_protocol_fuzz",
    description=(
        "Protocol fuzzing: generate mutated packets, boundary testing, "
        "field enumeration for network protocol testing."
    ),
    category="protocol",
    input_schema={
        "type": "object",
        "required": ["action"],
        "properties": {
            "action": {
                "type": "string",
                "enum": [
                    "mutate_packet", "boundary_values",
                    "field_enumerate", "generate_corpus",
                ],
                "description": "Fuzzing action.",
            },
            "hex_data": {
                "type": "string",
                "description": "Base packet in hex.",
            },
            "field_offset": {
                "type": "integer",
                "description": "Offset of field to fuzz.",
            },
            "field_size": {
                "type": "integer",
                "description": "Size of field in bytes.",
            },
            "mutations": {
                "type": "integer",
                "description": "Number of mutations. Default: 20.",
            },
        },
    },
)
async def handle_protocol_fuzz(
    arguments: dict[str, Any],
) -> list[dict[str, Any]]:
    """Protocol fuzzing helpers."""
    action = arguments["action"]
    hex_data = arguments.get("hex_data", "")
    field_offset = arguments.get("field_offset", 0)
    field_size = arguments.get("field_size", 1)
    mutations = arguments.get("mutations", 20)

    if action == "mutate_packet":
        if not hex_data:
            return error_result("hex_data required")
        data = bytes.fromhex(hex_data.replace(" ", ""))
        mutated = _mutate_packet(data, mutations)
        return text_result({
            "action": "mutate_packet",
            "original": hex_data,
            "mutations": mutated,
        })

    elif action == "boundary_values":
        boundaries = _boundary_values(field_size)
        return text_result({
            "action": "boundary_values",
            "field_size": field_size,
            "values": boundaries,
        })

    elif action == "field_enumerate":
        if not hex_data:
            return error_result("hex_data required")
        data = bytes.fromhex(hex_data.replace(" ", ""))
        enumerated = _enumerate_field(data, field_offset, field_size, mutations)
        return text_result({
            "action": "field_enumerate",
            "packets": enumerated,
        })

    elif action == "generate_corpus":
        if not hex_data:
            return error_result("hex_data required")
        data = bytes.fromhex(hex_data.replace(" ", ""))
        corpus = _generate_corpus(data, mutations)
        return text_result({
            "action": "generate_corpus",
            "corpus_size": len(corpus),
            "corpus": corpus,
        })

    else:
        return error_result(f"Unknown fuzz action: {action}")


def _analyze_packet(data: bytes) -> dict[str, Any]:
    """Analyze packet structure heuristically."""
    analysis: dict[str, Any] = {
        "length": len(data),
        "hex": data.hex(),
    }

    # Check for common header patterns
    if len(data) >= 2:
        analysis["first_2_bytes"] = {
            "uint16_be": struct.unpack(">H", data[:2])[0],
            "uint16_le": struct.unpack("<H", data[:2])[0],
        }

    if len(data) >= 4:
        analysis["first_4_bytes"] = {
            "uint32_be": struct.unpack(">I", data[:4])[0],
            "uint32_le": struct.unpack("<I", data[:4])[0],
        }

    # Byte frequency analysis
    freq: dict[int, int] = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    analysis["unique_bytes"] = len(freq)
    analysis["most_common"] = sorted(
        freq.items(), key=lambda x: -x[1]
    )[:5]

    # Printable ratio
    printable = sum(1 for b in data if 0x20 <= b <= 0x7e)
    analysis["printable_ratio"] = f"{printable / len(data):.2%}"

    # Null byte positions
    null_positions = [i for i, b in enumerate(data) if b == 0]
    if null_positions:
        analysis["null_positions"] = null_positions[:20]

    return analysis


def _find_length_fields(data: bytes) -> list[dict[str, Any]]:
    """Find potential length fields in packet data."""
    candidates: list[dict[str, Any]] = []
    pkt_len = len(data)

    for offset in range(len(data) - 1):
        # 1-byte length
        val = data[offset]
        remaining = pkt_len - offset - 1
        if val in (remaining, pkt_len):
            candidates.append({
                "offset": offset,
                "size": 1,
                "value": val,
                "interpretation": "remaining" if val == remaining else "total",
            })

        # 2-byte length (big-endian and little-endian)
        if offset < len(data) - 1:
            val_be = struct.unpack(">H", data[offset:offset + 2])[0]
            val_le = struct.unpack("<H", data[offset:offset + 2])[0]
            remaining2 = pkt_len - offset - 2

            for val, endian in [(val_be, "big"), (val_le, "little")]:
                if val in (remaining2, pkt_len, pkt_len - offset):
                    candidates.append({
                        "offset": offset,
                        "size": 2,
                        "value": val,
                        "endian": endian,
                        "interpretation": "length_field",
                    })

    return candidates[:20]


def _detect_structure(data: bytes) -> list[dict[str, Any]]:
    """Infer protocol structure from packet."""
    fields: list[dict[str, Any]] = []
    offset = 0

    while offset < len(data):
        # Check for string-like sequences
        if 0x20 <= data[offset] <= 0x7e:
            end = offset
            while end < len(data) and 0x20 <= data[end] <= 0x7e:
                end += 1
            if end - offset >= 3:
                fields.append({
                    "offset": offset,
                    "size": end - offset,
                    "type": "string",
                    "value": data[offset:end].decode("ascii"),
                })
                offset = end
                continue

        # Check for null-terminated fields
        if data[offset] == 0x00:
            null_run = 0
            while offset + null_run < len(data) and data[offset + null_run] == 0:
                null_run += 1
            fields.append({
                "offset": offset,
                "size": null_run,
                "type": "padding/null",
            })
            offset += null_run
            continue

        # Treat as binary field
        fields.append({
            "offset": offset,
            "size": 1,
            "type": "byte",
            "value": f"0x{data[offset]:02x}",
        })
        offset += 1

    return fields[:50]


def _compare_packets(packets: list[bytes]) -> dict[str, Any]:
    """Compare multiple packets to find static/variable fields."""
    min_len = min(len(p) for p in packets)

    static_bytes: list[int] = []
    variable_bytes: list[int] = []

    for i in range(min_len):
        values = {p[i] for p in packets}
        if len(values) == 1:
            static_bytes.append(i)
        else:
            variable_bytes.append(i)

    return {
        "packet_count": len(packets),
        "min_length": min_len,
        "max_length": max(len(p) for p in packets),
        "static_byte_positions": static_bytes[:50],
        "variable_byte_positions": variable_bytes[:50],
        "static_ratio": f"{len(static_bytes) / min_len:.2%}" if min_len else "0%",
        "static_content": bytes(
            packets[0][i] for i in static_bytes[:50]
        ).hex() if static_bytes else "",
    }


def _mutate_packet(data: bytes, count: int) -> list[str]:
    """Generate mutated versions of a packet."""
    import random
    mutations: list[str] = []

    for i in range(count):
        mutant = bytearray(data)
        mutation_type = i % 5

        if mutation_type == 0:
            # Bit flip
            pos = random.randint(0, len(mutant) - 1)
            bit = random.randint(0, 7)
            mutant[pos] ^= 1 << bit
        elif mutation_type == 1:
            # Byte replacement
            pos = random.randint(0, len(mutant) - 1)
            mutant[pos] = random.randint(0, 255)
        elif mutation_type == 2:
            # Insert byte
            pos = random.randint(0, len(mutant))
            mutant.insert(pos, random.randint(0, 255))
        elif mutation_type == 3:
            # Delete byte
            if len(mutant) > 1:
                pos = random.randint(0, len(mutant) - 1)
                del mutant[pos]
        else:
            # Boundary value at random position
            pos = random.randint(0, len(mutant) - 1)
            mutant[pos] = random.choice([0x00, 0xFF, 0x7F, 0x80])

        mutations.append(bytes(mutant).hex())

    return mutations


def _boundary_values(field_size: int) -> list[dict[str, str]]:
    """Generate boundary values for a field."""
    values: list[dict[str, str]] = []

    if field_size == 1:
        for v, desc in [(0, "min"), (1, "min+1"), (0x7E, "max_printable"),
                        (0x7F, "max_signed"), (0x80, "min_negative"),
                        (0xFE, "max-1"), (0xFF, "max")]:
            values.append({"value": f"0x{v:02x}", "description": desc})
    elif field_size == 2:
        for v, desc in [(0, "min"), (1, "min+1"), (0x7FFF, "max_signed"),
                        (0x8000, "min_negative"), (0xFFFE, "max-1"),
                        (0xFFFF, "max")]:
            values.append({"value": f"0x{v:04x}", "description": desc})
    elif field_size == 4:
        for v, desc in [(0, "min"), (1, "min+1"), (0x7FFFFFFF, "max_signed"),
                        (0x80000000, "min_negative"), (0xFFFFFFFE, "max-1"),
                        (0xFFFFFFFF, "max")]:
            values.append({"value": f"0x{v:08x}", "description": desc})

    return values


def _enumerate_field(
    data: bytes, offset: int, size: int, count: int,
) -> list[str]:
    """Generate packets with enumerated field values."""
    packets: list[str] = []
    max_val = min((1 << (size * 8)) - 1, count)

    for i in range(min(count, max_val + 1)):
        mutant = bytearray(data)
        val_bytes = i.to_bytes(size, "big")
        for j in range(size):
            if offset + j < len(mutant):
                mutant[offset + j] = val_bytes[j]
        packets.append(bytes(mutant).hex())

    return packets


def _generate_corpus(data: bytes, count: int) -> list[str]:
    """Generate a fuzzing corpus from a seed packet."""
    import random
    corpus: list[str] = [data.hex()]

    # Add boundary mutations for each byte position
    for pos in range(min(len(data), count)):
        for val in (0x00, 0xFF):
            mutant = bytearray(data)
            mutant[pos] = val
            corpus.append(bytes(mutant).hex())

    # Add random mutations
    for _ in range(count):
        mutant = bytearray(data)
        num_mutations = random.randint(1, 3)
        for _ in range(num_mutations):
            pos = random.randint(0, len(mutant) - 1)
            mutant[pos] = random.randint(0, 255)
        corpus.append(bytes(mutant).hex())

    return corpus[:count]
