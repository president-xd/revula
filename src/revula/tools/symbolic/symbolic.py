"""
Revula Symbolic Execution — angr and Triton integration.

Provides: path exploration, constraint solving, vulnerability finding,
and directed symbolic execution (DSE).
"""

from __future__ import annotations

import logging
from typing import Any

from revula.sandbox import validate_binary_path
from revula.tools import TOOL_REGISTRY, error_result, text_result

logger = logging.getLogger(__name__)

try:
    import angr
    import claripy

    ANGR_AVAILABLE = True
except ImportError:
    ANGR_AVAILABLE = False

try:
    import triton as _triton

    _ = (_triton.ARCH, _triton.TritonContext)
except Exception:
    TRITON_AVAILABLE = False
else:
    TRITON_AVAILABLE = True


# ---------------------------------------------------------------------------
# angr Integration
# ---------------------------------------------------------------------------


@TOOL_REGISTRY.register(
    name="re_angr_explore",
    description=(
        "Use angr symbolic execution to explore paths in a binary. "
        "Can find paths to a target address while avoiding others. "
        "Solves constraints to generate concrete inputs."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "binary_path": {"type": "string"},
            "find": {
                "type": ["string", "array"],
                "description": "Target address(es) to reach (hex). Can be single address or array.",
            },
            "avoid": {
                "type": ["string", "array"],
                "description": "Address(es) to avoid (hex).",
            },
            "start_address": {
                "type": "string",
                "description": "Start address (hex). Default: entry point.",
            },
            "stdin_length": {
                "type": "integer",
                "description": "Length of symbolic stdin to create.",
                "default": 64,
            },
            "argc": {
                "type": "integer",
                "description": "Number of symbolic argv arguments.",
            },
            "timeout": {
                "type": "integer",
                "default": 300,
                "description": "Exploration timeout in seconds.",
            },
            "strategy": {
                "type": "string",
                "enum": ["bfs", "dfs", "explorer"],
                "default": "explorer",
            },
        },
        "required": ["binary_path", "find"],
    },
    category="symbolic",
    requires_modules=["angr"],
)
async def handle_angr_explore(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Symbolic exploration with angr."""
    if not ANGR_AVAILABLE:
        return error_result("angr not installed. pip install angr")

    binary_path = arguments["binary_path"]
    find_addrs = arguments["find"]
    avoid_addrs = arguments.get("avoid", [])
    start_addr = arguments.get("start_address")
    stdin_length = arguments.get("stdin_length", 64)
    timeout_secs = arguments.get("timeout", 300)
    arguments.get("strategy", "explorer")

    config = arguments.get("__config__")
    allowed_dirs = config.security.allowed_dirs if config else None
    file_path = validate_binary_path(binary_path, allowed_dirs=allowed_dirs)

    # Parse addresses
    def parse_addrs(val: str | list[str]) -> list[int]:
        if isinstance(val, str):
            return [int(val, 16) if val.startswith("0x") else int(val)]
        return [int(a, 16) if isinstance(a, str) and a.startswith("0x") else int(a) for a in val]

    find_list = parse_addrs(find_addrs)
    avoid_list = parse_addrs(avoid_addrs) if avoid_addrs else []

    # Create angr project
    proj = angr.Project(str(file_path), auto_load_libs=False)

    # Set up initial state
    if start_addr:
        addr = int(start_addr, 16) if start_addr.startswith("0x") else int(start_addr)
        state = proj.factory.blank_state(addr=addr)
    else:
        state = proj.factory.entry_state(
            stdin=angr.SimFileStream(
                name="stdin",
                content=claripy.BVS("stdin", stdin_length * 8),
                has_end=False,
            )
        )

    # Create simulation manager
    simgr = proj.factory.simulation_manager(state)

    # Explore
    simgr.explore(
        find=find_list,
        avoid=avoid_list,
        timeout=timeout_secs,
    )

    results: list[dict[str, Any]] = []

    for found_state in simgr.found:
        result: dict[str, Any] = {
            "address": f"0x{found_state.addr:x}",
            "path_length": found_state.history.depth,
        }

        # Try to get concrete stdin
        try:
            stdin_data = found_state.posix.dumps(0)
            result["stdin"] = stdin_data.hex()
            result["stdin_ascii"] = stdin_data.decode("ascii", errors="replace")
        except Exception as e:
            logger.debug("Unable to extract concrete stdin from symbolic state: %s", e)

        # Try to get stdout
        try:
            stdout_data = found_state.posix.dumps(1)
            result["stdout"] = stdout_data.decode("ascii", errors="replace")
        except Exception as e:
            logger.debug("Unable to extract concrete stdout from symbolic state: %s", e)

        results.append(result)

    return text_result({
        "binary": str(file_path),
        "find_addresses": [f"0x{a:x}" for a in find_list],
        "avoid_addresses": [f"0x{a:x}" for a in avoid_list],
        "paths_found": len(results),
        "results": results,
        "stats": {
            "active": len(simgr.active),
            "deadended": len(simgr.deadended),
            "errored": len(simgr.errored) if hasattr(simgr, "errored") else 0,
        },
    })


@TOOL_REGISTRY.register(
    name="re_angr_cfg",
    description=(
        "Generate a Control Flow Graph using angr's CFG analysis. "
        "Returns function list, call graph, and basic block information."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "binary_path": {"type": "string"},
            "cfg_type": {
                "type": "string",
                "enum": ["fast", "accurate"],
                "default": "fast",
                "description": "CFGFast (heuristic) or CFGEmulated (accurate but slow).",
            },
            "function_filter": {
                "type": "string",
                "description": "Filter functions by name substring.",
            },
        },
        "required": ["binary_path"],
    },
    category="symbolic",
    requires_modules=["angr"],
)
async def handle_angr_cfg(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Generate CFG with angr."""
    if not ANGR_AVAILABLE:
        return error_result("angr not installed")

    binary_path = arguments["binary_path"]
    cfg_type = arguments.get("cfg_type", "fast")
    func_filter = arguments.get("function_filter")

    config = arguments.get("__config__")
    allowed_dirs = config.security.allowed_dirs if config else None
    file_path = validate_binary_path(binary_path, allowed_dirs=allowed_dirs)

    proj = angr.Project(str(file_path), auto_load_libs=False)

    proj.analyses.CFGFast() if cfg_type == "fast" else proj.analyses.CFGEmulated()

    functions: list[dict[str, Any]] = []
    for addr, func in proj.kb.functions.items():
        if func_filter and func_filter.lower() not in (func.name or "").lower():
            continue
        functions.append({
            "address": f"0x{addr:x}",
            "name": func.name,
            "size": func.size,
            "blocks": len(list(func.blocks)),
            "is_simprocedure": func.is_simprocedure,
            "is_plt": func.is_plt,
            "calling_convention": str(func.calling_convention) if func.calling_convention else None,
        })

    # Call graph edges
    call_graph_edges: list[dict[str, str]] = []
    for src, dst in proj.kb.callgraph.edges():
        src_func = proj.kb.functions.get(src)
        dst_func = proj.kb.functions.get(dst)
        if src_func and dst_func:
            call_graph_edges.append({
                "from": f"{src_func.name} (0x{src:x})",
                "to": f"{dst_func.name} (0x{dst:x})",
            })

    return text_result({
        "binary": str(file_path),
        "cfg_type": cfg_type,
        "functions_count": len(functions),
        "functions": functions[:500],
        "call_graph_edges": call_graph_edges[:500],
    })


@TOOL_REGISTRY.register(
    name="re_angr_vuln_scan",
    description=(
        "Use angr to find potential vulnerabilities: "
        "buffer overflows, format strings, command injection, etc. "
        "Checks for unconstrained states and dangerous function calls."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "binary_path": {"type": "string"},
            "vuln_types": {
                "type": "array",
                "items": {
                    "type": "string",
                    "enum": ["overflow", "format_string", "command_injection", "all"],
                },
                "default": ["all"],
            },
            "timeout": {"type": "integer", "default": 300},
        },
        "required": ["binary_path"],
    },
    category="symbolic",
    requires_modules=["angr"],
)
async def handle_angr_vuln_scan(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Scan for vulnerabilities with angr."""
    if not ANGR_AVAILABLE:
        return error_result("angr not installed")

    binary_path = arguments["binary_path"]
    vuln_types = arguments.get("vuln_types", ["all"])
    timeout_secs = arguments.get("timeout", 300)

    config = arguments.get("__config__")
    allowed_dirs = config.security.allowed_dirs if config else None
    file_path = validate_binary_path(binary_path, allowed_dirs=allowed_dirs)

    proj = angr.Project(str(file_path), auto_load_libs=False)
    cfg = proj.analyses.CFGFast()

    vulnerabilities: list[dict[str, Any]] = []
    do_all = "all" in vuln_types

    # Dangerous functions to check
    dangerous_funcs: dict[str, str] = {
        "strcpy": "Buffer overflow — no bounds checking",
        "strcat": "Buffer overflow — no bounds checking",
        "gets": "Buffer overflow — reads until newline",
        "sprintf": "Buffer overflow — no size limit",
        "scanf": "Buffer overflow — no field width limit",
        "system": "Command injection — if input controlled",
        "popen": "Command injection — if input controlled",
        "execve": "Command injection",
        "printf": "Format string — if format controlled",
        "fprintf": "Format string — if format controlled",
        "syslog": "Format string — if format controlled",
    }

    for func_name, vuln_desc in dangerous_funcs.items():
        func = proj.kb.functions.function(name=func_name)
        if func is None:
            # Check PLT
            for _addr, f in proj.kb.functions.items():
                if f.name == func_name:
                    func = f
                    break

        if func:
            # Find callers
            callers = list(cfg.kb.callgraph.predecessors(func.addr))
            for caller_addr in callers:
                caller_func = proj.kb.functions.get(caller_addr)
                vulnerabilities.append({
                    "type": "dangerous_function",
                    "function": func_name,
                    "description": vuln_desc,
                    "caller": caller_func.name if caller_func else f"0x{caller_addr:x}",
                    "caller_address": f"0x{caller_addr:x}",
                    "severity": "high" if func_name in ("gets", "system") else "medium",
                })

    # Check for unconstrained (symbolic IP)
    if do_all or "overflow" in vuln_types:
        state = proj.factory.entry_state(
            stdin=angr.SimFileStream(
                name="stdin",
                content=claripy.BVS("stdin", 256 * 8),
            )
        )
        simgr = proj.factory.simulation_manager(state)

        # Quick exploration for unconstrained states
        try:
            simgr.run(until=lambda sm: len(sm.unconstrained) > 0, timeout=min(timeout_secs, 60))
            for unc_state in simgr.unconstrained:
                vulnerabilities.append({
                    "type": "unconstrained_ip",
                    "description": "Symbolic instruction pointer — potential control flow hijack",
                    "ip": str(unc_state.regs.ip),
                    "severity": "critical",
                })
        except Exception as e:
            logger.debug(f"Unconstrained exploration failed: {e}")

    return text_result({
        "binary": str(file_path),
        "vulnerabilities_found": len(vulnerabilities),
        "vulnerabilities": vulnerabilities,
    })


# ---------------------------------------------------------------------------
# Triton DSE
# ---------------------------------------------------------------------------


async def handle_triton_dse(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """DSE with Triton."""
    try:
        from triton import (
            ARCH,
            MODE,
            OPCODE,
            Instruction,
            MemoryAccess,
            TritonContext,
        )
    except ImportError:
        return error_result("triton not installed. pip install triton")

    binary_path = arguments["binary_path"]
    target_addr_str = arguments.get("target_address")
    start_addr_str = arguments.get("start_address")
    symbolic_mem = arguments.get("symbolic_memory", {})
    max_insns = arguments.get("max_instructions", 10000)

    config = arguments.get("__config__")
    allowed_dirs = config.security.allowed_dirs if config else None
    file_path = validate_binary_path(binary_path, allowed_dirs=allowed_dirs)

    data = file_path.read_bytes()

    # Initialize Triton
    ctx = TritonContext(ARCH.X86_64)
    ctx.setMode(MODE.ALIGNED_MEMORY, True)

    # Parse ELF/PE with LIEF for proper segment loading
    base_addr = 0x400000
    entry_point = base_addr
    try:
        import lief
        binary = lief.parse(str(file_path))
        if binary is not None:
            # Load segments at their virtual addresses
            if hasattr(binary, 'segments'):
                for seg in binary.segments:
                    if seg.virtual_size > 0 and len(seg.content) > 0:
                        ctx.setConcreteMemoryAreaValue(
                            seg.virtual_address, bytes(seg.content)
                        )
            elif hasattr(binary, 'sections'):
                for sec in binary.sections:
                    if sec.virtual_size > 0 and len(sec.content) > 0:
                        ctx.setConcreteMemoryAreaValue(
                            sec.virtual_address, bytes(sec.content)
                        )
            # Get entry point from binary
            if hasattr(binary, 'entrypoint') and binary.entrypoint:
                entry_point = binary.entrypoint
            # Detect architecture
            if hasattr(binary, 'header'):
                hdr = binary.header
                if hasattr(hdr, 'machine_type'):
                    mt = str(hdr.machine_type)
                    if '386' in mt or 'I386' in mt:
                        ctx = TritonContext(ARCH.X86)
                        ctx.setMode(MODE.ALIGNED_MEMORY, True)
                        # Reload segments for new context
                        if hasattr(binary, 'segments'):
                            for seg in binary.segments:
                                if seg.virtual_size > 0 and len(seg.content) > 0:
                                    ctx.setConcreteMemoryAreaValue(
                                        seg.virtual_address, bytes(seg.content)
                                    )
        else:
            # Fallback: load raw bytes
            ctx.setConcreteMemoryAreaValue(base_addr, data)
    except ImportError:
        # No LIEF — load raw bytes at base address
        ctx.setConcreteMemoryAreaValue(base_addr, data)

    # Set up symbolic memory regions
    for addr_str, size in symbolic_mem.items():
        addr = int(addr_str, 16) if isinstance(addr_str, str) and addr_str.startswith("0x") else int(addr_str)
        for i in range(size):
            ctx.symbolizeMemory(MemoryAccess(addr + i, 1))

    # Set up stack
    stack_addr = 0x7FFFFF00
    ctx.setConcreteRegisterValue(ctx.registers.rsp, stack_addr)
    ctx.setConcreteRegisterValue(ctx.registers.rbp, stack_addr)

    # Start address
    if start_addr_str:
        pc = int(start_addr_str, 16) if start_addr_str.startswith("0x") else int(start_addr_str)
    else:
        pc = entry_point

    target_addr = None
    if target_addr_str:
        target_addr = int(target_addr_str, 16) if target_addr_str.startswith("0x") else int(target_addr_str)

    # Execute
    path_constraints: list[dict[str, Any]] = []
    instructions_executed = 0
    target_reached = False

    for _ in range(max_insns):
        opcode = ctx.getConcreteMemoryAreaValue(pc, 16)
        insn = Instruction(pc, opcode)
        ctx.processing(insn)

        instructions_executed += 1
        pc = int(ctx.getConcreteRegisterValue(ctx.registers.rip))

        if target_addr and pc == target_addr:
            target_reached = True
            break

        # Collect path constraints
        if insn.isBranch():
            path_constraints.append({
                "address": f"0x{insn.getAddress():x}",
                "taken": insn.isConditionTaken(),
                "mnemonic": insn.getDisassembly(),
            })

        # Break on ret/hlt
        if insn.getType() in (OPCODE.X86.RET, OPCODE.X86.HLT):
            break

    # Try to solve constraints
    solutions: list[dict[str, Any]] = []
    if target_reached:
        # Get symbolic variables and their solutions
        for _sym_var in ctx.getSymbolicVariables().values():
            model = ctx.getModel(ctx.getPathPredicate())
            if model:
                for var_id, sol in model.items():
                    solutions.append({
                        "variable": str(ctx.getSymbolicVariable(var_id)),
                        "value": f"0x{sol.getValue():x}",
                    })
                break

    return text_result({
        "binary": str(file_path),
        "instructions_executed": instructions_executed,
        "target_reached": target_reached,
        "path_constraints": path_constraints[:100],
        "solutions": solutions,
    })


if TRITON_AVAILABLE:
    TOOL_REGISTRY.register(
        name="re_triton_dse",
        description=(
            "Dynamic Symbolic Execution using Triton. "
            "Concretely executes code while maintaining symbolic state. "
            "Can solve for inputs that reach specific conditions."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "binary_path": {"type": "string"},
                "target_address": {
                    "type": "string",
                    "description": "Address to reach (hex).",
                },
                "start_address": {
                    "type": "string",
                    "description": "Address to start from (hex).",
                },
                "symbolic_memory": {
                    "type": "object",
                    "description": "Memory addresses to symbolize: {address: size}.",
                },
                "max_instructions": {"type": "integer", "default": 10000},
            },
            "required": ["binary_path"],
        },
        category="symbolic",
    )(handle_triton_dse)
else:
    logger.info("Skipping re_triton_dse registration: Triton backend unavailable")
