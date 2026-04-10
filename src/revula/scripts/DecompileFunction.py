# Ghidra headless script: DecompileFunction.py
# Usage: analyzeHeadless ... -postScript DecompileFunction.py <function_name_or_addr>
#
# Decompiles the specified function and writes:
#   1. C pseudocode to <project_dir>/<function>_decompiled.c
#   2. Summary to stdout for capture
#
# @category Revula
# @author Revula MCP

import os
import sys

from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.util.task import ConsoleTaskMonitor


def get_function(program, identifier):
    """Find function by name or address."""
    fm = program.getFunctionManager()

    # Try as address first
    try:
        addr_str = identifier
        if addr_str.startswith("0x") or addr_str.startswith("0X"):
            addr_str = addr_str[2:]
        addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(long(addr_str, 16))
        func = fm.getFunctionAt(addr)
        if func is not None:
            return func
        # Maybe it's inside a function
        func = fm.getFunctionContaining(addr)
        if func is not None:
            return func
    except ValueError:
        addr = None
    except Exception as e:
        println("WARNING: Address lookup failed: " + str(e))

    # Try as name
    funcs = list(fm.getFunctions(True))
    for f in funcs:
        if f.getName() == identifier:
            return f

    # Try partial match
    for f in funcs:
        if identifier.lower() in f.getName().lower():
            return f

    return None


def decompile_function(program, func, monitor):
    """Decompile a single function and return C code."""
    decomp = DecompInterface()
    opts = DecompileOptions()
    decomp.setOptions(opts)
    decomp.openProgram(program)

    result = decomp.decompileFunction(func, 120, monitor)

    if result is None or not result.getDecompiledFunction():
        # Try without timeout constraint
        result = decomp.decompileFunction(func, 0, monitor)

    if result is not None and result.getDecompiledFunction():
        return result.getDecompiledFunction().getC()

    if result is not None and result.getErrorMessage():
        return "// Decompilation error: " + result.getErrorMessage()

    return None


def main():
    args = getScriptArgs()
    if len(args) < 1:
        println("ERROR: No function specified. Usage: -postScript DecompileFunction.py <function>")
        return

    func_identifier = args[0]
    monitor = ConsoleTaskMonitor()

    program = currentProgram
    if program is None:
        println("ERROR: No program loaded")
        return

    println("Revula: Looking for function: " + func_identifier)

    func = get_function(program, func_identifier)
    if func is None:
        # If function not found, list available functions
        fm = program.getFunctionManager()
        all_funcs = list(fm.getFunctions(True))
        println("ERROR: Function '" + func_identifier + "' not found.")
        println("Available functions (" + str(len(all_funcs)) + "):")
        for f in all_funcs[:50]:
            println("  " + f.getName() + " @ 0x" + str(f.getEntryPoint()))
        if len(all_funcs) > 50:
            println("  ... and " + str(len(all_funcs) - 50) + " more")
        return

    println("Revula: Decompiling " + func.getName() + " @ " + str(func.getEntryPoint()))

    code = decompile_function(program, func, monitor)

    if code is None:
        println("ERROR: Decompilation returned no result")
        return

    # Print to stdout first (always works, captured by safe_subprocess)
    println("/* Function: " + func.getName() + " */")
    println(code)
    println("/* End of decompilation */")

    # Try to write output file (best-effort)
    try:
        # Use script args if output dir provided, otherwise use /tmp
        output_dir = None
        if len(args) >= 2:
            output_dir = args[1]
        else:
            # Try to get project directory
            try:
                locator = program.getDomainFile().getProjectLocator()
                if locator is not None:
                    output_dir = str(locator.getLocation())
            except Exception as e:
                println("WARNING: Could not resolve project location: " + str(e))

        if output_dir is None:
            import tempfile
            output_dir = tempfile.gettempdir()

        output_path = os.path.join(output_dir, func_identifier + "_decompiled.c")
        with open(output_path, "w") as f:
            f.write("// Decompiled by Ghidra via Revula MCP\n")
            f.write("// Binary: " + str(program.getExecutablePath()) + "\n")
            f.write("// Function: " + func.getName() + " @ " + str(func.getEntryPoint()) + "\n\n")
            f.write(code)
        println("Revula: Output written to " + output_path)
    except Exception as e:
        println("WARNING: Could not write output file: " + str(e))


main()
