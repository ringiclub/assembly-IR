import idaapi
import idautils
import idc
import ida_hexrays

def get_funcs(self) -> list:
    functions = []
    for func_ea in idautils.Functions():
        func_name = idc.get_func_name(func_ea)
        functions.append((func_name, hex(func_ea)))
    return functions

def patch_jnz_to_jz():
    idaapi.msg_clear()

    if not ida_hexrays.init_hexrays_plugin():
        print("Hex-Rays decompiler is not available.")
        return

    functions = get_funcs()

    for func_name, func_ea in functions:
        if func_name == "main":
            cfunc = ida_hexrays.decompile(func_ea)
            if not cfunc:
                print(f"Failed to decompile function at address {hex(func_ea)}.")
                continue
            
            for block in cfunc:
                for insn in block:
                    if insn.op == ida_hexrays.m_jnz:
                        print(f"Patching jnz to jz at address {hex(insn.ea)}.")
                        insn.op = ida_hexrays.m_jz
            ida_hexrays.rebuild_cfunc(cfunc)
        else:
            print(f"Ignoring function: {func_name} at {hex(func_ea)}")

patch_jnz_to_jz(start_ea, end_ea)

print("Patch complete.")