import idaapi
import idautils
import idc
import ida_hexrays

def get_funcs() -> list:
    """Retrieve a list of functions in the binary."""
    functions = []
    for func_ea in idautils.Functions():
        func_name = idc.get_func_name(func_ea)
        functions.append((func_name, func_ea))  # Store the address as an integer
    return functions

def get_microcode(func_addr, maturity) -> ida_hexrays.mba_t:
    """Retrieve microcode of a function for a given maturity level."""
    func = idaapi.get_func(func_addr)
    mbr = ida_hexrays.mba_ranges_t(func)
    hf = ida_hexrays.hexrays_failure_t()
    ml = ida_hexrays.mlist_t()
    
    # Mark the function dirty to ensure updates
    ida_hexrays.mark_cfunc_dirty(func.start_ea)

    # Generate microcode
    mba = ida_hexrays.gen_microcode(mbr, hf, ml, ida_hexrays.DECOMP_NO_WAIT, maturity)
    if not mba:
        print(f"Failed to generate microcode: {hf.errea} - {hf.desc()}")
        return None
    return mba

def patch_jnz_to_jz_in_binary(func_name: str = "main"):
    """Patch all occurrences of `jnz` to `jz` at the binary level in the specified function."""
    func_ea = idc.get_name_ea_simple(func_name)
    if func_ea == idc.BADADDR:
        print(f"Function {func_name} not found.")
        return
    
    func = idaapi.get_func(func_ea)
    if not func:
        print(f"Unable to retrieve function information for {func_name}.")
        return
    
    ea = func.start_ea
    while ea < func.end_ea:
        mnem = idc.print_insn_mnem(ea)
        
        if mnem == "jnz":
            print(f"Patching jnz to jz at address {hex(ea)}")
            
            # Get the opcode for `jz` and replace it
            idc.patch_byte(ea, idc.get_original_byte(ea) ^ 0x01)  # Toggle jnz (0x75) to jz (0x74) or vice-versa
        ea = idc.next_head(ea, func.end_ea)

    print(f"Patched `jnz` to `jz` in function {func_name}.")

def patch_jnz_to_jz_in_microcode(fname: str = "main"):
    """Patch jnz instructions to jz in the specified function."""
    idaapi.msg_clear()

    functions = get_funcs()
    for func_name, func_ea in functions:
        if func_name == fname:
            mba = get_microcode(func_ea, 8)  # maturity n°8 is MMAT_LVARS
            if mba:
                for i in range(mba.qty):  # iterate over all basic blocks
                    block = mba.get_mblock(i)  # get basic block at index i
                    insn = block.head

                    while insn:
                        if insn.opcode == ida_hexrays.m_jnz:  # check for jnz instruction
                            print(f"Patching jnz to jz at address {hex(insn.ea)}")
                            insn.opcode = ida_hexrays.m_jz  # patch jnz to jz
                        insn = insn.next  # Move to the next instruction

                # Mark the function as dirty to commit changes
                ida_hexrays.mark_cfunc_dirty(func_ea)
                print(f"Patched function: {func_name} at {hex(func_ea)}.")
            else:
                print(f"Failed to get microcode for function: {func_name}")
        # else:
            # print(f"Ignoring function: {func_name} at {hex(func_ea)}")

patch_jnz_to_jz_in_binary()
print("Terminated.")