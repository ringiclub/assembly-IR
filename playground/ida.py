import idaapi  # pylint: disable=import-error
import idautils  # pylint: disable=import-error
import ida_ua  # pylint: disable=import-error
import ida_hexrays # pylint: disable=import-error
import idc # pylint: disable=import-error
import ida_name # pylint: disable=import-error
import ida_kernwin # pylint: disable=import-error

class MicrocodePlayground(idaapi.plugin_t):
    flags = 0
    comment = "IDA Microcode Playground Plugin"
    help = "This plugin is used to testing purposes"
    wanted_name = "MicrocodePlayground"
    wanted_hotkey = "Ctrl-Shift-P"

    def init(self):
        self.opcode_dict = {
            0x00: "m_nop",     # no operation
            0x01: "m_stx",     # store register to memory
            0x02: "m_ldx",     # load register from memory
            0x03: "m_ldc",     # load constant
            0x04: "m_mov",     # move
            0x05: "m_neg",     # negate
            0x06: "m_lnot",    # logical not
            0x07: "m_bnot",    # bitwise not
            0x08: "m_xds",     # extend (signed)
            0x09: "m_xdu",     # extend (unsigned)
            0x0A: "m_low",     # take low part
            0x0B: "m_high",    # take high part
            0x0C: "m_add",     # l + r -> dst
            0x0D: "m_sub",     # l - r -> dst
            0x0E: "m_mul",     # l * r -> dst
            0x0F: "m_udiv",    # l / r -> dst (unsigned)
            0x10: "m_sdiv",    # l / r -> dst (signed)
            0x11: "m_umod",    # l % r -> dst (unsigned)
            0x12: "m_smod",    # l % r -> dst (signed)
            0x13: "m_or",      # bitwise or
            0x14: "m_and",     # bitwise and
            0x15: "m_xor",     # bitwise xor
            0x16: "m_shl",     # shift logical left
            0x17: "m_shr",     # shift logical right
            0x18: "m_sar",     # shift arithmetic right
            0x19: "m_cfadd",   # calculate carry bit of (l + r)
            0x1A: "m_ofadd",   # calculate overflow bit of (l + r)
            0x1B: "m_cfshl",   # calculate carry bit of (l << r)
            0x1C: "m_cfshr",   # calculate carry bit of (l >> r)
            0x1D: "m_sets",    # set sign flag (SF = 1)
            0x1E: "m_seto",    # set overflow flag if overflow in (l - r)
            0x1F: "m_setp",    # set parity flag (unordered/parity)
            0x20: "m_setnz",   # set flag if not equal (ZF = 0)
            0x21: "m_setz",    # set flag if equal (ZF = 1)
            0x22: "m_setae",   # set flag if above or equal (CF = 0)
            0x23: "m_setb",    # set flag if below (CF = 1)
            0x24: "m_seta",    # set flag if above (CF = 0 & ZF = 0)
            0x25: "m_setbe",   # set flag if below or equal (CF = 1 | ZF = 1)
            0x26: "m_setg",    # set flag if greater (SF = OF & ZF = 0)
            0x27: "m_setge",   # set flag if greater or equal (SF = OF)
            0x28: "m_setl",    # set flag if less (SF != OF)
            0x29: "m_setle",   # set flag if less or equal (SF != OF | ZF = 1)
            0x2A: "m_jcnd",    # conditional jump
            0x2B: "m_jnz",     # jump if not equal (ZF = 0)
            0x2C: "m_jz",      # jump if equal (ZF = 1)
            0x2D: "m_jae",     # jump if above or equal (CF = 0)
            0x2E: "m_jb",      # jump if below (CF = 1)
            0x2F: "m_ja",      # jump if above (CF = 0 & ZF = 0)
            0x30: "m_jbe",     # jump if below or equal (CF = 1 | ZF = 1)
            0x31: "m_jg",      # jump if greater (SF = OF & ZF = 0)
            0x32: "m_jge",     # jump if greater or equal (SF = OF)
            0x33: "m_jl",      # jump if less (SF != OF)
            0x34: "m_jle",     # jump if less or equal (SF != OF | ZF = 1)
            0x35: "m_jtbl",    # table jump
            0x36: "m_ijmp",    # indirect unconditional jump
            0x37: "m_goto",    # unconditional jump
            0x38: "m_call",    # call (subroutine)
            0x39: "m_icall",   # indirect call
            0x3A: "m_ret",     # return from subroutine
            0x3B: "m_push",    # push onto stack
            0x3C: "m_pop",     # pop from stack
            0x3D: "m_und",     # undefine
            0x3E: "m_ext",     # external instruction
            0x3F: "m_f2i",     # convert floating point to integer
            0x40: "m_f2u",     # convert floating point to unsigned integer
            0x41: "m_i2f",     # convert integer to floating point
            0x42: "m_u2f",     # convert unsigned integer to floating point
            0x43: "m_f2f",     # change floating point precision
            0x44: "m_fneg",    # negate floating point
            0x45: "m_fadd",    # floating point add
            0x46: "m_fsub",    # floating point subtract
            0x47: "m_fmul",    # floating point multiply
            0x48: "m_fdiv",    # floating point divide
        }

        return idaapi.PLUGIN_OK
    
    def get_funcs(self) -> list:
        functions = []
        for func_ea in idautils.Functions():
            func_name = idc.get_func_name(func_ea)
            functions.append((func_name, hex(func_ea)))
        return functions

    def get_pseudocode(self, func_ea) -> str:
        func = idaapi.get_func(func_ea)
        if func is None:
            return f"No function found at address {hex(func_ea)}"

        cfunc = ida_hexrays.decompile(func)
        if cfunc is None:
            return f"Failed to decompile function at address {hex(func_ea)}"

        return str(cfunc)

    def get_microcode(self, func_addr, maturity) -> ida_hexrays.mba_t:
        func = idaapi.get_func(func_addr)
        mbr = ida_hexrays.mba_ranges_t(func)
        hf = ida_hexrays.hexrays_failure_t()
        ml = ida_hexrays.mlist_t()
        ida_hexrays.mark_cfunc_dirty(func.start_ea)
        mba = ida_hexrays.gen_microcode(mbr, hf, ml, ida_hexrays.DECOMP_NO_WAIT, maturity)


        if not mba:
            print("0x%08X: %s" % (hf.errea, hf.desc()))
            return None
        return mba

    def run(self, arg):  # pylint: disable=unused-argument
        idaapi.msg_clear()

        function_list = self.get_funcs()
        microcode_instructions = []

        for name, addr in function_list:
            if name == "main":
                ida_kernwin.msg(f"{name} : {addr}\n")

                pseudocode = self.get_pseudocode(int(addr, 16))
                ida_kernwin.msg(f"Pseudocode for {name}:\n{pseudocode}\n")

                mba = self.get_microcode(int(addr, 16), 0)

                if mba:
                    for i in range(mba.qty):
                        block = mba.get_mblock(i)
                        
                        insn = block.head
                        while insn:
                            opcode_name = self.opcode_dict.get(insn.opcode, "Unknown opcode")
                            microcode_instructions.append({
                                "Instruction": str(insn),
                                "Opcode": opcode_name,
                                "Operands": (str(insn.l), str(insn.r))
                            })
                            insn = insn.next
            
        for instruction in microcode_instructions:
            print(f"Instruction: {instruction['Instruction']}\n")
            print(f"Opcode: {instruction['Opcode']}, Operands: {instruction['Operands']}\n\n")

    def term(self):
        print("End.")

def PLUGIN_ENTRY():  # pylint: disable=invalid-name
    return MicrocodePlayground()