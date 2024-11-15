from binaryninja import LogLevel, MediumLevelILOperation

log_to_stdout(LogLevel.InfoLog)

for func in bv.functions:
    if func.name == "main":
        log_info(f"Processing function: {repr(func)}")

        for block in func.medium_level_il:
            log_info(f"\tBlock: {block}")
            
            for insn in block:
                if insn.operation == MediumLevelILOperation.MLIL_IF:
                    condition = insn.condition
                    log_info(f"\t\tChecking condition: {condition}")

                    if condition.operation == MediumLevelILOperation.MLIL_CMP_E:
                        new_condition = func.medium_level_il.append(
                            MediumLevelILOperation.MLIL_CMP_NE
                        )
                        
                        if insn.true_block:
                            insn.true_block, insn.false_block = insn.false_block, insn.true_block
                        
                        insn.condition = new_condition
                        
                        log_info(f"\t\tReversed comparison and swapped branches at {insn.address}")
                else:
                    log_info(f"\t\tNot a conditional jump: {insn}")
