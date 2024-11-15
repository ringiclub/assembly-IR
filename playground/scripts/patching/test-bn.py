from binaryninja import *


# address = 0x1366

# with bv.get_function_at(address).begin_action("Invert Branch"):

#     llil_instr = bv.get_function_at(address).get_low_level_il_at(address)

#     if llil_instr.operation == LowLevelILOperation.LLIL_IF:
#         true_branch = llil_instr.true
#         false_branch = llil_instr.false

#         llil_instr.set_true_false(false_branch, true_branch)

#         bv.update_analysis_and_wait()

#     else:
#         print("No conditional branch found at this address.")


def find_strcpy(i, t) -> str:
    match i:
        case HighLevelILCall(dest=HighLevelILConstPtr(constant=c)) if c in t:
            return str(i.params[1].constant_data.data)

t = [
    bv.get_symbol_by_raw_name('__builtin_strcpy').address,
    bv.get_symbol_by_raw_name('__builtin_strncpy').address
]


for result in current_hlil.traverse(find_strcpy, t):

    print(result)
    break


def get_memcpy_data(i, t) -> bytes:
    match i:
        case HighLevelILCall(dest=HighLevelILConstPtr(constant=c)) if c == t:
            return bytes(i.params[1].constant_data.data)


t = bv.get_symbol_by_raw_name('__builtin_memcpy').address
for i in current_hlil.traverse(get_memcpy_data, t):
    print(f"Found some memcpy data: {repr(i)}")



def find_strcpy(i, t) -> str:
    match i:
        case HighLevelILCall(dest=HighLevelILConstPtr(constant=c)) if c in t:
            return str(i.params[1].constant_data.data)

t = [
    bv.get_symbol_by_raw_name('__builtin_strcpy').address,
    bv.get_symbol_by_raw_name('__builtin_strncpy').address
]

for i in current_hlil.traverse(find_strcpy, t):
    print(i)


def param_counter(i) -> int:
    match i:
        case HighLevelILCall():
            return len(i.params)

list(current_hlil.traverse(param_counter))



def collect_call_target(i) -> None:
    match i:
        case HighLevelILCall(dest=HighLevelILConstPtr(constant=c)):
            return c

set([hex(a) for a in current_hlil.traverse(collect_call_target)])


def collect_this_vars(i) -> Variable:
    match i:
        case HighLevelILVar(var=v) if v.name == 'this':
            return v

list(v for v in current_hlil.traverse(collect_this_vars))