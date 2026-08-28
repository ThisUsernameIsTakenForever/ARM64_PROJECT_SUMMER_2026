def sf(register):
    if register.startswith('X'):
        return 0x80000000
    elif register.startswith('W'):
        return 0
    else:
        return ValueError("Register must start with X or W")

def calculate_bitmask_fields(imm):
    """Helper to find structural A64 logical immediate bitfields."""
    # Handle structural edge cases (0 and -1 cannot be encoded as logical immediates)
    
    # Step 1: Find the repeating pattern size (e)
    # We test sizes: 2, 4, 8, 16, 32, 64
    size = 64
    for s in [2, 4, 8, 16, 32]:
        mask = (1 << s) - 1
        if (imm & mask) == ((imm >> s) & mask) and (imm == ((imm >> s) | (imm << (64 - s))) & 0xFFFFFFFFFFFFFFFF):
            # The pattern repeats safely across the 64-bit width
            if all((imm >> i) & mask == imm & mask for i in range(0, 64, s)):
                size = s
                break

    # Truncate the immediate to its smallest repeating element size
    val = imm & ((1 << size) - 1)
        
    # Step 2: Determine rotation (R) and continuous ones (S)
    # We look for a rotated sequence of S ones.
    # An unrotated sequence has ones at the least-significant bits.
    immr = None
    imms = None
        
    for r in range(size):
        # Rotate left by r (equivalent to undoing a right rotation by r)
        rotated = ((val << r) | (val >> (size - r))) & ((1 << size) - 1)
            
        # Check if 'rotated' is a sequence of S continuous ones at the bottom
        # A valid sequence plus 1 is a power of 2: (rotated & (rotated + 1)) == 0
        if rotated > 0 and (rotated & (rotated + 1)) == 0:
            # Count trailing ones to find S
            s_count = bin(rotated).count('1')
            if s_count < size: # Cannot be all ones
                immr = r
                # Encode imms field:
                # - For size 64: imms = (S - 1) | 0b000000 (since N=1 goes elsewhere or top bit acts as size)
                # - For size 32: imms = (S - 1) | 0b100000
                # - For size 16: imms = (S - 1) | 0b110000, etc.
                size_mask = (~(size - 1) << 1) & 0x3F
                imms = (size_mask | (s_count - 1)) & 0x3F
                break
    return (imms, immr)

def encode_ret(tokens, current_pc, symbol_table):
    """
    >>> symbol_table = {}
    >>> encode_ret(['RET', 'X1'], 0x100000350, symbol_table)
    3596550176
    >>> encode_ret(['RET'], 0x100000350, symbol_table)
    3596551104
    """
    if len(tokens) == 1:
        base_opcode = 0xd65f03c0
        return base_opcode
    reg_str = tokens[1]
    reg_num = int(reg_str[1:])
    base_opcode = 0xd65f0000
    return base_opcode | (reg_num << 5)

def encode_nop(tokens, current_pc, symbol_table):
    """
    >>> symbol_table = {}
    >>> encode_nop(['NOP'], 0x100000350, symbol_table)
    3573751839
    """
    base_opcode = 0xd503201f
    return base_opcode

def encode_svc(tokens, current_pc, symbol_table):
    """Encodes an ARM64 SVC (Supervisor Call) instruction.
    Returns a fixed 32-bit integer representing the machine code opcode.

    >>> symbol_table = {}
    >>> encode_svc(['SVC', '0X80'], 0x100000350, symbol_table)
    3556773889
    >>> encode_svc(['SVC', '0'], 0x100000350, symbol_table)
    3556769793
    """    
    base_opcode = 0xd4000001
    imm_str = tokens[1]
    imm_val = int(imm_str, 0)
    return base_opcode | (imm_val << 5)

def encode_adr(tokens, current_pc, symbol_table):
    """Encodes an ARM64 ADR instruction by calculating a byte-level PC-relative offset."""
    reg_str = tokens[1]
    if reg_str == 'XZR':
        reg_str = 'X31'
    
    rd_num = int(reg_str[1:]) & 0x1F  # Restrict to 5 bits
    target_address = symbol_table[tokens[2]]
    
    # ADR calculates the exact byte offset
    offset = target_address - current_pc
    
    # Check if offset fits in a signed 21-bit field (-1MB to +1MB)
    if not (-1048576 <= offset < 1048576):
        raise ValueError("ADR offset out of range (+/- 1MB).")
        
    immlo = offset & 0x3             # Bottom 2 bits
    immhi = (offset >> 2) & 0x7FFFF  # Next 19 bits (masked to clear negative sign extension)
    
    base_opcode = 0x10000000         # op=0, op2=0, reserved bit pattern
    return base_opcode | (immlo << 29) | (immhi << 5) | rd_num

def encode_adrp(tokens, current_pc, symbol_table):
    """Encodes an ARM64 ADRP instruction by calculating a 4KB page-level PC-relative offset."""
    reg_str = tokens[1]
    if reg_str == 'XZR':
        reg_str = 'X31'    
    rd_num = int(reg_str[1:]) & 0x1F
    operand2 = tokens[2]

    if "@PAGE" in operand2:
        label_name = operand2.replace("@PAGE", "")
        
        if label_name not in symbol_table:
            raise ValueError(f"Undefined label: {label_name}")

        target_address = symbol_table[label_name]   
    else:
        target_address = symbol_table[operand2]   
    # ADRP works strictly on 4KB aligned page boundaries
    target_page = target_address & ~0xFFF
    current_page = current_pc & ~0xFFF
    page_offset = (target_page - current_page) >> 12
    
    # Check if page offset fits in a signed 21-bit field (+/- 4GB)
    if not (-1048576 <= page_offset < 1048576):
        raise ValueError("ADRP offset out of range (+/- 4GB).")
        
    immlo = page_offset & 0x3
    immhi = (page_offset >> 2) & 0x7FFFF
    
    base_opcode = 0x90000000         # op=1 (this sets bit 31 to 1 natively)
    return base_opcode | (immlo << 29) | (immhi << 5) | rd_num

def encode_mul(tokens, current_pc, symbol_table):
    """
    >>> symbol_table = {}
    >>> encode_mul(['MUL', 'X1', 'X2', 'X3'], 0x100000350, symbol_table)
    """
    reg_str = tokens[1]
    SF = sf(reg_str)
    Rd = int(tokens[1][1:])
    Rn = int(tokens[2][1:])
    Rm = int(tokens[3][1:])
    base_opcode = 0x1b007c00
    return base_opcode | Rd | (Rn << 5) | (Rm << 16) | SF

def encode_abs(tokens, current_pc, symbol_table):
    reg_str = tokens[1]
    SF = sf(reg_str)
    Rd = int(tokens[1][1:])
    Rn = int(tokens[2][1:])
    base_opcode = 0x5ac02000 
    return base_opcode | Rd | (Rn << 5) | SF

def encode_adcs(tokens, current_pc, symbol_table):
    reg_str = tokens[1]
    SF = sf(reg_str)
    Rd = int(tokens[1][1:])
    Rn = int(tokens[2][1:])
    Rm = int(tokens[3][1:])
    base_opcode = 0x3a000000
    return base_opcode | Rd | (Rn << 5) | (Rm << 16) | SF

def encode_smull(tokens, current_pc, symbol_table):
    """
    >>> symbol_table = {}
    >>> encode_smull(['SMULL', 'X1', 'X2', 'X3'], 0x100000350, symbol_table)
    """
    reg_str = tokens[1]
    SF = sf(reg_str)
    Rd = int(tokens[1][1:])
    Rn = int(tokens[2][1:])
    Rm = int(tokens[3][1:])
    base_opcode = 0x1b207c00 
    return base_opcode | Rd | (Rn << 5) | (Rm << 16) | SF

def encode_umull(tokens, current_pc, symbol_table):
    """
    >>> symbol_table = {}
    >>> encode_umull(['UMULL', 'X1', 'X2', 'X3'], 0x100000350, symbol_table)
    """
    return encode_smull(tokens, current_pc, symbol_table) + 0x800000

def encode_smulh(tokens, current_pc, symbol_table):
    """
    >>> symbol_table = {}
    >>> encode_smulh(['SMULH', 'X1', 'X2', 'X3'], 0x100000350, symbol_table)
    """
    Xd = int(tokens[1][1:])
    Xn = int(tokens[2][1:])
    Xm = int(tokens[3][1:])
    base_opcode = 0x9b407c00 
    return base_opcode | Xd | (Xn << 5) | (Xm << 16)

def encode_umulh(tokens, current_pc, symbol_table):
    """
    >>> symbol_table = {}
    >>> encode_umulh(['UMULH', 'X1', 'X2', 'X3'], 0x100000350, symbol_table)
    """
    return encode_smulh(tokens, current_pc, symbol_table) + 0x800000

def encode_uxtb(tokens, current_pc, symbol_table):
    base_opcode = 0x53001c00
    Wd = int(tokens[1][1:])
    Wn = int(tokens[2][1:])
    return base_opcode | Wd | (Wn << 5)

def encode_uxth(tokens, current_pc, symbol_table):
    return encode_uxtb(tokens, current_pc, symbol_table) + 0x2000

def encode_ubfx(tokens, current_pc, symbol_table):
    reg_str = tokens[1]
    SF = sf(reg_str)
    Rd = int(tokens[1][1:])
    Rn = int(tokens[2][1:])
    lsb = int(tokens[3], 0)
    width = int(tokens[4], 0)
    base_opcode = 0x53400000 
    immr = lsb
    imms = lsb + width - 1
    return base_opcode | Rd | (Rn << 5) | (imms << 10) | (immr << 16) | SF

def encode_ubfiz(tokens, current_pc, symbol_table):
    reg_str = tokens[1]
    SF = sf(reg_str)
    Rd = int(tokens[1][1:])
    Rn = int(tokens[2][1:])
    lsb = int(tokens[3], 0)
    width = int(tokens[4], 0)
    base_opcode = 0x53400000
    immr = (-lsb) % 32
    imms = width - 1
    return base_opcode | Rd | (Rn << 5) | (imms << 10) | (immr << 16) | SF

def encode_sxtb(tokens, current_pc, symbol_table):
    reg_str = tokens[1]
    SF = sf(reg_str)
    base_opcode = 0x13401c00
    Rd = int(tokens[1][1:])
    Rn = int(tokens[2][1:])
    return base_opcode | Rd | (Rn << 5) | SF

def encode_sxth(tokens, current_pc, symbol_table):
    return encode_sxtb(tokens, current_pc, symbol_table) + 0x2000

def encode_sxtw(tokens, current_pc, symbol_table):
    base_opcode = 0x93407c00
    Xd = int(tokens[1][1:])
    Xn = int(tokens[2][1:])
    return base_opcode | Xd | (Xn << 5)

def encode_sbfx(tokens, current_pc, symbol_table):
    reg_str = tokens[1]
    SF = sf(reg_str)
    Rd = int(tokens[1][1:])
    Rn = int(tokens[2][1:])
    lsb = int(tokens[3], 0)
    width = int(tokens[4], 0)
    base_opcode = 0x13400000
    immr = lsb
    imms = lsb + width - 1
    return base_opcode | Rd | (Rn << 5) | (imms << 10) | (immr << 16) | SF

def encode_sbfiz(tokens, current_pc, symbol_table):
    reg_str = tokens[1]
    SF = sf(reg_str)
    Xd = int(tokens[1][1:])
    Xn = int(tokens[2][1:])
    lsb = int(tokens[3], 0)
    width = int(tokens[4], 0)
    base_opcode = 0x13400000
    immr = (-lsb) % 32
    imms = width - 1
    return base_opcode | Xd | (Xn << 5) | (imms << 10) | (immr << 16) | SF

def encode_udiv(tokens, current_pc, symbol_table):
    reg_str = tokens[1]
    SF = sf(reg_str)
    Rd = int(tokens[1][1:])
    Rn = int(tokens[2][1:])
    Rm = int(tokens[3][1:])
    base_opcode = 0x1ac00800
    return base_opcode | Rd | (Rn << 5) | (Rm << 16) | SF

def encode_sdiv(tokens, current_pc, symbol_table):
    return encode_udiv(tokens, current_pc, symbol_table) + 0x400

def encode_umsubl(tokens, current_pc, symbol_table):
    Xd = int(tokens[1][1:])
    Xn = int(tokens[2][1:])
    Xm = int(tokens[3][1:])
    Xa = int(tokens[4][1:])
    base_opcode = 0x9ba08000
    return base_opcode | Xd | (Xn << 5) | (Xa << 10) | (Xm << 16)

def encode_smsubl(tokens, current_pc, symbol_table):
    return encode_umsubl(tokens, current_pc, symbol_table) + 0x800000

def encode_umnegl(tokens, current_pc, symbol_table):
    Xd = int(tokens[1][1:])
    Xn = int(tokens[2][1:])
    Xm = int(tokens[3][1:])
    base_opcode = 0x9ba0fc00
    return base_opcode | Xd | (Xn << 5) | (Xm << 16)

def encode_smnegl(tokens, current_pc, symbol_table):
    return encode_umnegl(tokens, current_pc, symbol_table) + 0x800000

def encode_movn(tokens, current_pc, symbol_table):
    reg_str = tokens[1]
    SF = sf(reg_str)
    base_opcode = 0x12800000
    Xd = int(tokens[1][1:])
    imm16 = int(tokens[2], 0)
    return base_opcode | Xd | (imm16 << 5) | SF

def encode_movz(tokens, current_pc, symbol_table):
    return encode_movn(tokens, current_pc, symbol_table) + 0x40000000

def encode_movk(tokens, current_pc, symbol_table):
    return encode_movn(tokens, current_pc, symbol_table) + 0x60000000

def encode_smaddl(tokens, current_pc, symbol_table):
    Xd = int(tokens[1][1:])
    Xn = int(tokens[2][1:])
    Xm = int(tokens[3][1:])
    Xa = int(tokens[4][1:])
    base_opcode = 0x9b200000
    return base_opcode | Xd | (Xn << 5) | (Xa << 10) | (Xm << 16)

def encode_umaddl(tokens, current_pc, symbol_table):
    return encode_smaddl(tokens, current_pc, symbol_table) + 0x800000

def encode_madd(tokens, current_pc, symbol_table):
    reg_str = tokens[1]
    SF = sf(reg_str)
    Rd = int(tokens[1][1:])
    Rn = int(tokens[2][1:])
    Rm = int(tokens[3][1:])
    Ra = int(tokens[4][1:])
    base_opcode = 0x1b000000
    return base_opcode | Rd | (Rn << 5) | (Ra << 10) | (Rm << 16) | SF

def encode_msub(tokens, current_pc, symbol_table):
    reg_str = tokens[1]
    SF = sf(reg_str)
    Rd = int(tokens[1][1:])
    Rn = int(tokens[2][1:])
    Rm = int(tokens[3][1:])
    Ra = int(tokens[4][1:])
    base_opcode = 0x1b008000
    return base_opcode | Rd | (Rn << 5) | (Ra << 10) | (Rm << 16) | SF

def encode_mneg(tokens, current_pc, symbol_table):
    reg_str = tokens[1]
    SF = sf(reg_str)
    Rd = int(tokens[1][1:])
    Rn = int(tokens[2][1:])
    Rm = int(tokens[3][1:])
    base_opcode = 0x1b00fc00
    return base_opcode | Rd | (Rn << 5) | (Rm << 16) | SF

def encode_umin(tokens, current_pc, symbol_table):
    reg_str = tokens[1]
    SF = sf(reg_str)
    Rd = int(tokens[1][1:])
    Rn = int(tokens[2][1:])
    if tokens[3][1:].isdigit():
        base_opcode = 0x1ac06c00
        Rm = int(tokens[3][1:])
        return base_opcode | Rd | (Rn << 5) | (Rm << 16) | SF
    base_opcode = 0x11cc0000
    imm8 = int(tokens[3], 0)
    return base_opcode | Rd | (Rn << 5) | (imm8 << 10) | SF

def encode_umax(tokens, current_pc, symbol_table):
    reg_str = tokens[1]
    SF = sf(reg_str)
    Rd = int(tokens[1][1:])
    Rn = int(tokens[2][1:])
    if tokens[3][1:].isdigit():
        base_opcode = 0x1ac06400
        Rm = int(tokens[3][1:])
        return base_opcode | Rd | (Rn << 5) | (Rm << 16) | SF
    base_opcode = 0x11c40000
    imm8 = int(tokens[3], 0)
    return base_opcode | Rd | (Rn << 5) | (imm8 << 10) | SF

def encode_smin(tokens, current_pc, symbol_table):
    reg_str = tokens[1]
    SF = sf(reg_str)
    Rd = int(tokens[1][1:])
    Rn = int(tokens[2][1:])
    if tokens[3][1:].isdigit():
        base_opcode = 0x1ac06800
        Rm = int(tokens[3][1:])
        return base_opcode | Rd | (Rn << 5) | (Rm << 16) | SF
    base_opcode = 0x11c80000
    imm8 = int(tokens[3], 0)
    return base_opcode | Rd | (Rn << 5) | (imm8 << 10) | SF

def encode_smax(tokens, current_pc, symbol_table):
    reg_str = tokens[1]
    SF = sf(reg_str)
    Rd = int(tokens[1][1:])
    Rn = int(tokens[2][1:])
    if tokens[3][1:].isdigit():
        base_opcode = 0x1ac06000
        Rm = int(tokens[3][1:])
        return base_opcode | Rd | (Rn << 5) | (Rm << 16) | SF
    base_opcode = 0x11c00000
    imm8 = int(tokens[3], 0)
    return base_opcode | Rd | (Rn << 5) | (imm8 << 10) | SF

def encode_asr(tokens, current_pc, symbol_table):
    reg_str = tokens[1]
    SF = sf(reg_str)
    Rd = int(tokens[1][1:])
    Rn = int(tokens[2][1:])
    if tokens[3][1:].isdigit():
        base_opcode = 0x1ac02800
        Rm = int(tokens[3][1:])
        return base_opcode | Rd | (Rn << 5) | (Rm << 16) | SF
    base_opcode = 0x1340fc00
    shift = int(tokens[3], 0)
    return base_opcode | Rd | (Rn << 5) | (shift << 16) | SF

def encode_ror(tokens, current_pc, symbol_table):
    reg_str = tokens[1]
    SF = sf(reg_str)
    Rd = int(tokens[1][1:])
    Rn = int(tokens[2][1:])
    if tokens[3][1:].isdigit():
        base_opcode = 0x1ac02c00
        Rm = int(tokens[3][1:])
        return base_opcode | Rd | (Rn << 5) | (Rm << 16) | SF
    base_opcode = 0x13c00000
    shift = int(tokens[3], 0)
    return base_opcode | Rd | (Rn << 5) | (Rn << 16) | (shift << 10) | SF

def encode_lsl(tokens, current_pc, symbol_table):
    reg_str = tokens[1]
    SF = sf(reg_str)
    Rd = int(tokens[1][1:])
    Rn = int(tokens[2][1:])
    if tokens[3][1:].isdigit():
        base_opcode = 0x1ac02000
        Rm = int(tokens[3][1:])
        return base_opcode | Rd | (Rn << 5) | (Rm << 16) | SF
    base_opcode = 0x53400000
    shift = int(tokens[3], 0)
    immr = (64 - shift) & 0x3F
    imms = 63 - shift
    return base_opcode | Rd | (Rn << 5) | (imms << 10) | (immr << 16) | SF

def encode_lsr(tokens, current_pc, symbol_table):
    reg_str = tokens[1]
    SF = sf(reg_str)
    Rd = int(tokens[1][1:])
    Rn = int(tokens[2][1:])
    if tokens[3][1:].isdigit():
        base_opcode = 0x1ac02400
        Rm = int(tokens[3][1:])
        return base_opcode | Rd | (Rn << 5) | (Rm << 16) | SF
    base_opcode = 0x5340fc00
    shift = int(tokens[3], 0)
    immr = shift
    imms = 63 
    return base_opcode | Rd | (Rn << 5) | (imms << 10) | (immr << 16) | SF

def encode_mov(tokens, current_pc, symbol_table):
    reg_str = tokens[1]
    SF = sf(reg_str)
    Rd = int(tokens[1][1:])
    if tokens[2][1:].isdigit():
        base_opcode = 0x2a0003e0
        Rm = int(tokens[2][1:])
        return base_opcode | Rd | (Rm << 16) | SF
    base_opcode = 0x52800000
    imm16 = int(tokens[2], 0)
    return base_opcode | Rd | (imm16 << 5) | SF

def encode_and(tokens, current_pc, symbol_table):
    reg_str = tokens[1]
    SF = sf(reg_str)
    Rd = int(tokens[1][1:])
    Rn = int(tokens[2][1:])

    # CASE 1: AND (register) -> e.g., AND Xd, Xn, Xm
    if len(tokens) == 4 and tokens[3][1:].isdigit():
        Rm = int(tokens[3][1:])
        # Base opcode for AND (register), sf=1, opc=00, shift=00, N=0
        # Binary: 1 00 01010 00 0 [Rm] 000000 [Rn] [Rd]
        base_opcode = 0xA000000
        return base_opcode | Rd | (Rn << 5) | (Rm << 16) | SF

    # CASE 2: AND (shifted register) -> e.g., AND Xd, Xn, Xm, LSL #4
    elif len(tokens) > 4:
        Rm = int(tokens[3][1:])
        shift_type = tokens[4] # LSL, LSR, ASR, ROR
        imm6 = int(tokens[5], 0)
        
        # Map shift types to their 2-bit ARM64 hardware codes
        shift_codes = {"LSL": 0b00, "LSR": 0b01, "ASR": 0b10, "RESERVED": 0b11}
        shift = shift_codes.get(shift_type, 0b00)
        
        base_opcode = 0xA000000
        return base_opcode | Rd | (Rn << 5) | (Rm << 16) | (imm6 << 10) | (shift << 22) | SF
    else:
        imm = int(tokens[3], 0) 
        (imms, immr)= calculate_bitmask_fields(imm)
        base_opcode = 0x12800000
        return base_opcode | Rd | (Rn << 5) | (imms << 10) | (immr << 16) | SF

def encode_ands(tokens, current_pc, symbol_table):
    reg_str = tokens[1]
    SF = sf(reg_str)
    Rd = int(tokens[1][1:])
    Rn = int(tokens[2][1:])

    if len(tokens) == 4 and tokens[3][1:].isdigit():
        Rm = int(tokens[3][1:])
        base_opcode = 0x6A000000
        return base_opcode | Rd | (Rn << 5) | (Rm << 16) | SF

    elif len(tokens) > 4:
        Rm = int(tokens[3][1:])
        shift_type = tokens[4]
        imm6 = int(tokens[5], 0)
        
        shift_codes = {"LSL": 0b00, "LSR": 0b01, "ASR": 0b10, "RESERVED": 0b11}
        shift = shift_codes.get(shift_type, 0b00)
        
        base_opcode = 0x6A000000
        return base_opcode | Rd | (Rn << 5) | (Rm << 16) | (imm6 << 10) | (shift << 22) | SF
    
    else:
        imm = int(tokens[3], 0) 
        
        (imms, immr)= calculate_bitmask_fields(imm)
        base_opcode = 0x72400000 
        return base_opcode | Rd | (Rn << 5) | (imms << 10) | (immr << 16) | SF

def encode_orr(tokens, current_pc, symbol_table):
    reg_str = tokens[1]
    SF = sf(reg_str)
    Rd = int(tokens[1][1:])
    Rn = int(tokens[2][1:])

    if len(tokens) == 4 and tokens[3][1:].isdigit():
        Rm = int(tokens[3][1:])
        base_opcode = 0x2A000000
        return base_opcode | Rd | (Rn << 5) | (Rm << 16) | SF
    
    elif len(tokens) > 4:
        Rm = int(tokens[3][1:])
        shift_type = tokens[4]
        imm6 = int(tokens[5], 0)
        
        shift_codes = {"LSL": 0b00, "LSR": 0b01, "ASR": 0b10, "RESERVED": 0b11}
        shift = shift_codes.get(shift_type, 0b00)
        
        base_opcode = 0x2A000000
        return base_opcode | Rd | (Rn << 5) | (Rm << 16) | (imm6 << 10) | (shift << 22) | SF
    
    else:
        imm = int(tokens[3], 0) 
        
        (imms, immr)= calculate_bitmask_fields(imm)
        base_opcode = 0x32400000
        return base_opcode | Rd | (Rn << 5) | (imms << 10) | (immr << 16) | SF 


def encode_orn(tokens, current_pc, symbol_table):
    reg_str = tokens[1]
    SF = sf(reg_str)
    Rd = int(tokens[1][1:])
    Rn = int(tokens[2][1:])

    if len(tokens) == 4 and tokens[3][1:].isdigit():
        Rm = int(tokens[3][1:])

        base_opcode = 0x2A200000
        return base_opcode | Rd | (Rn << 5) | (Rm << 16) | SF

    elif len(tokens) > 4:
        Rm = int(tokens[3][1:])
        shift_type = tokens[4]
        imm6 = int(tokens[5], 0)
        
        shift_codes = {"LSL": 0b00, "LSR": 0b01, "ASR": 0b10, "RESERVED": 0b11}
        shift = shift_codes.get(shift_type, 0b00)
        
        base_opcode = 0x2A200000
        return base_opcode | Rd | (Rn << 5) | (Rm << 16) | (imm6 << 10) | (shift << 22) | SF


def encode_eor(tokens, current_pc, symbol_table):
    reg_str = tokens[1]
    SF = sf(reg_str)
    Rd = int(tokens[1][1:])
    Rn = int(tokens[2][1:])

    if len(tokens) == 4 and tokens[3][1:].isdigit():
        Rm = int(tokens[3][1:])
        base_opcode = 0x4A000000
        return base_opcode | Rd | (Rn << 5) | (Rm << 16) | SF

    elif len(tokens) > 4:
        Rm = int(tokens[3][1:])
        shift_type = tokens[4]
        imm6 = int(tokens[5], 0)
        
        shift_codes = {"LSL": 0b00, "LSR": 0b01, "ASR": 0b10, "RESERVED": 0b11}
        shift = shift_codes.get(shift_type, 0b00)
        
        base_opcode = 0x4A000000
        return base_opcode | Rd | (Rn << 5) | (Rm << 16) | (imm6 << 10) | (shift << 22) | SF

    else:
        imm = int(tokens[3], 0) 
        
        (imms, immr)= calculate_bitmask_fields(imm)
        base_opcode = 0x52400000
        return base_opcode | Rd | (Rn << 5) | (imms << 10) | (immr << 16) | SF


def encode_eon(tokens, current_pc, symbol_table):
    reg_str = tokens[1]
    SF = sf(reg_str)
    Rd = int(tokens[1][1:])
    Rn = int(tokens[2][1:])

    if len(tokens) == 4 and tokens[3][1:].isdigit():
        Rm = int(tokens[3][1:])

        base_opcode = 0x4A200000
        return base_opcode | Rd | (Rn << 5) | (Rm << 16) | SF

    elif len(tokens) > 4:
        Rm = int(tokens[3][1:])
        shift_type = tokens[4]
        imm6 = int(tokens[5], 0)
        
        shift_codes = {"LSL": 0b00, "LSR": 0b01, "ASR": 0b10, "RESERVED": 0b11}
        shift = shift_codes.get(shift_type, 0b00)
        
        base_opcode = 0x4A200000
        return base_opcode | Rd | (Rn << 5) | (Rm << 16) | (imm6 << 10) | (shift << 22) | SF



def encode_neg(tokens, current_pc, symbol_table):
    reg_str = tokens[1]
    SF = sf(reg_str)
    Rd = int(tokens[1][1:])

    if len(tokens) == 3 and tokens[2][1:].isdigit():
        Rm = int(tokens[2][1:])
        base_opcode = 0x4B0003E0
        return base_opcode | Rd | (Rm << 16) | SF


    elif len(tokens) > 3:
        Rm = int(tokens[2][1:])
        shift_type = tokens[3]
        imm6 = int(tokens[4], 0)
        
        shift_codes = {"LSL": 0b00, "LSR": 0b01, "ASR": 0b10, "RESERVED": 0b11}
        shift = shift_codes.get(shift_type, 0b00)
        
        base_opcode = 0x4B0003E0
        return base_opcode | Rd | (Rm << 16) | (imm6 << 10) | (shift << 22) | SF

def encode_negs(tokens, current_pc, symbol_table):
    reg_str = tokens[1]
    SF = sf(reg_str)
    Rd = int(tokens[1][1:])

    if len(tokens) == 3 and tokens[2][1:].isdigit():
        Rm = int(tokens[2][1:])
        base_opcode = 0x6B0003E0
        return base_opcode | Rd | (Rm << 16) | SF

    elif len(tokens) > 3:
        Rm = int(tokens[2][1:])
        shift_type = tokens[3]
        imm6 = int(tokens[4], 0)
        
        shift_codes = {"LSL": 0b00, "LSR": 0b01, "ASR": 0b10, "RESERVED": 0b11}
        shift = shift_codes.get(shift_type, 0b00)
        
        base_opcode = 0x6B0003E0
        return base_opcode | Rd | (Rm << 16) | (imm6 << 10) | (shift << 22) | SF

def encode_add(tokens, current_pc, symbol_table):
    reg_str = tokens[1]
    SF = sf(reg_str)
    Rd = int(tokens[1][1:])
    Rn = int(tokens[2][1:])
    operand3 = tokens[3]

    if operand3[1:].isdigit():
        if operand3.startswith('W'):
            base_opcode = 0xB200000
            shift_codes = {"UXTB": 0b000, "UXTH": 0b001, "UXTW": 0b010, "UXTX": 0b011, "SXTB": 0b100, "SXTH": 0b101, "SXTW": 0b110, "SXTX": 0b111}
            if len(tokens) == 4:
                Rm = int(tokens[3][1:])
                return base_opcode | Rd | (Rn << 5) | (Rm << 16) | SF
            elif len(tokens) > 4:
                Rm = int(operand3[1:])
                shift_type = tokens[4] 
                imm3 = int(tokens[5], 0)
                option = shift_codes.get(shift_type, 0b000)
                return base_opcode | Rd | (Rn << 5) | (Rm << 16) | (imm3 << 10) | (option << 13) | SF
        if operand3.startswith('X'):
            base_opcode = 0xB000000
            shift_codes = {"LSL": 0b000, "LSR": 0b001, "ASR": 0b010, "RESERVED": 0b011}
            if len(tokens) == 4:
                Rm = int(operand3[1:])
                return base_opcode | Rd | (Rn << 5) | (Rm << 16) | SF
            elif len(tokens) > 4:
                Rm = int(operand3[1:])
                shift_type = tokens[4]
                imm6 = int(tokens[5], 0)
                shift = shift_codes.get(shift_type, 0b000)
                return base_opcode | Rd | (Rn << 5) | (Rm << 16) | (imm6 << 10) | (shift << 22) | SF
    if "@PAGEOFF" in operand3 or ":lo12:" in operand3:
        label_name = operand3.replace("@PAGEOFF", "").replace(":lo12:", "")
        
        if label_name not in symbol_table:
            raise ValueError(f"Undefined label: {label_name}")
            
        absolute_address = symbol_table[label_name]
        imm12 = absolute_address & 0xFFF
        
    elif operand3 in symbol_table:
        absolute_address = symbol_table[operand3]
        if absolute_address > 0xFFF:
            raise ValueError(f"Label '{operand3}' address requires @PAGEOFF modifier to fit in ADD instruction.")
        imm12 = absolute_address

    else:
        imm12 = int(operand3, 0) 
    base_opcode = 0x11000000
    return base_opcode | Rd | (Rn << 5) | (imm12 << 10) | SF

def encode_adds(tokens, current_pc, symbol_table):
    reg_str = tokens[1]
    SF = sf(reg_str)
    Rd = int(tokens[1][1:])
    Rn = int(tokens[2][1:])
    operand3 = tokens[3]

    if operand3[1:].isdigit():
        if operand3.startswith('W'):
            base_opcode = 0x2B200000
            shift_codes = {"UXTB": 0b000, "UXTH": 0b001, "UXTW": 0b010, "UXTX": 0b011, "SXTB": 0b100, "SXTH": 0b101, "SXTW": 0b110, "SXTX": 0b111}
            if len(tokens) == 4:
                Rm = int(tokens[3][1:])
                return base_opcode | Rd | (Rn << 5) | (Rm << 16) | SF
            elif len(tokens) > 4:
                Rm = int(operand3[1:])
                shift_type = tokens[4] 
                imm3 = int(tokens[5], 0)
                option = shift_codes.get(shift_type, 0b000)
                return base_opcode | Rd | (Rn << 5) | (Rm << 16) | (imm3 << 10) | (option << 13) | SF
        if operand3.startswith('X'):
            base_opcode = 0x2B000000
            shift_codes = {"LSL": 0b000, "LSR": 0b001, "ASR": 0b010, "RESERVED": 0b011}
            if len(tokens) == 4:
                Rm = int(operand3[1:])
                return base_opcode | Rd | (Rn << 5) | (Rm << 16) | SF
            elif len(tokens) > 4:
                Rm = int(operand3[1:])
                shift_type = tokens[4]
                imm6 = int(tokens[5], 0)
                shift = shift_codes.get(shift_type, 0b000)
                return base_opcode | Rd | (Rn << 5) | (Rm << 16) | (imm6 << 10) | (shift << 22) | SF
    if "@PAGEOFF" in operand3 or ":lo12:" in operand3:
        label_name = operand3.replace("@PAGEOFF", "").replace(":lo12:", "")
        
        if label_name not in symbol_table:
            raise ValueError(f"Undefined label: {label_name}")
            
        absolute_address = symbol_table[label_name]
        imm12 = absolute_address & 0xFFF
        
    elif operand3 in symbol_table:
        absolute_address = symbol_table[operand3]
        if absolute_address > 0xFFF:
            raise ValueError(f"Label '{operand3}' address requires @PAGEOFF modifier to fit in ADD instruction.")
        imm12 = absolute_address

    else:
        imm12 = int(operand3, 0) 
    base_opcode = 0x31000000
    return base_opcode | Rd | (Rn << 5) | (imm12 << 10) | SF


def encode_sub(tokens, current_pc, symbol_table):
    reg_str = tokens[1]
    SF = sf(reg_str)
    Rd = int(tokens[1][1:])
    Rn = int(tokens[2][1:])
    operand3 = tokens[3]

    if operand3[1:].isdigit():
        if operand3.startswith('W'):
            base_opcode = 0x4B200000
            shift_codes = {"UXTB": 0b000, "UXTH": 0b001, "UXTW": 0b010, "UXTX": 0b011, "SXTB": 0b100, "SXTH": 0b101, "SXTW": 0b110, "SXTX": 0b111}
            if len(tokens) == 4:
                Rm = int(tokens[3][1:])
                return base_opcode | Rd | (Rn << 5) | (Rm << 16) | SF
            elif len(tokens) > 4:
                Rm = int(operand3[1:])
                shift_type = tokens[4] 
                imm3 = int(tokens[5], 0)
                option = shift_codes.get(shift_type, 0b000)
                return base_opcode | Rd | (Rn << 5) | (Rm << 16) | (imm3 << 10) | (option << 13) | SF
        if operand3.startswith('X'):
            base_opcode = 0x4B000000
            shift_codes = {"LSL": 0b000, "LSR": 0b001, "ASR": 0b010, "RESERVED": 0b011}
            if len(tokens) == 4:
                Rm = int(operand3[1:])
                return base_opcode | Rd | (Rn << 5) | (Rm << 16) | SF
            elif len(tokens) > 4:
                Rm = int(operand3[1:])
                shift_type = tokens[4]
                imm6 = int(tokens[5], 0)
                shift = shift_codes.get(shift_type, 0b000)
                return base_opcode | Rd | (Rn << 5) | (Rm << 16) | (imm6 << 10) | (shift << 22) | SF
    if "@PAGEOFF" in operand3 or ":lo12:" in operand3:
        label_name = operand3.replace("@PAGEOFF", "").replace(":lo12:", "")
        
        if label_name not in symbol_table:
            raise ValueError(f"Undefined label: {label_name}")
            
        absolute_address = symbol_table[label_name]
        imm12 = absolute_address & 0xFFF
        
    elif operand3 in symbol_table:
        absolute_address = symbol_table[operand3]
        if absolute_address > 0xFFF:
            raise ValueError(f"Label '{operand3}' address requires @PAGEOFF modifier to fit in ADD instruction.")
        imm12 = absolute_address

    else:
        imm12 = int(operand3, 0) 
    base_opcode = 0x51000000
    return base_opcode | Rd | (Rn << 5) | (imm12 << 10) | SF

def encode_subs(tokens, current_pc, symbol_table):
    reg_str = tokens[1]
    SF = sf(reg_str)
    Rd = int(tokens[1][1:])
    Rn = int(tokens[2][1:])
    operand3 = tokens[3]

    if operand3[1:].isdigit():
        if operand3.startswith('W'):
            base_opcode = 0x6B200000
            shift_codes = {"UXTB": 0b000, "UXTH": 0b001, "UXTW": 0b010, "UXTX": 0b011, "SXTB": 0b100, "SXTH": 0b101, "SXTW": 0b110, "SXTX": 0b111}
            if len(tokens) == 4:
                Rm = int(tokens[3][1:])
                return base_opcode | Rd | (Rn << 5) | (Rm << 16) | SF
            elif len(tokens) > 4:
                Rm = int(operand3[1:])
                shift_type = tokens[4] 
                imm3 = int(tokens[5], 0)
                option = shift_codes.get(shift_type, 0b000)
                return base_opcode | Rd | (Rn << 5) | (Rm << 16) | (imm3 << 10) | (option << 13) | SF
        if operand3.startswith('X'):
            base_opcode = 0x6B000000
            shift_codes = {"LSL": 0b000, "LSR": 0b001, "ASR": 0b010, "RESERVED": 0b011}
            if len(tokens) == 4:
                Rm = int(operand3[1:])
                return base_opcode | Rd | (Rn << 5) | (Rm << 16) | SF
            elif len(tokens) > 4:
                Rm = int(operand3[1:])
                shift_type = tokens[4]
                imm6 = int(tokens[5], 0)
                shift = shift_codes.get(shift_type, 0b000)
                return base_opcode | Rd | (Rn << 5) | (Rm << 16) | (imm6 << 10) | (shift << 22) | SF
    if "@PAGEOFF" in operand3 or ":lo12:" in operand3:
        label_name = operand3.replace("@PAGEOFF", "").replace(":lo12:", "")
        
        if label_name not in symbol_table:
            raise ValueError(f"Undefined label: {label_name}")
            
        absolute_address = symbol_table[label_name]
        imm12 = absolute_address & 0xFFF
        
    elif operand3 in symbol_table:
        absolute_address = symbol_table[operand3]
        if absolute_address > 0xFFF:
            raise ValueError(f"Label '{operand3}' address requires @PAGEOFF modifier to fit in ADD instruction.")
        imm12 = absolute_address

    else:
        imm12 = int(operand3, 0) 
    base_opcode = 0x71000000
    return base_opcode | Rd | (Rn << 5) | (imm12 << 10) | SF

def encode_str(tokens, current_pc, symbol_table):
    reg_str = tokens[1]
    if reg_str.startswith('X'):
        SF = 0x40000000
    elif reg_str.startswith('W'):
        SF = 0
    open_bracket = tokens.index('[')
    Rt = int(tokens[1][1:])
    Rn = int(tokens[open_bracket + 1][1:])  # 'X1'

    #encode_str(['STR', 'X0', '[', 'X1', 'X2', ']'], 0x100000350, symbol_table)
    if len(tokens) == 6 and tokens[4][1:].isdigit():
        Rm = int(tokens[4][1:])
        base_opcode = 0xB8206800
        S = 0
        return base_opcode | Rt | (Rn << 5) | (Rm << 16) | (S << 12) | SF
    elif len(tokens) > 6 and tokens[4][1:].isdigit():
        Rm = int(tokens[4][1:])
        shift_type = tokens[5]
        S = 1
        shift_codes = {"LSL": 0b011, "UXTW": 0b010, "	SXTW": 0b110, "SXTX": 0b111}
        option = shift_codes.get(shift_type, 0b011)
        base_opcode = 0xB8200800
        return base_opcode | Rt | (Rn << 5) | (Rm << 16) | (option << 13) | (S << 12) | SF

    elif tokens[-1] == ']!':
        # 1. PRE-INDEXED: The exclamation mark is at the very end
        #encode_str(['STR', 'W0', '[', 'X1', '0x4', ']!'], 0x100000350, symbol_table)
        close_bracket = tokens.index(']!')
        base_opcode = 0xB8000000
        imm9 = int(tokens[close_bracket - 1], 0)
        if imm9 < 0:
            imm9 = 0b1000000000 + imm9
        size = 3
        return base_opcode | Rt | (Rn << 5) | (size << 10) | (imm9 << 12) | SF
    elif tokens[-1] == ']':
        # 2. UNSIGNED OFFSET: The offset token sits INSIDE before the closing bracket
        #encode_str(['STR', 'W0', '[', 'X1', '0x4', ']'], 0x100000350, symbol_table)
        close_bracket = tokens.index(']')
        base_opcode = 0xB9000000
        if len(tokens) == 5:
            imm12 = 0
        else:
            imm12 = int(tokens[close_bracket - 1], 0)  # 4
        return base_opcode | Rt | (Rn << 5) | (imm12 << 10) | SF
    # 3. POST-INDEXED: The offset token sits OUTSIDE and after the closing bracket
    #encode_str(['STR', 'W0', '[', 'X1', ']', '0x4'], 0x100000350, symbol_table)
    else:
        close_bracket = tokens.index(']')
        if close_bracket < len(tokens) - 1:
            base_opcode = 0xB8000000
            imm9 = int(tokens[close_bracket + 1], 0)  
            if imm9 < 0:
                imm9 = 0b1000000000 + imm9
            size = 1
            return base_opcode | Rt | (Rn << 5) | (size << 10) | (imm9 << 12) | SF

def encode_ldr(tokens, current_pc, symbol_table):
    reg_str = tokens[1]
    if reg_str.startswith('X'):
        SF = 0x40000000
    elif reg_str.startswith('W'):
        SF = 0

    if tokens[2] == '[':
        open_bracket = tokens.index('[')
        Rt = int(tokens[1][1:])
        Rn = int(tokens[open_bracket + 1][1:])  # 'X1'

        #encode_strb(['STRB', 'X0', '[', 'X1', 'X2', ']'], 0x100000350, symbol_table)
        if len(tokens) == 6 and tokens[4][1:].isdigit():
            Rm = int(tokens[4][1:])
            base_opcode = 0xB8606800
            S = 0
            return base_opcode | Rt | (Rn << 5) | (Rm << 16) | (S << 12) | SF
        #encode_strb(['STRB', 'X0', '[', 'X1', 'X2', ']'], 0x100000350, symbol_table)
        elif len(tokens) > 6 and tokens[4][1:].isdigit():
            Rm = int(tokens[4][1:])
            shift_type = tokens[5]
            S = 1
            # Map shift types to their 2-bit ARM64 hardware codes
            shift_codes = {"LSL": 0b011, "UXTW": 0b010, "	SXTW": 0b110, "SXTX": 0b111}
            option = shift_codes.get(shift_type, 0b011)
            base_opcode = 0xB8600800
            return base_opcode | Rt | (Rn << 5) | (Rm << 16) | (option << 13) | (S << 12) | SF

        elif tokens[-1] == ']!':
            # 1. PRE-INDEXED: The exclamation mark is at the very end
            #encode_ldr(['LDR', 'X0', '[', 'X1', '0x4', ']!'], 0x100000350, symbol_table)
            close_bracket = tokens.index(']!')
            base_opcode = 0xB8400000
            imm9 = int(tokens[close_bracket - 1], 0)
            if imm9 < 0:
                imm9 = 0b1000000000 + imm9
            size = 3
            return base_opcode | Rt | (Rn << 5) | (size << 10) | (imm9 << 12) | SF
        elif tokens[-1] == ']':
            # 2. UNSIGNED OFFSET: The offset token sits INSIDE before the closing bracket
            #encode_ldr(['LDR', 'X0', '[', 'X1', '0x4', ']'], 0x100000350, symbol_table)
            close_bracket = tokens.index(']')
            base_opcode = 0xB9400000
            if len(tokens) == 5:
                imm12 = 0
            else:
                imm12 = int(tokens[close_bracket - 1], 0)  # 4
            return base_opcode | Rt | (Rn << 5) | (imm12 << 10) | SF
        # 3. POST-INDEXED: The offset token sits OUTSIDE and after the closing bracket
        #encode_ldr(['LDR', 'X0', '[', 'X1', ']', '0x4'], 0x100000350, symbol_table)
        else:
            close_bracket = tokens.index(']')
            if close_bracket < len(tokens) - 1:
                base_opcode = 0xB8400000
                imm9 = int(tokens[close_bracket + 1], 0)  
                if imm9 < 0:
                    imm9 = 0b1000000000 + imm9
                size = 1
                return base_opcode | Rt | (Rn << 5) | (size << 10) | (imm9 << 12) | SF
    else:
        """Encodes an ARM64 ADR instruction by calculating a PC-relative offset.
        
        >>> symbol_table = {'_START': 0x100000328, 'MSG': 0x100000364}
        >>> encode_ldr(['LDR', 'X1', 'MSG'], 0x100000344, symbol_table)
        """
        lbl_name = tokens[2] # 'MSG'
        rd_num = int(tokens[1][1:]) # 'X1'
        target_address = symbol_table[lbl_name]
        imm19 = target_address - current_pc
        base_opcode = 0x18000000
        return base_opcode | (imm19 << 5) | rd_num | SF # suppose to have (imm19 << 3), but strange offset occurs

def encode_strb(tokens, current_pc, symbol_table):
    # Find the position index of the bracket tokens
    open_bracket = tokens.index('[')
    Xt = int(tokens[1][1:])
    Xn = int(tokens[open_bracket + 1][1:])  # 'X1'

    #encode_strb(['STRB', 'X0', '[', 'X1', 'X2', ']'], 0x100000350, symbol_table)
    # STRB <Xt>, [<Xn|SP>, (<Wm>|<Xm>){, LSL}]
    if len(tokens) == 6 and tokens[4][1:].isdigit():
        Xm = int(tokens[4][1:])
        base_opcode = 0x38206800
        S = 0
        return base_opcode | Xt | (Xn << 5) | (Xm << 16) | (S << 12)
    elif len(tokens) > 6 and tokens[4][1:].isdigit():
        Xm = int(tokens[4][1:])
        shift_type = tokens[5].upper() # LSL, LSR, ASR, ROR
        S = 1
        # Map shift types to their 2-bit ARM64 hardware codes
        shift_codes = {"LSL": 0b011, "UXTW": 0b010, "	SXTW": 0b110, "SXTX": 0b111}
        option = shift_codes.get(shift_type, 0b011)
        base_opcode = 0x38200800
        return base_opcode | Xt | (Xn << 5) | (Xm << 16) | (option << 13) | (S << 12)

    elif tokens[-1] == ']!':
        # 1. PRE-INDEXED: The exclamation mark is at the very end
        #encode_strb(['STRB', 'W0', '[', 'X1', '0x4', ']!'], 0x100000350, symbol_table)
        close_bracket = tokens.index(']!')
        base_opcode = 0x38000000
        imm9 = int(tokens[close_bracket - 1], 0)
        if imm9 < 0:
            imm9 = 0b1000000000 + imm9
        size = 3
        return base_opcode | Xt | (Xn << 5) | (size << 10) | (imm9 << 12)
    elif tokens[-1] == ']':
        # 2. UNSIGNED OFFSET: The offset token sits INSIDE before the closing bracket
        #encode_strb(['STRB', 'W0', '[', 'X1', '0x4', ']'], 0x100000350, symbol_table)
        close_bracket = tokens.index(']')
        base_opcode = 0x39000000
        if len(tokens) == 5:
            imm12 = 0
        else:
            imm12 = int(tokens[close_bracket - 1], 0)  # 4
        return base_opcode | Xt | (Xn << 5) | (imm12 << 10)
    # 3. POST-INDEXED: The offset token sits OUTSIDE and after the closing bracket
    #encode_strb(['STRB', 'W0', '[', 'X1', ']', '0x4'], 0x100000350, symbol_table)
    else:
        close_bracket = tokens.index(']')
        if close_bracket < len(tokens) - 1:
            base_opcode = 0x38000000
            imm9 = int(tokens[close_bracket + 1], 0)  
            if imm9 < 0:
                imm9 = 0b1000000000 + imm9
            size = 1
            return base_opcode | Xt | (Xn << 5) | (size << 10) | (imm9 << 12)

def encode_ldrb(tokens, current_pc, symbol_table):
    # Find the position index of the bracket tokens
    open_bracket = tokens.index('[')
    Xt = int(tokens[1][1:])
    Xn = int(tokens[open_bracket + 1][1:])  # 'X1'

    #encode_strb(['STRB', 'X0', '[', 'X1', 'X2', ']'], 0x100000350, symbol_table)
    # STRB <Xt>, [<Xn|SP>, (<Wm>|<Xm>){, LSL}]
    if len(tokens) == 6 and tokens[4][1:].isdigit():
        Xm = int(tokens[4][1:])
        base_opcode = 0x38606800
        S = 0
        return base_opcode | Xt | (Xn << 5) | (Xm << 16) | (S << 12)
    elif len(tokens) > 6 and tokens[4][1:].isdigit():
        Xm = int(tokens[4][1:])
        shift_type = tokens[5].upper() # LSL, LSR, ASR, ROR
        S = 1
        # Map shift types to their 2-bit ARM64 hardware codes
        shift_codes = {"LSL": 0b011, "UXTW": 0b010, "	SXTW": 0b110, "SXTX": 0b111}
        option = shift_codes.get(shift_type, 0b011)
        base_opcode = 0x38600800
        return base_opcode | Xt | (Xn << 5) | (Xm << 16) | (option << 13) | (S << 12)

    elif tokens[-1] == ']!':
        # 1. PRE-INDEXED: The exclamation mark is at the very end
        #encode_strb(['STRB', 'W0', '[', 'X1', '0x4', ']!'], 0x100000350, symbol_table)
        close_bracket = tokens.index(']!')
        base_opcode = 0x38400000
        imm9 = int(tokens[close_bracket - 1], 0)
        if imm9 < 0:
            imm9 = 0b1000000000 + imm9
        size = 3
        return base_opcode | Xt | (Xn << 5) | (size << 10) | (imm9 << 12)
    elif tokens[-1] == ']':
        # 2. UNSIGNED OFFSET: The offset token sits INSIDE before the closing bracket
        #encode_strb(['STRB', 'W0', '[', 'X1', '0x4', ']'], 0x100000350, symbol_table)
        close_bracket = tokens.index(']')
        base_opcode = 0x39400000
        if len(tokens) == 5:
            imm12 = 0
        else:
            imm12 = int(tokens[close_bracket - 1], 0)  # 4
        return base_opcode | Xt | (Xn << 5) | (imm12 << 10)
    # 3. POST-INDEXED: The offset token sits OUTSIDE and after the closing bracket
    #encode_strb(['STRB', 'W0', '[', 'X1', ']', '0x4'], 0x100000350, symbol_table)
    else:
        close_bracket = tokens.index(']')
        if close_bracket < len(tokens) - 1:
            base_opcode = 0x38400000
            imm9 = int(tokens[close_bracket + 1], 0)  
            if imm9 < 0:
                imm9 = 0b1000000000 + imm9
            size = 1
            return base_opcode | Xt | (Xn << 5) | (size << 10) | (imm9 << 12)

def encode_strh(tokens, current_pc, symbol_table):
    # Find the position index of the bracket tokens
    open_bracket = tokens.index('[')
    Xt = int(tokens[1][1:])
    Xn = int(tokens[open_bracket + 1][1:])  # 'X1'

    #encode_strb(['STRB', 'X0', '[', 'X1', 'X2', ']'], 0x100000350, symbol_table)
    # STRB <Xt>, [<Xn|SP>, (<Wm>|<Xm>){, LSL}]
    if len(tokens) == 6 and tokens[4][1:].isdigit():
        Xm = int(tokens[4][1:])
        base_opcode = 0x78206800
        S = 0
        return base_opcode | Xt | (Xn << 5) | (Xm << 16) | (S << 12)
    elif len(tokens) > 6 and tokens[4][1:].isdigit():
        Xm = int(tokens[4][1:])
        shift_type = tokens[5].upper() # LSL, LSR, ASR, ROR
        S = 1
        # Map shift types to their 2-bit ARM64 hardware codes
        shift_codes = {"LSL": 0b011, "UXTW": 0b010, "	SXTW": 0b110, "SXTX": 0b111}
        option = shift_codes.get(shift_type, 0b011)
        base_opcode = 0x78200800
        return base_opcode | Xt | (Xn << 5) | (Xm << 16) | (option << 13) | (S << 12)

    elif tokens[-1] == ']!':
        # 1. PRE-INDEXED: The exclamation mark is at the very end
        #encode_strb(['STRB', 'W0', '[', 'X1', '0x4', ']!'], 0x100000350, symbol_table)
        close_bracket = tokens.index(']!')
        base_opcode = 0x78000000
        imm9 = int(tokens[close_bracket - 1], 0)
        if imm9 < 0:
            imm9 = 0b1000000000 + imm9
        size = 3
        return base_opcode | Xt | (Xn << 5) | (size << 10) | (imm9 << 12)
    elif tokens[-1] == ']':
        # 2. UNSIGNED OFFSET: The offset token sits INSIDE before the closing bracket
        #encode_strb(['STRB', 'W0', '[', 'X1', '0x4', ']'], 0x100000350, symbol_table)
        close_bracket = tokens.index(']')
        base_opcode = 0x79000000
        if len(tokens) == 5:
            imm12 = 0
        else:
            imm12 = int(tokens[close_bracket - 1], 0)  # 4
        return base_opcode | Xt | (Xn << 5) | (imm12 << 10)
    # 3. POST-INDEXED: The offset token sits OUTSIDE and after the closing bracket
    #encode_strb(['STRB', 'W0', '[', 'X1', ']', '0x4'], 0x100000350, symbol_table)
    else:
        close_bracket = tokens.index(']')
        if close_bracket < len(tokens) - 1:
            base_opcode = 0x78000000
            imm9 = int(tokens[close_bracket + 1], 0)  
            if imm9 < 0:
                imm9 = 0b1000000000 + imm9
            size = 1
            return base_opcode | Xt | (Xn << 5) | (size << 10) | (imm9 << 12)
        
def encode_ldrh(tokens, current_pc, symbol_table):
    # Find the position index of the bracket tokens
    open_bracket = tokens.index('[')
    Xt = int(tokens[1][1:])
    Xn = int(tokens[open_bracket + 1][1:])  # 'X1'

    #encode_strb(['STRB', 'X0', '[', 'X1', 'X2', ']'], 0x100000350, symbol_table)
    # STRB <Xt>, [<Xn|SP>, (<Wm>|<Xm>){, LSL}]
    if len(tokens) == 6 and tokens[4][1:].isdigit():
        Xm = int(tokens[4][1:])
        base_opcode = 0x78606800
        S = 0
        return base_opcode | Xt | (Xn << 5) | (Xm << 16) | (S << 12)
    elif len(tokens) > 6 and tokens[4][1:].isdigit():
        Xm = int(tokens[4][1:])
        shift_type = tokens[5].upper() # LSL, LSR, ASR, ROR
        S = 1
        # Map shift types to their 2-bit ARM64 hardware codes
        shift_codes = {"LSL": 0b011, "UXTW": 0b010, "	SXTW": 0b110, "SXTX": 0b111}
        option = shift_codes.get(shift_type, 0b011)
        base_opcode = 0x78600800
        return base_opcode | Xt | (Xn << 5) | (Xm << 16) | (option << 13) | (S << 12)

    elif tokens[-1] == ']!':
        # 1. PRE-INDEXED: The exclamation mark is at the very end
        #encode_strb(['STRB', 'W0', '[', 'X1', '0x4', ']!'], 0x100000350, symbol_table)
        close_bracket = tokens.index(']!')
        base_opcode = 0x78400000
        imm9 = int(tokens[close_bracket - 1], 0)
        if imm9 < 0:
            imm9 = 0b1000000000 + imm9
        size = 3
        return base_opcode | Xt | (Xn << 5) | (size << 10) | (imm9 << 12)
    elif tokens[-1] == ']':
        # 2. UNSIGNED OFFSET: The offset token sits INSIDE before the closing bracket
        #encode_strb(['STRB', 'W0', '[', 'X1', '0x4', ']'], 0x100000350, symbol_table)
        close_bracket = tokens.index(']')
        base_opcode = 0x79400000
        if len(tokens) == 5:
            imm12 = 0
        else:
            imm12 = int(tokens[close_bracket - 1], 0)  # 4
        return base_opcode | Xt | (Xn << 5) | (imm12 << 10)
    # 3. POST-INDEXED: The offset token sits OUTSIDE and after the closing bracket
    #encode_strb(['STRB', 'W0', '[', 'X1', ']', '0x4'], 0x100000350, symbol_table)
    else:
        close_bracket = tokens.index(']')
        if close_bracket < len(tokens) - 1:
            base_opcode = 0x78400000
            imm9 = int(tokens[close_bracket + 1], 0)  
            if imm9 < 0:
                imm9 = 0b1000000000 + imm9
            size = 1
            return base_opcode | Xt | (Xn << 5) | (size << 10) | (imm9 << 12)

def encode_stur(tokens, current_pc, symbol_table):
    open_bracket = tokens.index('[')
    close_bracket = tokens.index(']')
    reg_str = tokens[1]
    if reg_str.startswith('X'):
        SF = 0x40000000
    elif reg_str.startswith('W'):
        SF = 0
    Rt = int(tokens[1][1:])
    Rn = int(tokens[open_bracket + 1][1:])  
    imm9 = int(tokens[close_bracket - 1], 0)
    if imm9 < 0:
        imm9 = 0b1000000000 + imm9
    base_opcode = 0xB8000000
    return base_opcode | Rt | (Rn << 5) | (imm9 << 12) | SF

def encode_sturb(tokens, current_pc, symbol_table):
    open_bracket = tokens.index('[')
    close_bracket = tokens.index(']')
    Wt = int(tokens[1][1:])
    Xn = int(tokens[open_bracket + 1][1:])  
    imm9 = int(tokens[close_bracket - 1], 0)
    if imm9 < 0:
        imm9 = 0b1000000000 + imm9
    base_opcode = 0x38000000
    return base_opcode | Wt | (Xn << 5) | (imm9 << 12)

def encode_sturh(tokens, current_pc, symbol_table):
    open_bracket = tokens.index('[')
    close_bracket = tokens.index(']')
    Wt = int(tokens[1][1:])
    Xn = int(tokens[open_bracket + 1][1:])  
    imm9 = int(tokens[close_bracket - 1], 0)
    if imm9 < 0:
        imm9 = 0b1000000000 + imm9
    base_opcode = 0x78000000
    return base_opcode | Wt | (Xn << 5) | (imm9 << 12)

def encode_ldur(tokens, current_pc, symbol_table):
    open_bracket = tokens.index('[')
    close_bracket = tokens.index(']')
    reg_str = tokens[1]
    if reg_str.startswith('X'):
        SF = 0x40000000
    elif reg_str.startswith('W'):
        SF = 0
    Rt = int(tokens[1][1:])
    Rn = int(tokens[open_bracket + 1][1:])  
    imm9 = int(tokens[close_bracket - 1], 0)
    if imm9 < 0:
        imm9 = 0b1000000000 + imm9
    base_opcode = 0xB8400000
    return base_opcode | Rt | (Rn << 5) | (imm9 << 12) | SF

def encode_ldurb(tokens, current_pc, symbol_table):
    open_bracket = tokens.index('[')
    close_bracket = tokens.index(']')
    Wt = int(tokens[1][1:])
    Xn = int(tokens[open_bracket + 1][1:])  
    imm9 = int(tokens[close_bracket - 1], 0)
    if imm9 < 0:
        imm9 = 0b1000000000 + imm9
    base_opcode = 0x38400000
    return base_opcode | Wt | (Xn << 5) | (imm9 << 12)

def encode_ldurh(tokens, current_pc, symbol_table):
    open_bracket = tokens.index('[')
    close_bracket = tokens.index(']')
    Xt = int(tokens[1][1:])
    Wn = int(tokens[open_bracket + 1][1:])  
    imm9 = int(tokens[close_bracket - 1], 0)
    if imm9 < 0:
        imm9 = 0b1000000000 + imm9
    base_opcode = 0x78400000
    return base_opcode | Xt | (Wn << 5) | (imm9 << 12)

def encode_ldursb(tokens, current_pc, symbol_table):
    open_bracket = tokens.index('[')
    close_bracket = tokens.index(']')
    reg_str = tokens[1]
    if reg_str.startswith('X'):
        SF = 0x400000
    elif reg_str.startswith('W'):
        SF = 0
    Rt = int(tokens[1][1:])
    Xn = int(tokens[open_bracket + 1][1:])  
    imm9 = int(tokens[close_bracket - 1], 0)
    if imm9 < 0:
        imm9 = 0b1000000000 + imm9
    base_opcode = 0x38400000
    return base_opcode | Rt | (Xn << 5) | (imm9 << 12) | SF

def encode_ldursh(tokens, current_pc, symbol_table):
    open_bracket = tokens.index('[')
    close_bracket = tokens.index(']')
    reg_str = tokens[1]
    if reg_str.startswith('X'):
        SF = 0x400000
    elif reg_str.startswith('W'):
        SF = 0
    Rt = int(tokens[1][1:])
    Xn = int(tokens[open_bracket + 1][1:])  
    imm9 = int(tokens[close_bracket - 1], 0)
    if imm9 < 0:
        imm9 = 0b1000000000 + imm9
    base_opcode = 0x78400000
    return base_opcode | Rt | (Xn << 5) | (imm9 << 12) | SF

def encode_ldursw(tokens, current_pc, symbol_table):
    open_bracket = tokens.index('[')
    close_bracket = tokens.index(']')
    Xt = int(tokens[1][1:])
    Xn = int(tokens[open_bracket + 1][1:])  
    imm9 = int(tokens[close_bracket - 1], 0)
    if imm9 < 0:
        imm9 = 0b1000000000 + imm9
    base_opcode = 0xB8800000
    return base_opcode | Xt | (Xn << 5) | (imm9 << 12)

def encode_ldrsb(tokens, current_pc, symbol_table):
    # Find the position index of the bracket tokens
    open_bracket = tokens.index('[')
    Rt = int(tokens[1][1:])
    Rn = int(tokens[open_bracket + 1][1:])  # 'X1'
    reg_str = tokens[1]
    if reg_str.startswith('W'):
        SF = 0x400000
    elif reg_str.startswith('X'):
        SF = 0

    #encode_strb(['STRB', 'X0', '[', 'X1', 'X2', ']'], 0x100000350, symbol_table)
    # STRB <Xt>, [<Xn|SP>, (<Wm>|<Xm>){, LSL}]
    if len(tokens) == 6 and tokens[4][1:].isdigit():
        Rm = int(tokens[4][1:])
        base_opcode = 0x38A06800
        S = 0
        return base_opcode | Rt | (Rn << 5) | (Rm << 16) | (S << 12) | SF
    elif len(tokens) > 6 and tokens[4][1:].isdigit():
        Rm = int(tokens[4][1:])
        shift_type = tokens[5].upper() # LSL, LSR, ASR, ROR
        S = 1
        # Map shift types to their 2-bit ARM64 hardware codes
        shift_codes = {"LSL": 0b011, "UXTW": 0b010, "	SXTW": 0b110, "SXTX": 0b111}
        option = shift_codes.get(shift_type, 0b011)
        base_opcode = 0x38A00800
        return base_opcode | Rt | (Rn << 5) | (Rm << 16) | (option << 13) | (S << 12) | SF

    elif tokens[-1] == ']!':
        # 1. PRE-INDEXED: The exclamation mark is at the very end
        #encode_strb(['STRB', 'W0', '[', 'X1', '0x4', ']!'], 0x100000350, symbol_table)
        close_bracket = tokens.index(']!')
        base_opcode = 0x38800000
        imm9 = int(tokens[close_bracket - 1], 0)
        if imm9 < 0:
            imm9 = 0b1000000000 + imm9
        size = 3
        return base_opcode | Rt | (Rn << 5) | (size << 10) | (imm9 << 12) | SF
    elif tokens[-1] == ']':
        # 2. UNSIGNED OFFSET: The offset token sits INSIDE before the closing bracket
        #encode_strb(['STRB', 'W0', '[', 'X1', '0x4', ']'], 0x100000350, symbol_table)
        close_bracket = tokens.index(']')
        base_opcode = 0x39800000
        if len(tokens) == 5:
            imm12 = 0
        else:
            imm12 = int(tokens[close_bracket - 1], 0)  # 4
        return base_opcode | Rt | (Rn << 5) | (imm12 << 10) | SF
    # 3. POST-INDEXED: The offset token sits OUTSIDE and after the closing bracket
    #encode_strb(['STRB', 'W0', '[', 'X1', ']', '0x4'], 0x100000350, symbol_table)
    else:
        close_bracket = tokens.index(']')
        if close_bracket < len(tokens) - 1:
            base_opcode = 0x38800000
            imm9 = int(tokens[close_bracket + 1], 0) 
            if imm9 < 0:
                imm9 = 0b1000000000 + imm9 
            size = 1
            return base_opcode | Rt | (Rn << 5) | (size << 10) | (imm9 << 12) | SF
        
def encode_ldrsh(tokens, current_pc, symbol_table):
    # Find the position index of the bracket tokens
    open_bracket = tokens.index('[')
    Rt = int(tokens[1][1:])
    Rn = int(tokens[open_bracket + 1][1:])  # 'X1'
    reg_str = tokens[1]
    if reg_str.startswith('W'):
        SF = 0x400000
    elif reg_str.startswith('X'):
        SF = 0

    #encode_strb(['STRB', 'X0', '[', 'X1', 'X2', ']'], 0x100000350, symbol_table)
    # STRB <Xt>, [<Xn|SP>, (<Wm>|<Xm>){, LSL}]
    if len(tokens) == 6 and tokens[4][1:].isdigit():
        Rm = int(tokens[4][1:])
        base_opcode = 0x78A06800
        S = 0
        return base_opcode | Rt | (Rn << 5) | (Rm << 16) | (S << 12) | SF
    elif len(tokens) > 6 and tokens[4][1:].isdigit():
        Rm = int(tokens[4][1:])
        shift_type = tokens[5].upper() # LSL, LSR, ASR, ROR
        S = 1
        # Map shift types to their 2-bit ARM64 hardware codes
        shift_codes = {"LSL": 0b011, "UXTW": 0b010, "	SXTW": 0b110, "SXTX": 0b111}
        option = shift_codes.get(shift_type, 0b011)
        base_opcode = 0x78A00800
        return base_opcode | Rt | (Rn << 5) | (Rm << 16) | (option << 13) | (S << 12) | SF

    elif tokens[-1] == ']!':
        # 1. PRE-INDEXED: The exclamation mark is at the very end
        #encode_strb(['STRB', 'W0', '[', 'X1', '0x4', ']!'], 0x100000350, symbol_table)
        close_bracket = tokens.index(']!')
        base_opcode = 0x78800000
        imm9 = int(tokens[close_bracket - 1], 0)
        if imm9 < 0:
            imm9 = 0b1000000000 + imm9
        size = 3
        return base_opcode | Rt | (Rn << 5) | (size << 10) | (imm9 << 12) | SF
    elif tokens[-1] == ']':
        # 2. UNSIGNED OFFSET: The offset token sits INSIDE before the closing bracket
        #encode_strb(['STRB', 'W0', '[', 'X1', '0x4', ']'], 0x100000350, symbol_table)
        close_bracket = tokens.index(']')
        base_opcode = 0x79800000
        if len(tokens) == 5:
            imm12 = 0
        else:
            imm12 = int(tokens[close_bracket - 1], 0)  # 4
        return base_opcode | Rt | (Rn << 5) | (imm12 << 10) | SF
    # 3. POST-INDEXED: The offset token sits OUTSIDE and after the closing bracket
    #encode_strb(['STRB', 'W0', '[', 'X1', ']', '0x4'], 0x100000350, symbol_table)
    else:
        close_bracket = tokens.index(']')
        if close_bracket < len(tokens) - 1:
            base_opcode = 0x78800000
            imm9 = int(tokens[close_bracket + 1], 0)  
            if imm9 < 0:
                imm9 = 0b1000000000 + imm9
            size = 1
            return base_opcode | Rt | (Rn << 5) | (size << 10) | (imm9 << 12) | SF

def encode_ldrsw(tokens, current_pc, symbol_table):
    # Find the position index of the bracket tokens
    if tokens[2] == '[':
        open_bracket = tokens.index('[')
        Xt = int(tokens[1][1:])
        Xn = int(tokens[open_bracket + 1][1:])  # 'X1'

        #encode_strb(['STRB', 'X0', '[', 'X1', 'X2', ']'], 0x100000350, symbol_table)
        if len(tokens) == 6 and tokens[4][1:].isdigit():
            Xm = int(tokens[4][1:])
            base_opcode = 0xB8A06800
            S = 0
            return base_opcode | Xt | (Xn << 5) | (Xm << 16) | (S << 12)
        #encode_strb(['STRB', 'X0', '[', 'X1', 'X2', ']'], 0x100000350, symbol_table)
        elif len(tokens) > 6 and tokens[4][1:].isdigit():
            Xm = int(tokens[4][1:])
            shift_type = tokens[5].upper() # LSL, LSR, ASR, ROR
            S = 1
            # Map shift types to their 2-bit ARM64 hardware codes
            shift_codes = {"LSL": 0b011, "UXTW": 0b010, "	SXTW": 0b110, "SXTX": 0b111}
            option = shift_codes.get(shift_type, 0b011)
            base_opcode = 0xB8A00800
            return base_opcode | Xt | (Xn << 5) | (Xm << 16) | (option << 13) | (S << 12)

        elif tokens[-1] == ']!':
            # 1. PRE-INDEXED: The exclamation mark is at the very end
            #encode_ldr(['LDR', 'X0', '[', 'X1', '0x4', ']!'], 0x100000350, symbol_table)
            close_bracket = tokens.index(']!')
            base_opcode = 0xB8800000
            imm9 = int(tokens[close_bracket - 1], 0)
            if imm9 < 0:
                imm9 = 0b1000000000 + imm9
            size = 3
            return base_opcode | Xt | (Xn << 5) | (size << 10) | (imm9 << 12)
        elif tokens[-1] == ']':
            # 2. UNSIGNED OFFSET: The offset token sits INSIDE before the closing bracket
            #encode_ldr(['LDR', 'X0', '[', 'X1', '0x4', ']'], 0x100000350, symbol_table)
            close_bracket = tokens.index(']')
            base_opcode = 0xB9800000
            if len(tokens) == 5:
                imm12 = 0
            else:
                imm12 = int(tokens[close_bracket - 1], 0)  # 4
            return base_opcode | Xt | (Xn << 5) | (imm12 << 10)
        # 3. POST-INDEXED: The offset token sits OUTSIDE and after the closing bracket
        #encode_ldr(['LDR', 'X0', '[', 'X1', ']', '0x4'], 0x100000350, symbol_table)
        else:
            close_bracket = tokens.index(']')
            if close_bracket < len(tokens) - 1:
                base_opcode = 0xB8800000
                imm9 = int(tokens[close_bracket + 1], 0)  
                if imm9 < 0:
                    imm9 = 0b1000000000 + imm9
                size = 1
                return base_opcode | Xt | (Xn << 5) | (size << 10) | (imm9 << 12)
    else:
        """Encodes an ARM64 ADR instruction by calculating a PC-relative offset.
        
        >>> symbol_table = {'_START': 0x100000328, 'MSG': 0x100000364}
        >>> encode_ldrsw(['LDRSW', 'X1', 'MSG'], 0x100000344, symbol_table)
        """
        lbl_name = tokens[2] # 'MSG'
        rd_num = int(tokens[1][1:]) # 'X1'
        target_address = symbol_table[lbl_name]
        imm19 = target_address - current_pc
        base_opcode = 0x98000000
        return base_opcode | (imm19 << 5) | rd_num # suppose to have (imm19 << 3), but strange offset occurs

def encode_stp(tokens, current_pc, symbol_table):
    reg_str = tokens[1]
    SF = sf(reg_str)
    open_bracket = tokens.index('[')
    Rt1 = int(tokens[1][1:])
    Rt2 = int(tokens[2][1:])
    Rn = int(tokens[open_bracket + 1][1:])

    if tokens[-1] == ']!':
        # 1. PRE-INDEXED: The exclamation mark is at the very end
        #encode_stp(['STP', 'X0', 'X1', '[', 'X2', '0x4', ']!'], 0x100000350, symbol_table)
        close_bracket = tokens.index(']!')
        base_opcode = 0x29800000
        imm7 = int(tokens[close_bracket - 1], 0)
        if imm7 < 0:
            imm7 = 0b10000000 + imm7
        return base_opcode | Rt1 | (Rn << 5) | (Rt2 << 10) | (imm7 << 15) | SF
    elif tokens[-1] == ']':
        # 2. SIGNED OFFSET: The offset token sits INSIDE before the closing bracket
        #encode_stp(['STP', 'X0', 'X1', '[', 'X2', '0x4', ']'], 0x100000350, symbol_table)
        close_bracket = tokens.index(']')
        base_opcode = 0x29000000
        if len(tokens) == 6:
            imm7 = 0
        else:
            imm7 = int(tokens[close_bracket - 1], 0)  # 4
            if imm7 < 0:
                imm7 = 0b10000000 + imm7
        return base_opcode | Rt1 | (Rn << 5) | (Rt2 << 10) | (imm7 << 15) | SF
    # 3. POST-INDEXED: The offset token sits OUTSIDE and after the closing bracket
    #encode_stp(['STP', 'X0', 'X1', '[', 'X2', ']', '0x4'], 0x100000350, symbol_table)
    else:
        close_bracket = tokens.index(']')
        if close_bracket < len(tokens) - 1:
            base_opcode = 0x28800000
            imm7 = int(tokens[close_bracket + 1], 0)  
            if imm7 < 0:
                imm7 = 0b10000000 + imm7
            return base_opcode | Rt1 | (Rn << 5) | (Rt2 << 10) | (imm7 << 15) | SF

def encode_ldp(tokens, current_pc, symbol_table):
    reg_str = tokens[1]
    SF = sf(reg_str)
    open_bracket = tokens.index('[')
    Rt1 = int(tokens[1][1:])
    Rt2 = int(tokens[2][1:])
    Rn = int(tokens[open_bracket + 1][1:])

    if tokens[-1] == ']!':
        # 1. PRE-INDEXED: The exclamation mark is at the very end
        #encode_ldp(['LDP', 'X0', 'X1', '[', 'X2', '0x4', ']!'], 0x100000350, symbol_table)
        close_bracket = tokens.index(']!')
        base_opcode = 0x29C00000
        imm7 = int(tokens[close_bracket - 1], 0)
        if imm7 < 0:
            imm7 = 0b10000000 + imm7
        return base_opcode | Rt1 | (Rn << 5) | (Rt2 << 10) | (imm7 << 15) | SF
    elif tokens[-1] == ']':
        # 2. SIGNED OFFSET: The offset token sits INSIDE before the closing bracket
        #encode_ldp(['LDP', 'X0', 'X1', '[', 'X2', '0x4', ']'], 0x100000350, symbol_table)
        close_bracket = tokens.index(']')
        base_opcode = 0x29400000
        if len(tokens) == 6:
            imm7 = 0
        else:
            imm7 = int(tokens[close_bracket - 1], 0)  # 4
        if imm7 < 0:
            imm7 = 0b10000000 + imm7
        return base_opcode | Rt1 | (Rn << 5) | (Rt2 << 10) | (imm7 << 15) | SF
    # 3. POST-INDEXED: The offset token sits OUTSIDE and after the closing bracket
    #encode_ldp(['LDP', 'X0', 'X1', '[', 'X2', ']', '0x4'], 0x100000350, symbol_table)
    else:
        close_bracket = tokens.index(']')
        if close_bracket < len(tokens) - 1:
            base_opcode = 0x28C00000
            imm7 = int(tokens[close_bracket + 1], 0)  
            if imm7 < 0:
                imm7 = 0b10000000 + imm7
            return base_opcode | Rt1 | (Rn << 5) | (Rt2 << 10) | (imm7 << 15) | SF

def encode_b(tokens, current_pc, symbol_table):
    """Encodes an unconditional branch (B). Range: +/- 128MB.
    
    >>> symbol_table = {'_START': 0x100000328, 'MSG': 0x100000364}
    >>> encode_b(['B', 'MSG'], 0x100000344, symbol_table)
    335544328
    """
    lbl_name = tokens[1]
    if lbl_name not in symbol_table:
        raise ValueError(f"Undefined label: {lbl_name}")
        
    target_address = symbol_table[lbl_name]
    byte_offset = target_address - current_pc
    
    # Mathematical correction: Branch offsets are stored as word counts (bytes / 4)
    word_offset = byte_offset >> 2
    
    # B takes a signed 26-bit immediate value (-33554432 to 33554431 words)
    if not (-33554432 <= word_offset < 33554432):
        raise ValueError("Branch target out of range (+/- 128MB).")
        
    # Mask to 26 bits to eliminate Python negative sign extension
    imm26 = word_offset & 0x3FFFFFF
    
    base_opcode = 0x14000000
    return base_opcode | imm26

def encode_bcond(tokens, current_pc, symbol_table):
    """Encodes a conditional branch (B.cond). Range: +/- 1MB.
    >>> symbol_table = {'_START': 0x100000328, 'MSG': 0x100000364}
    >>> encode_bcond(['B.', 'EQ', 'MSG'], 0x100000344, symbol_table)
    1409286400
    """
    cond = tokens[1]
    lbl_name = tokens[2]
    
    if lbl_name not in symbol_table:
        raise ValueError(f"Undefined label: {lbl_name}")
        
    target_address = symbol_table[lbl_name]
    byte_offset = target_address - current_pc
    
    # Mathematical correction: Divide byte offset by 4
    word_offset = byte_offset >> 2
    
    # B.cond takes a signed 19-bit immediate value (-262144 to 262143 words)
    if not (-262144 <= word_offset < 262144):
        raise ValueError("Conditional branch target out of range (+/- 1MB).")
        
    # Mask to 19 bits to eliminate Python negative sign extension
    imm19 = word_offset & 0x7FFFF
    
    # Fixed typo from "EG" to "EQ"
    cond_codes = {
        "EQ": 0b0000, "NE": 0b0001, "CS": 0b0010, "CC": 0b0011,
        "MI": 0b0100, "PL": 0b0101, "VS": 0b0110, "VC": 0b0111,
        "HI": 0b1000, "LS": 0b1001, "GE": 0b1010, "LT": 0b1011,
        "GT": 0b1100, "LE": 0b1101, "AL": 0b1110, "NV": 0b1111
    }
    
    if cond not in cond_codes:
        raise ValueError(f"Unknown condition code: {cond}")
        
    cond_opcode = cond_codes[cond]
    base_opcode = 0x54000000
    
    # imm19 starts at bit position 5
    return base_opcode | (imm19 << 5) | cond_opcode

def encode_bc(tokens, current_pc, symbol_table):
    """
    Encodes a modern ARM64 BC.cond instruction (Branch Consistent).
    >>> symbol_table = {'_START': 0x100000328, 'MSG': 0x100000364}
    >>> encode_bc(['BC.', 'EQ', 'MSG'], 0x100000344, symbol_table)
    1409287168
    """
    cond = tokens[1].upper() # 'EQ'
    lbl_name = tokens[2]    # 'MSG'
    
    if lbl_name not in symbol_table:
        raise ValueError(f"Undefined label: {lbl_name}")
        
    target_address = symbol_table[lbl_name]
    byte_offset = target_address - current_pc
    
    # 1. Hardware requires byte offsets divided by 4 instructions
    word_offset = byte_offset >> 2
    
    # 2. Check signed 19-bit boundary limits (+/- 1MB range)
    if not (-262144 <= word_offset < 262144):
        raise ValueError("BC.cond branch target out of range (+/- 1MB).")
        
    # 3. Mask to 19 bits to prevent negative sign leaks in Python
    imm19 = word_offset & 0x7FFFF
    
    # 4. Standard condition mapping codes
    cond_codes = {
        "EQ": 0b0000, "NE": 0b0001, "CS": 0b0010, "CC": 0b0011,
        "MI": 0b0100, "PL": 0b0101, "VS": 0b0110, "VC": 0b0111,
        "HI": 0b1000, "LS": 0b1001, "GE": 0b1010, "LT": 0b1011,
        "GT": 0b1100, "LE": 0b1101, "AL": 0b1110, "NV": 0b1111
    }
    
    if cond not in cond_codes:
        raise ValueError(f"Unknown condition code: {cond}")
        
    cond_opcode = cond_codes[cond]
    
    # 5. Base opcode for BC.cond is 0x54000010
    base_opcode = 0x54000010
    
    # Mathematical assembly:
    # Opcode goes wide, imm19 shifts left 5 spaces, cond goes to bits 0-3
    return base_opcode | (imm19 << 5) | cond_opcode

def encode_bl(tokens, current_pc, symbol_table):
    """Encodes a function call branch (BL). Range: +/- 128MB.
    >>> symbol_table = {'_START': 0x100000328, 'MSG': 0x100000364}
    >>> encode_bl(['BL', 'MSG'], 0x100000344, symbol_table)
    2483027976
    """
    lbl_name = tokens[1]
    if lbl_name not in symbol_table:
        raise ValueError(f"Undefined label: {lbl_name}")
        
    target_address = symbol_table[lbl_name]
    byte_offset = target_address - current_pc
    
    # Mathematical correction: Branch offsets are stored as word counts (bytes / 4)
    word_offset = byte_offset >> 2
    
    # BL takes a signed 26-bit immediate value (-33554432 to 33554431 words)
    if not (-33554432 <= word_offset < 33554432):
        raise ValueError("BL branch target out of range (+/- 128MB).")
        
    # Mask to 26 bits to eliminate Python negative sign extension leaks
    imm26 = word_offset & 0x3FFFFFF
    
    base_opcode = 0x94000000
    return base_opcode | imm26

def encode_br(tokens, current_pc, symbol_table):
    """Encodes an unconditional branch to a register (BR).
    >>> symbol_table = {'_START': 0x100000328, 'MSG': 0x100000364}
    >>> encode_br(['BR', 'X1'], 0x100000344, symbol_table)
    3592355872
    """
    reg_str = tokens[1]
    
    # BR strictly requires a 64-bit X register (X0-X30)
    if not reg_str.startswith('X') or reg_str == 'SP':
        raise ValueError("BR requires a valid 64-bit general-purpose register (X0-X30).")
        
    Xn = int(reg_str[1:])
    if not (0 <= Xn <= 30):
        raise ValueError("BR register index must be between 0 and 30.")
        
    base_opcode = 0xD61F0000
    return base_opcode | (Xn << 5)

def encode_blr(tokens, current_pc, symbol_table):
    """Encodes a function call branch to a register (BLR).
    >>> symbol_table = {'_START': 0x100000328, 'MSG': 0x100000364}
    >>> encode_blr(['BLR', 'X1'], 0x100000344, symbol_table)
    3594453024
    """
    reg_str = tokens[1]
    
    # BLR strictly requires a 64-bit X register (X0-X30)
    if not reg_str.startswith('X') or reg_str == 'SP':
        raise ValueError("BLR requires a valid 64-bit general-purpose register (X0-X30).")
        
    Xn = int(reg_str[1:])
    if not (0 <= Xn <= 30):
        raise ValueError("BLR register index must be between 0 and 30.")
        
    base_opcode = 0xD63F0000
    return base_opcode | (Xn << 5)

def encode_cbz(tokens, current_pc, symbol_table):
    """Encodes a Compare and Branch if Zero (CBZ) instruction. Range: +/- 1MB.
    >>> symbol_table = {'_START': 0x100000328, 'MSG': 0x100000364}
    >>> encode_cbz(['CBZ', 'X1', 'MSG'], 0x100000344, symbol_table)
    3019899137
    """
    reg_str = tokens[1].upper()
    lbl_name = tokens[2]
    
    # 1. Determine size flag (SF) at bit 31
    if reg_str.startswith('X'):
        SF = 0x80000000
    elif reg_str.startswith('W'):
        SF = 0x00000000
    else:
        raise ValueError("CBZ/CBNZ requires a valid X or W register.")
        
    Rt = int(reg_str[1:])
    if not (0 <= Rt <= 30):
        raise ValueError("Register index must be between 0 and 30 (XZR/WZR not allowed here).")

    if lbl_name not in symbol_table:
        raise ValueError(f"Undefined label: {lbl_name}")
        
    target_address = symbol_table[lbl_name]
    byte_offset = target_address - current_pc
    
    # 2. Convert bytes to instruction/word count (divide by 4)
    word_offset = byte_offset >> 2
    
    # 3. CBZ takes a signed 19-bit immediate field (-262144 to 262143 words)
    if not (-262144 <= word_offset < 262144):
        raise ValueError("Branch target out of range (+/- 1MB).")
        
    # 4. Mask to 19 bits to kill Python negative sign extension
    imm19 = word_offset & 0x7FFFF
    
    # Base opcode for 32-bit CBZ is 0x34000000
    base_opcode = 0x34000000
    
    # Mathematical layout: SF at bit 31, imm19 shifted by 5, Rt at bits 0-4
    return base_opcode | SF | (imm19 << 5) | Rt


def encode_cbnz(tokens, current_pc, symbol_table):
    """Encodes a Compare and Branch if Non-Zero (CBNZ) instruction.
    >>> symbol_table = {'_START': 0x100000328, 'MSG': 0x100000364}
    >>> encode_cbnz(['CBNZ', 'X1', 'MSG'], 0x100000344, symbol_table)
    """
    # CBNZ is identical to CBZ, but bit 24 is flipped to 1 (0x01000000)
    return encode_cbz(tokens, current_pc, symbol_table) | 0x01000000

def encode_cmp(tokens, current_pc, symbol_table):
    """
    Encodes the CMP instruction (an alias for SUBS with Rd = XZR/WZR).
    Expected tokens format: 
      - Immediate: ['CMP', 'X0', '10'] or ['CMP', 'X0', 'MSG@PAGEOFF']
      - Register:  ['CMP', 'X0', 'X1'] or ['CMP', 'X0', 'X1', 'LSL', '2']
    """
    reg_str = tokens[1]
    SF = sf(reg_str)
    Rn = int(reg_str[1:])
    Rd = 31  # Target is always XZR/WZR (31) to discard the result
    
    operand2 = tokens[2]
    imm12 = None
    
    # Parse labels and page offset modifiers
    if "@PAGEOFF" in operand2 or ":lo12:" in operand2:
        label_name = operand2.replace("@PAGEOFF", "").replace(":lo12:", "")
        if label_name not in symbol_table:
            raise ValueError(f"Undefined label: {label_name}")
        imm12 = symbol_table[label_name] & 0xFFF
    elif operand2 in symbol_table:
        imm12 = symbol_table[operand2] & 0xFFF
        
    # Check if operand2 is a raw numeric immediate value
    if imm12 is None:
        try:
            imm12 = int(operand2, 0)
        except ValueError:
            imm12 = None  # Process as a register operand instead

    # --- Variant A: CMP (immediate) ---
    if imm12 is not None:
        if not (0 <= imm12 <= 4095):
            raise ValueError("CMP immediate value must be a 12-bit number (0-4095).")
        base_opcode = 0x71000000  # Base for SUBS (immediate)
        return base_opcode | SF | Rd | (Rn << 5) | (imm12 << 10)
        
    # --- Variant B: CMP (register) ---
    op2_str = operand2
    Rm = int(op2_str[1:])
    
    if op2_str.startswith('W'):
        base_opcode = 0x6B200000  # Base for SUBS (extended register)
        shift_codes = {"UXTB": 0b000, "UXTH": 0b001, "UXTW": 0b010, "UXTX": 0b011, 
                       "SXTB": 0b100, "SXTH": 0b101, "SXTW": 0b110, "SXTX": 0b111}
        option = 0b010  # Default extension pattern: UXTW
        imm3 = 0
        
        if len(tokens) > 3:
            option = shift_codes.get(tokens[3], 0b010)
        if len(tokens) > 4:
            imm3 = int(tokens[4], 0) & 0x7
            
        return base_opcode | SF | Rd | (Rn << 5) | (Rm << 16) | (option << 13) | (imm3 << 10)
        
    elif op2_str.startswith('X'):
        base_opcode = 0x6B000000  # Base for SUBS (shifted register)
        shift_codes = {"LSL": 0b00, "LSR": 0b01, "ASR": 0b10}
        shift_type = 0b00  # Default shift: LSL
        imm6 = 0
        
        if len(tokens) > 3:
            shift_type = shift_codes.get(tokens[3], 0b00)
        if len(tokens) > 4:
            imm6 = int(tokens[4], 0) & 0x3F
            
        return base_opcode | SF | Rd | (Rn << 5) | (Rm << 16) | (shift_type << 22) | (imm6 << 10)
        
    else:
        raise ValueError(f"Invalid second operand structure: {operand2}")

def encode_cmn(tokens, current_pc, symbol_table):
    """
    Encodes the CMN instruction (an alias for ADDS with Rd = XZR/WZR).
    Expected tokens format: 
      - Immediate: ['CMN', 'X0', '#10'] or ['CMN', 'X0', 'MSG@PAGEOFF']
      - Register:  ['CMN', 'X0', 'X1'] or ['CMN', 'X0', 'X1', 'LSL', '2']
    """
    reg_str = tokens[1]
    SF = sf(reg_str)
    Rn = int(reg_str[1:])
    Rd = 31  # Target is always XZR/WZR (31) to discard the result
    
    operand2 = tokens[2]
    imm12 = None
    
    # Parse labels and page offset modifiers
    if "@PAGEOFF" in operand2 or ":lo12:" in operand2:
        label_name = operand2.replace("@PAGEOFF", "").replace(":lo12:", "")
        if label_name not in symbol_table:
            raise ValueError(f"Undefined label: {label_name}")
        imm12 = symbol_table[label_name] & 0xFFF
    elif operand2 in symbol_table:
        imm12 = symbol_table[operand2] & 0xFFF
        
    # Check if operand2 is a raw numeric immediate value
    if imm12 is None:
        try:
            imm12 = int(operand2, 0)
        except ValueError:
            imm12 = None  # Process as a register operand instead

    # --- Variant A: CMN (immediate) ---
    if imm12 is not None:
        if not (0 <= imm12 <= 4095):
            raise ValueError("CMN immediate value must be a 12-bit number (0-4095).")
        base_opcode = 0x31000000  # Base for ADDS (immediate)
        return base_opcode | SF | Rd | (Rn << 5) | (imm12 << 10)
        
    # --- Variant B: CMN (register) ---
    op2_str = operand2.upper()
    Rm = int(op2_str[1:])
    
    if op2_str.startswith('W'):
        base_opcode = 0x2B200000  # Base for ADDS (extended register)
        shift_codes = {"UXTB": 0b000, "UXTH": 0b001, "UXTW": 0b010, "UXTX": 0b011, 
                       "SXTB": 0b100, "SXTH": 0b101, "SXTW": 0b110, "SXTX": 0b111}
        option = 0b010  # Default extension pattern: UXTW
        imm3 = 0
        
        if len(tokens) > 3:
            option = shift_codes.get(tokens[3].upper(), 0b010)
        if len(tokens) > 4:
            imm3 = int(tokens[4], 0) & 0x7
            
        return base_opcode | SF | Rd | (Rn << 5) | (Rm << 16) | (option << 13) | (imm3 << 10)
        
    elif op2_str.startswith('X'):
        base_opcode = 0x2B000000  # Base for ADDS (shifted register)
        shift_codes = {"LSL": 0b00, "LSR": 0b01, "ASR": 0b10}
        shift_type = 0b00  # Default shift: LSL
        imm6 = 0
        
        if len(tokens) > 3:
            shift_type = shift_codes.get(tokens[3].upper(), 0b00)
        if len(tokens) > 4:
            imm6 = int(tokens[4], 0) & 0x3F
            
        return base_opcode | SF | Rd | (Rn << 5) | (Rm << 16) | (shift_type << 22) | (imm6 << 10)
        
    else:
        raise ValueError(f"Invalid second operand structure: {operand2}")    

def encode_ccmp(tokens, current_pc, symbol_table):
    """
    Encodes the ARM64 CCMP (Conditional Compare) instruction.
    Expected Formats:
      - Register:  ['CCMP', 'X0', 'X1', '4', 'EQ']
      - Immediate: ['CCMP', 'X0', '5', '4', 'EQ']
    """
    reg_str = tokens[1]
    SF = sf(reg_str)
    Rn = int(reg_str[1:])
    
    operand2 = tokens[2]
    nzcv_str = tokens[3]
    cond = tokens[4]
    
    # 2. Parse condition codes safely
    cond_codes = {
        "EQ": 0b0000, "NE": 0b0001, "CS": 0b0010, "CC": 0b0011,
        "MI": 0b0100, "PL": 0b0101, "VS": 0b0110, "VC": 0b0111,
        "HI": 0b1000, "LS": 0b1001, "GE": 0b1010, "LT": 0b1011,
        "GT": 0b1100, "LE": 0b1101, "AL": 0b1110, "NV": 0b1111
    }
    if cond not in cond_codes:
        raise ValueError(f"Unknown condition code: {cond}")
    cond_opcode = cond_codes[cond]
    
    # 3. Parse NZCV flag values (0 to 15)
    nzcv = int(nzcv_str, 0)
    if not (0 <= nzcv <= 15):
        raise ValueError("NZCV flag valuation must be between 0 and 15.")

    # --- Variant A: CCMP (immediate) ---
    if operand2.isdigit():
        clean_imm = operand2
        imm5 = int(clean_imm, 0)
        if not (0 <= imm5 <= 31):
            raise ValueError("CCMP immediate value must fit in 5 bits (0-31).")
            
        base_opcode = 0x7A400800  # Base for CCMP (immediate)
        return base_opcode | SF | (imm5 << 16) | (cond_opcode << 12) | (Rn << 5) | nzcv

    # --- Variant B: CCMP (register) ---
    elif operand2.startswith('X') or operand2.startswith('W'):
        if operand2[0] != reg_str[0]:
            raise ValueError("CCMP register sizes must match (both X or both W).")
            
        Rm = int(operand2[1:])
        base_opcode = 0x7A400000  # Base for CCMP (register)
        return base_opcode | SF | (Rm << 16) | (cond_opcode << 12) | (Rn << 5) | nzcv
        
    else:
        raise ValueError(f"Invalid second operand token: {tokens[2]}")
    
    

def encode_ccmn(tokens, current_pc, symbol_table):
    """
    Encodes the ARM64 CCMN (Conditional Compare Negative) instruction.
    Expected Formats:
      - Register:  ['CCMN', 'X0', 'X1', '4', 'EQ']
      - Immediate: ['CCMN', 'X0', '5', '4', 'EQ']
    """
    reg_str = tokens[1]
    SF = sf(reg_str)
    Rn = int(reg_str[1:])
    
    operand2 = tokens[2]
    nzcv_str = tokens[3]
    cond = tokens[4]
    
    # 2. Parse condition codes safely
    cond_codes = {
        "EQ": 0b0000, "NE": 0b0001, "CS": 0b0010, "CC": 0b0011,
        "MI": 0b0100, "PL": 0b0101, "VS": 0b0110, "VC": 0b0111,
        "HI": 0b1000, "LS": 0b1001, "GE": 0b1010, "LT": 0b1011,
        "GT": 0b1100, "LE": 0b1101, "AL": 0b1110, "NV": 0b1111
    }
    
    if cond not in cond_codes:
        raise ValueError(f"Unknown condition code: {cond}")
    cond_opcode = cond_codes[cond]
    
    # 3. Parse NZCV flag values (0 to 15)
    nzcv = int(nzcv_str, 0)
    if not (0 <= nzcv <= 15):
        raise ValueError("NZCV flag valuation must be between 0 and 15.")

    # --- Variant A: CCMN (immediate) ---
    if operand2.isdigit():
        clean_imm = operand2
        imm5 = int(clean_imm, 0)
        if not (0 <= imm5 <= 31):
            raise ValueError("CCMN immediate value must fit in 5 bits (0-31).")
            
        base_opcode = 0x3A400800  # Base for CCMN (immediate)
        return base_opcode | SF | (imm5 << 16) | (cond_opcode << 12) | (Rn << 5) | nzcv

    # --- Variant B: CCMN (register) ---
    elif operand2.startswith('X') or operand2.startswith('W'):
        if operand2[0] != reg_str[0]:
            raise ValueError("CCMN register sizes must match (both X or both W).")
            
        Rm = int(operand2[1:])
        base_opcode = 0x3A400000  # Base for CCMN (register)
        return base_opcode | SF | (Rm << 16) | (cond_opcode << 12) | (Rn << 5) | nzcv
    else:
        raise ValueError(f"Invalid second operand token: {tokens[2]}")

DISPATCH_TABLE = {
    'ABS': encode_abs,
    'ADCS': encode_adcs,
    'SVC': encode_svc, 
    'ADR': encode_adr, 
    'ADRP': encode_adrp,
    'ASR': encode_asr,
    'ADD': encode_add,
    'ADDS': encode_adds,
    'SUB': encode_sub,
    'SUBS': encode_subs,
    'AND': encode_and,
    'ANDS': encode_ands,
    'EON': encode_eon,
    'EOR': encode_eor,
    'MOV': encode_mov,
    'MOVZ': encode_movz,
    'MOVK': encode_movk,
    'MOVN': encode_movn,
    'MUL': encode_mul,
    'MSUB': encode_msub,
    'MNEG': encode_mneg,
    'NOP': encode_nop,
    'NEG':  encode_neg,
    'NEGS': encode_negs,
    'UDIV': encode_udiv,
    'SDIV': encode_sdiv,
    "ORR": encode_orr,
    'ORN': encode_orn,
    'RET': encode_ret,
    'ROR': encode_ror,
    'LSR': encode_lsr,
    'LSL': encode_lsl,
    'UMIN': encode_umin,
    'SMIN': encode_smin,
    'UMAX': encode_umax,
    'SMAX': encode_smax,
    'UMULH': encode_umulh,
    'UMULL': encode_umull,
    'SMULL': encode_smull,
    'SMULH': encode_smulh,
    'UXTH': encode_uxth,
    'UXTB': encode_uxtb,
    'UBFX': encode_ubfx,
    'UBFIZ': encode_ubfiz,
    'SXTH': encode_sxth,
    'SXTB': encode_sxtb,
    'SXTW': encode_sxtw,
    'SBFX': encode_sbfx,
    'SBFIZ': encode_sbfiz,
    'STR': encode_str,
    'LDR': encode_ldr,
    'STRB': encode_strb,
    'LDRB': encode_ldrb,
    'STRH': encode_strh,
    'LDRH': encode_ldrh,
    'LDRSB': encode_ldrsb,
    'LDRSH': encode_ldrsh,
    'LDRSW': encode_ldrsw,
    'STUR': encode_stur,
    'LDUR': encode_ldur,
    'STURB': encode_sturb,
    'LDURB': encode_ldurb,
    'STURH': encode_sturh,
    'LDURH': encode_ldurh,
    'LDURSB': encode_ldursb,
    'LDURSH': encode_ldursh,
    'LDURSW': encode_ldursw,
    'STP': encode_stp, 
    'LDP': encode_ldp,
    'UMADDL': encode_umaddl,
    'SMADDL': encode_smaddl,
    'MADD': encode_madd,
    'UMSUBL': encode_umsubl,
    'UMNEGL': encode_umnegl,
    'SMSUBL': encode_smsubl,
    'SMNEGL': encode_smnegl,
    'B': encode_b,
    'B.': encode_bcond,
    'BC.': encode_bc,
    'BR': encode_br,
    'BL': encode_bl,
    'BLR': encode_blr,
    'CBZ': encode_cbz,
    'CBNZ': encode_cbnz,
    'CMP': encode_cmp,
    'CMN': encode_cmn,
    'CCMP': encode_ccmp,
    'CCMN': encode_ccmn
}