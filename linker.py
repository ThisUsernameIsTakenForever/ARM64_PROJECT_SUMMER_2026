from asm_tokens import tokenize_line
from asm_enviroments import build_symbol_table
from asm_encodings import DISPATCH_TABLE
from asm_eval import evaluate_line

def hex_to_little_endian(hex_string):
    """Converts a hex string to little-endian format.

    Args:
        hex_string: The hex string to convert (e.g., "1234").

    Returns:
        The little-endian representation as a string.
    """
    # Ensure the hex string is of even length
    if len(hex_string) % 2 != 0:
        hex_string = "0" + hex_string

    # Convert hex string to bytes
    byte_array = bytes.fromhex(hex_string)

    # Reverse the byte order
    little_endian_bytes = byte_array[::-1]

    # Convert back to hex string
    return little_endian_bytes.hex()



def make_ELF_head(result, align):

    text_result = result[0]
    data_result = result[1]
    text_align = align[0]
    data_align = align[1]
    size__text = len(text_result) // 2 
    size__data = len(data_result) // 2


    # ==============================================================================
    # 1. MAIN MACH-O HEADER (32 bytes total)
    # ==============================================================================
    magic       = 'cffaedfe'  
    cputype     = '0c000001'  
    BUFFER_1    = '00000000'
    filetype    = '01000000'  
    ncmds       = '04000000'
    sizeofcmds  = '68010000'
    BUFFER_2    = '00000000'  
    BUFFER_3    = '00000000'  

    macho_header = magic + cputype + BUFFER_1 + filetype + ncmds + sizeofcmds + BUFFER_2 + BUFFER_3

    # ==============================================================================
    # 2. LC_SEGMENT_64 (152 bytes total)
    # ==============================================================================
    segname     = '19000000'
    seg_cmdsize = 'e8000000'
    BUFFER_4    = '0000000000000000'
    BUFFER_5    = '0000000000000000'
    vmaddr      = '0000000000000000'
    vmsize      = hex_to_little_endian(hex(size__text + size__data)[2:].zfill(16))
    fileoff     = 392
    display_fileoff = hex_to_little_endian(hex(fileoff)[2:].zfill(16))
    filesize    = vmsize
    maxprot     = '07000000'
    initprot    = '07000000'
    nsects      = '02000000'
    seg_flags   = '00000000'

    # Notice the '16s' for the string, and '4Q' for the 8-byte numbers
    segment_cmd = segname + seg_cmdsize + BUFFER_4 + BUFFER_5 + vmaddr + vmsize + display_fileoff + filesize + maxprot + initprot + nsects + seg_flags

    # --- SECTION __text INSIDE LC_SEGMENT_64 ---
    sectname__text    = '5f5f746578740000'
    BUFFER_6 = '0000000000000000'
    segname_ref__TEXT = '5f5f544558540000'
    BUFFER_7 = '0000000000000000'
    addr__text        = '0000000000000000'         
    display__size__text = hex_to_little_endian(hex(size__text)[2:].zfill(16))
    offset__text      = hex_to_little_endian(hex(fileoff)[2:].zfill(8))
    align_text        = hex_to_little_endian(hex(text_align)[2:].zfill(8))
    reloff__text      = '00000000'
    nreloc__text      = '00000000'
    sect_flags__text  = '00000080'
    res1__text        = '00000000'
    res2__text        = '00000000'
    res3__text        = '00000000'

    # --- SECTION __data INSIDE LC_SEGMENT_64 ---
    sectname__data    = '5f5f646174610000'
    BUFFER_8 = '0000000000000000'
    segname_ref__DATA = '5f5f444154410000'
    BUFFER_9 = '0000000000000000'
    addr__data        = display__size__text
    display__size__data =  hex_to_little_endian(hex(size__data)[2:].zfill(16))
    offset__data      = hex_to_little_endian(hex(size__text + fileoff)[2:].zfill(8))
    align_data        = hex_to_little_endian(hex(data_align)[2:].zfill(8))
    reloff__data      = '00000000'
    nreloc__data      = '00000000'
    sect_flags__data  = '00000000'
    res1__data        = '00000000'
    res2__data        = '00000000'
    res3__data        = '00000000'


    section_text = sectname__text + BUFFER_6 + segname_ref__TEXT + BUFFER_7 + addr__text + display__size__text + offset__text + align_text + reloff__text + nreloc__text + sect_flags__text + res1__text + res2__text + res3__text
    section_data = sectname__data + BUFFER_8 + segname_ref__DATA + BUFFER_9 + addr__data + display__size__data + offset__data + align_data + reloff__data + nreloc__data + sect_flags__data + res1__data + res2__data + res3__data

    # ==============================================================================
    # 3. LC_BUILD_VERSION (24 bytes total)
    # ==============================================================================
    bv_cmd      = '32000000'
    bv_cmdsize  = '18000000'
    platform    = '01000000'
    minos       = '00050f00'  
    sdk         = '00000000'           
    ntools      = '00000000'           

    build_version = bv_cmd + bv_cmdsize + platform + minos + sdk + ntools

    # ==============================================================================
    # 4. LC_SYMTAB (24 bytes total)
    # ==============================================================================
    sym_cmd     = '02000000'
    sym_cmdsize = '18000000'
    symoff      = hex_to_little_endian(hex(size__text + size__data + 392)[2:].zfill(8))
    nsyms       = '03000000'
    stroff      = hex_to_little_endian(hex(size__text + size__data + 392 + 48)[2:].zfill(8))
    strsize     = '18000000'

    symtab = sym_cmd + sym_cmdsize + symoff + nsyms + stroff + strsize

    # ==============================================================================
    # 5. LC_DYSYMTAB (80 bytes total)
    # ==============================================================================
    dysym_cmd     = '0b000000'
    dysym_cmdsize = '50000000'
    ilocalsym = '00000000'
    nlocalsym = '02000000'
    iextdefsym = '02000000'
    nextdefsym = '01000000'
    iundefsym = '03000000'
    nundefsym = '00000000'
    tocoff = '00000000'
    ntoc = '00000000'
    modtaboff = '00000000'
    nmodtab = '00000000'
    extrefsymoff = '00000000'
    nextrefsyms = '00000000'
    indirectsymoff = '00000000'
    nindirectsyms = '00000000'
    extreloff = '00000000'
    nextrel = '00000000'
    locreloff = '00000000'
    nlocrel = '00000000'

    dysymtab = dysym_cmd + dysym_cmdsize + ilocalsym + nlocalsym + iextdefsym + nextdefsym + iundefsym + nundefsym + tocoff + ntoc + modtaboff + nmodtab + extrefsymoff + nextrefsyms + indirectsymoff + nindirectsyms + extreloff + nextrel + locreloff + nlocrel

    head = macho_header + segment_cmd + section_text + section_data + build_version + symtab + dysymtab
    return head

def make_ELF_tail(result):
    String_Table_Index_ltmp0 = '0e000000'
    Type_Flags_ltmp0 = '0e010000'
    Section_Index_ltmp0 = '0000000000000000'

    ltmp0 = String_Table_Index_ltmp0 + Type_Flags_ltmp0 + Section_Index_ltmp0

    String_Table_Index_ltmp1 = '08000000'
    Type_Flags__data = '0e010000'
    text_result = result[0]
    size__text = len(text_result) // 2 
    display__size__data =  hex_to_little_endian(hex(size__text)[2:].zfill(16))

    ltmp1 = String_Table_Index_ltmp1 + Type_Flags__data + display__size__data

    String_Table_Index_start = '01000000'
    Type_Flags_start = '0f010000'
    Section_Index_start = '0000000000000000'

    _start = String_Table_Index_start + Type_Flags_start + Section_Index_start

    ascii_startltmp1ltmp0 = '005f7374617274006c746d7031006c746d70300000000000'

    return ltmp0 + ltmp1 + _start + ascii_startltmp1ltmp0

"""
 - CHANGES
 - STATIC

00000000: cffa edfe 0c00 0001 0000 0000 0100 0000 0400 0000 1801 0000 0000 0000 0000 0000  ................................
00000020: 1900 0000 9800 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000  ................................
00000040: 2e00 0000 0000 0000 3801 0000 0000 0000 2e00 0000 0000 0000 0700 0000 0700 0000  ........8.......................
00000060: 0100 0000 0000 0000 5f5f 7465 7874 0000 0000 0000 0000 0000 5f5f 5445 5854 0000  ........__text..........__TEXT..
00000080: 0000 0000 0000 0000 0000 0000 0000 0000 2e00 0000 0000 0000 3801 0000 0000 0000  ........................8.......
000000a0: 0000 0000 0000 0000 0004 0080 0000 0000 0000 0000 0000 0000 3200 0000 1800 0000  ........................2.......
000000c0: 0100 0000 0005 0f00 0000 0000 0000 0000 0200 0000 1800 0000 6801 0000 0300 0000  ........................h.......
000000e0: 9801 0000 1800 0000 0b00 0000 5000 0000 0000 0000 0200 0000 0200 0000 0100 0000  ............P...................
00000100: 0300 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000  ................................
00000120: 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 2000 80d2 e100 0010  ........................ .......
00000140: c201 80d2 9000 80d2 0100 00d4 0000 80d2 3000 80d2 0100 00d4 4865 6c6c 6f2c 2057  ................0.......Hello, W
00000160: 6f72 6c64 210a 0000 0c00 0000 0e01 0000 0000 0000 0000 0000 0800 0000 0e01 0000  orld!...........................
00000180: 2000 0000 0000 0000 0100 0000 0f01 0000 0000 0000 0000 0000 005f 7374 6172 7400   ........................_start.
000001a0: 6d73 6700 6c74 6d70 3000 0000 0000 0000                                          msg.ltmp0.......

cffa edfe - MAGIC NUMBER - STATIC

0c00 0001 - ARM 64 - STATIC

0000 0000 - BUFFER - STATIC

0000 0100 - MH_OBJECT - STATIC

0400 0000 - [ # of load commands ] - CHANGES(1)

1801 0000 - [ cmdsize sums ] - CHANGES(2)

0000 0000 - BUFFER - STATIC

0000 0000 - BUFFER - STATIC

1900 0000 - LC_SEGMENT_64

9800 0000 - cmdsize 152 - CHANGES(3)

0000 0000 0000 0000 - BUFFER - STATIC

0000 0000 0000 0000 - BUFFER - STATIC

0000 0000 0000 0000 - vmaddr - CHANGES

2e00 0000 0000 0000 - vmsize - CHANGES(4)

3801 0000 0000 0000 - fileoff - CHANGES(5)

2e00 0000 0000 0000 - filesize - CHANGES(6)

0700 0000 - maxprot - STATIC

0700 0000 - initprot - STATIC

0100 0000 - nsects - CHANGES(7)

0000 0000 - flags - CHANGES(8)

5f5f 7465 7874 0000 - ASCII '__text' - STATIC

0000 0000 0000 0000 - BUFFER - STATIC

5f5f 5445 5854 0000 - ASCII '__TEXT' - STATIC

0000 0000 0000 0000 - BUFFER - STATIC

0000 0000 0000 0000 - addr - CHANGES(9)

2e00 0000 0000 0000 - size - CHANGES(10)

3801 0000 0000 0000 - offset - CHANGES(11)

0000 0000 - reloff - STATIC

0000 0000 - nreloc - STATIC

0004 0080 - flags - CHANGES(12)

0000 0000 - reserved1 - STATIC

0000 0000 - reserved2 - STATIC

0000 0000 - BUFFER - STATIC

3200 0000 - LC_BUILD_VERSION - STATIC

1800 0000 - cmdsize 24 - CHANGES(13)

0100 0000 - platform - STATIC

0005 0f00 - minos - 0F in hex = 15 in decimal (Major) - 05 in hex = 5 in decimal (Minor) - 00 in hex = 0 in decimal (Patch) - STATIC

0000 0000 - sdk - STATIC

0000 0000 - ntools - STATIC

0200 0000 - LC_SYMTAB - STATIC

1800 0000 - cmdsize 24 - CHANGES(14)

6801 0000 - symoff 360 - CHANGES(15)

0300 0000 - nsyms 3 - CHANGES(16)

9801 0000 - stroff 408 - CHANGES(17)

1800 0000 - strsize 24 - CHANGES(18)

0b00 0000 - LC_DYSYMTAB - STATIC

5000 0000 - cmdsize 80 - CHANGES(19)

0000 0000 - ilocalsym 0 - CHANGES(20)

0200 0000 - nlocalsym 2 - CHANGES(21)

0200 0000 - iextdefsym 2 - CHANGES(22)

0100 0000 - nextdefsym 1 - CHANGES(23)

0300 0000 - iundefsym 3 - CHANGES(24)

0000 0000 - nundefsym 0 - CHANGES(25)

0000 0000 - tocoff 0 - STATIC

0000 0000 - ntoc 0 - STATIC

0000 0000 - modtaboff 0 - STATIC

0000 0000 - nmodtab 0 - STATIC

0000 0000 - extrefsymoff 0 - STATIC

0000 0000 - nextrefsyms 0 - STATIC

0000 0000 - indirectsymoff 0 - STATIC

0000 0000 - nindirectsyms 0 - STATIC

0000 0000 - extreloff 0 - STATIC

0000 0000 - nextrel 0 - STATIC

0000 0000 - locreloff 0 - STATIC

0000 0000 - nlocrel 0 - STATIC
"""