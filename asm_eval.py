import struct
from asm_tokens import tokenize_line
from asm_encodings import DISPATCH_TABLE

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

def evaluate_line(line, symbol_table, base_address=0x100000000):
    """Pass 2 Evaluator: Loops through token arrays, evaluates them into 
    machine code integers or ASCII data bytes, and compiles a binary stream.

    >>> symbol_table = {'_START': 0x100000328}
    >>> evaluate_line("mov x0, #9", symbol_table)
    200180d2
    >>> evaluate_line('.global _start', symbol_table)
    >>> evaluate_line('_start:', symbol_table)
    >>> evaluate_line('.data', symbol_table)
    >>> evaluate_line('.space 1', symbol_table)
    '00'
    >>> evaluate_line('.space 2', symbol_table)
    '0000'
    >>> evaluate_line('.space 3', symbol_table)
    '000000'
    >>> evaluate_line('.space 4', symbol_table)
    '00000000'
    >>> evaluate_line('.space 1', symbol_table)
    '00'
    >>> evaluate_line('mask:   .byte 0x1', symbol_table)
    '01'
    >>> evaluate_line('mask:   .byte 0xF1', symbol_table)
    'f1'
    >>> evaluate_line('mask:   .byte 0xF1, 0x43', symbol_table) 
    'f143'
    >>> evaluate_line('mask:   .byte 0x1, 0xF1, 0x43', symbol_table) 
    '01f143'
    >>> evaluate_line('scores: .short 10, 20, 30, 40', symbol_table)
    '0a0014001e002800'
    >>> evaluate_line('matrix: .long 17, 2, 3', symbol_table)
    '110000000200000003000000'
    >>> evaluate_line('matrix: .long 0x11, 0xff, 0x43', symbol_table)
    '11000000ff00000043000000'
    >>> evaluate_line('matrix: .long 0xf1, 0x5, 0x3', symbol_table)
    'f10000000500000003000000'
    evaluate_line('POINTER: .quad 0xff, 0x5, 0x3, 0xd2', symbol_table)
    'ff0000000000000005000000000000000300000000000000d200000000000000'
    >>> evaluate_line('msg: .ascii "Hello\n"', symbol_table)
    '48656c6c6f0a'
    """
    tokens = tokenize_line(line) # ['MOV', 'X0', '9']
    if not tokens:
        return ''
    directive = tokens[0]
    if directive in ['.GLOBAL', '_START:', '.TEXT', '.DATA']:
        return ''

    if directive[-1] == ':':    
        tokens = tokens[1:]
        if not tokens:
            return ''
    data_tokens = tokens[1:]
    directive = tokens[0]
    if directive[0] == '.':
        if directive == '.ASCII':
            result = ''
            original = data_tokens[0]
            cleaned = original.strip('"\'').encode('utf-8').decode('unicode_escape')
            for character in cleaned:
                result += hex(ord(character))[2:].zfill(2)
            return result
        elif directive == '.BYTE':
            result = ''
            for i in data_tokens:
                hex_result = hex(int(i, 0))
                hex_str = hex_result[2:].zfill(2)
                result += hex_str
            return result
        elif directive in ['.SHORT', '.HWORD']:
            result = ''
            for i in data_tokens:
                hex_result = hex(int(i, 0))
                hex_str = hex_result[2:].zfill(4)
                little_endian_value = hex_to_little_endian(hex_str)
                result += little_endian_value
            return result
        elif directive in ['.WORD', '.LONG']:
            result = ''
            for i in data_tokens:
                hex_result = hex(int(i, 0))
                hex_str = hex_result[2:].zfill(8)
                little_endian_value = hex_to_little_endian(hex_str)
                result += little_endian_value
            return result
        elif directive in ['.QUAD', '.DOUBLE']:
            result = ''
            for i in data_tokens:
                hex_result = hex(int(i, 0))
                hex_str = hex_result[2:].zfill(16)
                little_endian_value = hex_to_little_endian(hex_str)
                result += little_endian_value
            return result
        elif directive == '.SPACE':
            result = ''
            amount = int(data_tokens[0])
            for i in range(amount):
                result += '00'
            return result
    else:
        function = DISPATCH_TABLE[directive]
        result = function(tokens, base_address, symbol_table)
        hex_result = hex(result)
        hex_str = hex_result[2:].zfill(8)
        little_endian_value = hex_to_little_endian(hex_str)
        return little_endian_value