from asm_tokens import tokenize_line

def build_symbol_table(source_lines, base_address=0x100000000):
    """Pass 1 Scanner: Loops through token arrays to calculate the memory 
    address (PC) of every line and store labels inside a Symbol Table dictionary.

    >>> code = [
    ...     '.global _start',
    ...     '_start:',
    ...     '    MOV X0, #1',    
    ...     'msg: .ascii "Hello\n"',
    ...     '    MOV X16, #4'
    ... ]
    >>> build_symbol_table(code)
    {'_START': 4294968104, 'MSG': 4294968112}
    """
    symbol_table = {}
    current_pc = base_address
    data_address = 0x100004000
    for line in source_lines:
        tokens = tokenize_line(line)
        if not tokens:
            continue
        directive = tokens[0]
        if directive[-1] == ':':
            symbol_table[directive[:-1]] = current_pc
            tokens = tokens[1:]
            if not tokens:
                continue
        data_tokens = tokens[1:]
        directive = tokens[0]
        if directive[0] == '.':
            if directive == '.ASCII':
                clean_text = tokens[1].strip('"').encode('utf-8').decode('unicode_escape')
                space = len(clean_text)
                current_pc += space
            elif directive == '.BYTE':
                # 1 byte per item in the list
                current_pc += 1 * len(data_tokens)
            elif directive in ['.SHORT', '.HWORD']:
                # 2 bytes per item in the list
                current_pc += 2 * len(data_tokens)
            elif directive in ['.WORD', '.LONG']:
                # 4 bytes per item in the list
                current_pc += 4 * len(data_tokens)
            elif directive in ['.QUAD', '.DOUBLE']:
                # 8 bytes per item in the list
                current_pc += 8 * len(data_tokens)
            elif directive == '.SPACE':
                # .space reserves an explicit number of bytes (e.g., .space 20)
                current_pc += int(data_tokens[0])
            elif directive == '.DATA':
                base_address = current_pc
                current_pc = data_address
            elif directive == '.TEXT':
                data_address = current_pc
                current_pc = base_address
        else:
            current_pc += 4
    return symbol_table