from asm_tokens import tokenize_line
from asm_enviroments import build_symbol_table
from asm_encodings import DISPATCH_TABLE
from asm_eval import evaluate_line
from linker import *

with open("program.s", "r") as file:
    lines = file.read().splitlines()

def make_align(lines):
    text_align = 0
    data_align = 0
    align = text_align
    is_data = False
    for line in lines:
        tokens = tokenize_line(line)
        if '.ALIGN' in tokens:
            align = tokens[1]
        if '.DATA' in tokens:
            is_data = True
            text_align = align
            align = data_align
        if '.TEXT' in tokens:
            is_data = False
            data_align = align
            align = text_align
    if is_data == True:
        data_align = align
    else:
        text_align = align
    return [text_align, data_align]

def make(source_lines, text_result, data_result, text_address, data_address, current_pc, is_data, symbol_table):
    if source_lines:
        line = source_lines[0]
        evaled_line = evaluate_line(line, symbol_table, current_pc)
        if evaled_line == '':
            length = 0
        else:
            length = len(evaled_line) // 2
        if '.DATA' in tokenize_line(line):
            text_address = current_pc
            current_pc = data_address
            is_data = True
            return make(source_lines[1:], text_result, data_result + evaled_line, text_address, data_address, current_pc + length, is_data, symbol_table)
        elif '.TEXT' in tokenize_line(line):
            data_address = current_pc
            current_pc = text_address
            is_data = False
            return make(source_lines[1:], text_result + evaled_line, data_result, text_address, data_address, current_pc + length, is_data, symbol_table)
        if len(source_lines) == 1:
            size__text = len(text_result) // 2 
            size__data = len(data_result) // 2
            offset = (392 + size__text + size__data + len(evaled_line) // 2) % 4
            if (offset != 0):
                for i in range(4 - offset):
                    evaled_line = evaled_line + '00'
        if is_data == True:
            return make(source_lines[1:], text_result, data_result + evaled_line, text_address, data_address, current_pc + length, is_data, symbol_table)
        else:
            return make(source_lines[1:], text_result + evaled_line, data_result, text_address, data_address, current_pc + length, is_data, symbol_table)
    else:
        return [text_result, data_result]
    
def ARM64_Assembler(source_lines):
    symbol_table = build_symbol_table(source_lines)
    text_address=0x100000000
    data_address=0x100004000
    PC = text_address

    def make_lst(result, amount, my_list):
        if result:
            my_list.append(result[:amount])
            return make_lst(result[amount:], amount, my_list)
        else:
            return my_list     
        
    def make_table(chunks, my_str, PC):
        for chunk in chunks:
            my_str += f'{hex(PC)[3:]}: '
            PC = PC + 0x20
            shorts = make_lst(chunk, 4, [])
            for short in shorts:
                my_str += short + ' '
            my_str += ' ................................\n'
        return my_str

    def make_program(result):
        def make(code):
            chunks = [code[i:i+8] for i in range(0, len(code), 8)]
            for chunk in chunks:
                chunk_1 = chunk[0:2]
                if chunk_1 == '':
                    chunk_1 = '00'
                chunk_2 = chunk[2:4]
                if chunk_2 == '':
                    chunk_2 = '00'   
                chunk_3 = chunk[4:6]
                if chunk_3 == '':
                    chunk_3 = '00'
                chunk_4 = chunk[6:8]
                if chunk_4 == '':
                    chunk_4 = '00'
                package = f'   .byte 0x{chunk_1}, 0x{chunk_2}, 0x{chunk_3}, 0x{chunk_4}\n'
                print(package)
                with open("program.txt", "a") as file:
                    file.write(package) 
        with open("program.txt", "a") as file:
            file.write('.global _start\n    _start:\n') 
        make(result[0])
        if result[1]:
            with open("program.txt", "a") as file:
                file.write('    .data\n')
            make(result[1])

    
    
    result = make(source_lines, '', '', text_address, data_address, text_address, False, symbol_table)
    make_program(result)
    align = make_align(lines)
    head = make_ELF_head(result, align)
    tail = make_ELF_tail(result)

    text_result = result[0]
    data_result = result[1]

    full_result = head + text_result + data_result + tail
    chunks =  make_lst(full_result, 64, [])
    my_str = make_table(chunks, '', PC)
    with open("program.o", "a") as file:
        file.write(my_str)  

ARM64_Assembler(lines)