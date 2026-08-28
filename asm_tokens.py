def tokenize_line(line: str):
    """Transforms a raw assembly line string into a clean list of uppercase tokens,
    while carefully preserving the raw formatting of text strings inside quotes.

    >>> tokenize_line("  MOV X16, #4  ; write syscall number ")
    ['MOV', 'X16', '4']

    >>> tokenize_line("add x0, x1, x2 ; trailing inline comment")
    ['ADD', 'X0', 'X1', 'X2']

    >>> tokenize_line('msg: .ascii "Hello, World\n" ; do not break spaces!')
    ['MSG:', '.ASCII', '"Hello, World\n"']

    >>> tokenize_line("   ") # Completely empty or whitespace lines
    []

    >>> tokenize_line("; only a comment line")
    []
    """
    def make(lst):
            if not lst:
                  return []
            if lst[0].upper() in ['XZR', 'SP']:
                 lst[0] = 'X31'
            if lst[0].upper() in ['WZR', 'WSP']:
                 lst[0] = 'W31'
            return [lst[0].upper()] + make(lst[1:])
    
    if ".ascii" in line.lower():
        parts = line.split('"', 1)
        prefix_string = parts[0]
        prefix_tokens = make(prefix_string.replace(',', ' ').split())
        if len(parts) > 1:
            raw_text = parts[1].split('"')[0] 
            prefix_tokens.append(fr'"{raw_text}"')
        return prefix_tokens
    
    clean_line = line.split(';')[0]
    sanitized_line = clean_line.replace(',', ' ').replace('#', ' ')
    p = sanitized_line.split()
    return make(p)