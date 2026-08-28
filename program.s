.global _start
_start:
    ; --- Step 1: Prompt for First Number ---
    mov x0, #1                  ; stdout
    adrp x1, prompt1@PAGE       ; Address of prompt1
    add x1, x1, prompt1@PAGEOFF
    mov x2, #0x13                 ; Length of string
    mov x16, #4                 ; write syscall
    svc #0x80

    ; Read First Number
    mov x0, #0                  ; stdin
    adrp x1, num1@PAGE
    add x1, x1, num1@PAGEOFF
    mov x2, #2                  ; 1 char + newline
    mov x16, #3                 ; read syscall
    svc #0x80

    ; --- Step 2: Prompt for Operator ---
    mov x0, #1
    adrp x1, prompt_op@PAGE       ; Address of prompt_op
    add x1, x1, prompt_op@PAGEOFF
    mov x2, #0x10
    mov x16, #4
    svc #0x80

    ; Read Operator
    mov x0, #0
    adrp x1, op@PAGE   
    add x1, x1, op@PAGEOFF
    mov x2, #2


    mov x16, #3
    svc #0x80

    ; --- Step 3: Prompt for Second Number ---
    mov x0, #1
    adrp x1, prompt2@PAGE       ; Address of prompt2
    add x1, x1, prompt2@PAGEOFF
    mov x2, #0x14
    mov x16, #4
    svc #0x80

    ; Read Second Number
    mov x0, #0
    adrp x1, num2@PAGE
    add x1, x1, num2@PAGEOFF
    mov x2, #2
    mov x16, #3
    svc #0x80

    ; --- Step 4: Convert ASCII Characters to Integers ---
    adrp x1, num1@PAGE
    add x1, x1, num1@PAGEOFF
    ldrb w4, [ x1 ]               ; Load character
    sub w4, w4, #48             ; Convert ASCII '0'-'9' to 0-9

    adrp x1, num2@PAGE
    add x1, x1, num2@PAGEOFF
    ldrb w5, [ x1 ]
    sub w5, w5, #48

    ; --- Step 5: Check Operator and Do Math ---
    adrp x1, op@PAGE
    add x1, x1, op@PAGEOFF

    ldrb w6, [ x1 ]               ; Load operator character

    cmp w6, #43                 ; '+' ASCII is 43
    b. eq do_add
    cmp w6, #45                 ; '-' ASCII is 45
    b. eq do_sub
    cmp w6, #42                 ; '*' ASCII is 42
    b. eq do_mul
    b error                     ; Fallback for unsupported operators

    do_add:
        add w7, w4, w5              ; w7 = num1 + num2
        b print_result

    do_sub:
        sub w7, w4, w5              ; w7 = num1 - num2
        b print_result

    do_mul:
        mul w7, w4, w5              ; w7 = num1 * num2
        b print_result

    print_result:
        ; --- Step 6: Convert Result Integer to ASCII ---
        ; (Note: This handles a single-digit positive result for simplicity)
        add w7, w7, #48             ; Convert back to ASCII character
        adrp x1, result@PAGE
        add x1, x1, result@PAGEOFF
        strb w7, [ x1 ]               ; Store in memory

        ; Print Result Message
        mov x0, #1
        adrp x1, res_msg@PAGE
        add x1, x1, res_msg@PAGEOFF
        mov x2, #8
        mov x16, #4
        svc #0x80


        ; Print Result Digit
        mov x0, #1
        adrp x1, result@PAGE
        add x1, x1, result@PAGEOFF
        mov x2, #2                  ; Digit + trailing newline
        mov x16, #4
        svc #0x80

        b exit

    error:
        mov x0, #1
        adrp x1, err_msg@PAGE
        add x1, x1, err_msg@PAGEOFF
        mov x2, #15
        mov x16, #4
        svc #0x80

    exit:
        mov x0, #0                  ; Return 0
        mov x16, #1                 ; exit syscall
        svc #0x80

    .data
    prompt1:   .ascii "Enter first digit: "
    .space 8
    prompt_op: .ascii "Enter operator: "
    .space 8
    prompt2:   .ascii "Enter second digit: "
    .space 8
    res_msg:   .ascii "Result: "
    .space 8
    err_msg:   .ascii "Invalid input\n"

    num1:   .space 2
    op:     .space 2
    num2:   .space 2
    result: .space 2