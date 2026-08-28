Start by opening up 'assembler.py'. Then start by using 'program.s', once ready go to 'assembler.py' and press run. 
It should produce 2 files, program.txt for binary mapping and program.s for object file layout.

Notes on the Project:

1. Memory paddings in between ascii strings must be done manually and are 8 bytes wide, it is there to prevent sequential memory buffer overruns.
   
            Before                                           After
   
       prompt1:   .ascii "Enter first digit: "       prompt1:   .ascii "Enter first digit: "
       prompt_op: .ascii "Enter operator: "  ---->   .space 8
                                                      prompt_op: .ascii "Enter operator: "

3. Requires a space between the instruction and the condition modifier so the lexer can process them as separate tokens. 

             Before                                           After
   
            b.eq msg                  ---->                 b. eq msg

5. Requires spaces around the brackets so the syntax parser can isolate the registers and offset variables cleanly.

              Before                                          After
   
           ldrb w0, [x1]                  ---->            ldrb w0, [ x1 ]
         strb w0, [x1, #0x4]!             ---->         strb w0, [ x1, #0x4 ]!
         strb w0, [x1], #0x4              ---->         strb w0, [ x1 ], #0x4
