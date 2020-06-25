# pe_to_shellcode_linux

PE to shellcode will convert any Windows non .dot net 64bit EXE file to shellcode to avoid detection or such. This is based on hasherezade's pe_to_shellcode for Windows (https://github.com/hasherezade/pe_to_shellcode). 


Options:

-f specify an exe file to convert

-o output binary shell file to use

Usage: pe2shellcode -f 64bitexe.exe -o shellcode.sc
