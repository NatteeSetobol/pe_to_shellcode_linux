# pe_to_shellcode_linux

The PE to shellcode converter is a powerful tool for penetration testing and vulnerability analysis that allows you to convert any non .NET 64-bit Windows executable file to shellcode. The resulting shellcode can also be used to build custom payloads for use in security testing and penetration testing scenarios. The conversion process works by taking an executable file and converting it to a stream of shellcode that can be injected into memory at runtime.


Hldr64 file source by hashrezade

https://github.com/hasherezade/pe_to_shellcode/tree/master/hldr64



Downloading and Building:


In the terminal, download the source code via git:

git clone https://github.com/6A0BCD80/pe_to_shellcode_linux/

cd into the Folder:

cd pe_to_shellcode_linux

type ./build.sh



Options:


-f specify an exe file to convert

-o output binary shell file to use

Usage: pe2shellcode -f 64bitexe.exe -o shellcode.sc
