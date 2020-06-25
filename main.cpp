// NOTE():
/*
   This was inspired by pe_to_shell code created by hasherezade for Windows. I decided to transport to Linux because I'm mostly a linux user and I wanted to understand how this works.
// Stub64 was created by hasherezade (https://github.com/hasherezade/pe_to_shellcode/tree/master/hldr64 ).
*/
//TODO():
// - 32bit Executables 

#include <stdio.h>
#include "required/intrinsic.h"
#include "required/nix.h"
#include "required/memory.h"
#include "required/platform.h"
#include "required/assert.h"
#include "marray.h"
#include "stringz.h"

enum WIN_SUBSYSTEM
{
	SUBSYSTEM_UNKNOWN,
	SUBSYSTEM_NATIVE,
	SUBSYSTEM_WINDOWS_GUI,
	SUBSYSTEM_WINDOWS_CUI,
	SUBSYSTEM_OS2_CUI,
	SUBSYSTEM_POSIX_CUI,
	SUBSYSTEM_NATIVE_WINDOWS,
	SUBSYSTEM_WINDOWS_CE_GUI,
	SUBSYSTEM_EFI_APPLICATION,
	SUBSYSTEM_EFI_SERVICE_DRIVER,
	SUBSYSTEM_EFI_RUNTIME_DRIVER,
	SUBSYSTEM_EFI_ROM,
	SUBSYSTEM_WINDOWS_BOOT_APP
};

enum IMAGE_NT_OP_HDR_MAGIC
{
	HDR32_MAGIC = 0x10b,
	HDR64_MAGIC = 0x20b,
	IMAGE_HDR_MAGIC  = 0x107
};

enum  IMAGE_DIRECTORY
{
	DIRECTORY_ENTRY_EXPORT,
	DIRECTORY_ENTRY_IMPORT,
	DIRECTORY_ENTRY_RESOURCES,
	DIRECTORY_ENTRY_EXPECTION,
	DIRECTORY_ENTRY_SECURITY,
	DIRECTORY_ENTRY_BASELOG,
	DIRECTORY_ENTRY_DEBUG,
	DIRECTORY_ENTRY_ARCHITECTURE,
	DIRECTORY_ENTRY_GLOBAL_PTR,
	DIRECTORY_ENTRY_TS,
	DIRECTORY_ENTRY_LOAD_CONFIG,
	DIRECTORY_ENTRY_BOUND_IMPORT,
	DIRECTORY_ENTRY_IAT,
	DIRECTORY_ENTRY_DELAY_IMPORT,
	DIRECTORY_ENTRY_TLS,
	DIRECTORY_ENTRY_COM_DESCRIPTOR,
};

struct MS_DOS_HEADER
{
	ui16 magic;
	ui16 LastPageBytes;
	ui16 PagesInFile;
	ui16 Relocations;
	ui16 SizeInHeader;
	ui16 MinParagraph;
	ui16 MaxParagraph;
	ui16 SSValue;
	ui16 SPValue;
	ui16 CheckSum;
	ui16 IPValue;
	ui16 CSVALUE;
	ui16 FileAddressOf;
	ui16 OverlayNumber;
	ui16 ReservedWordsFour[4];
	ui16 OEMID;
	ui16 OEMInfo;
	ui16 ReservedWordsTen[10];
	ui32 PEOffset;
};

struct PE_HEADER
{
	ui32 Sign;
	ui16 Machine;
	ui16 NumOfSections;
	ui32 TimeDateStamp;
	ui32 PointerToSymbolTable;
	ui32 NumberOfSymbols;
	ui16 SizeOfOptionalHeader;
	ui16 Characteristics;
};

struct data_directory
{
	ui32 VirtualAddress;
	ui32 size;
};

struct PE_OP_HEADER
{
	ui16 magic;
};

struct PE_OP_HEADER64
{
	ui16 magic;
	uchar minorLinkVer;
	uchar majorLinkVer;
	ui32 sizeOfInitData;
	ui32 sizeOfUnInitData;
	ui32 addrOfEntryPoint;
	ui32 baseOfCode;

	ui64 ImageBase;
	ui32 sectionAlign;
	ui32 fileAlign;
	ui16 majorOSVer;
	ui16 minorOSVer;
	ui16 majorImageVer;
	ui16 minorImageVer;
	ui16 majorSubVer;
	ui16 minorSubVer;
	ui32 win32VersionValue;
	ui32 sizeOfImage;
	ui32 sizeOfHeader;
	ui32 checkSum;
	ui16 subSystem;
	ui16 DLLChar;
	ui64 sizeOfStackReserve;
	ui64 sizeOfStackCommit;
	ui64 sizeOfHeapReserve;
	ui64 sizeOfHeapCommit;
	ui32 loaderFlag;
	ui32 numberOfRvaAndSize;
	data_directory DataDirectory[16];
};

struct PE_OP_HEADER32
{
	ui16 magic;
	uchar minorLinkVer;
	uchar majorLinkVer;
	ui32 sizeOfInitData;
	ui32 sizeOfUnInitData;
	ui32 addrOfEntryPoint;
	ui32 baseOfCode;

	ui32 ImageBase;
	ui32 sectionAlign;
	ui32 fileAlign;
	ui16 majorOSVer;
	ui16 minorOSVer;
	ui16 majorImageVer;
	ui16 minorImageVer;
	ui16 majorSubVer;
	ui16 minorSubVer;
	ui32 win32VersionValue;
	ui32 sizeOfImage;
	ui32 sizeOfHeader;
	ui32 checkSum;
	ui16 subSystem;
	ui16 DLLChar;
	ui32 sizeOfStackReserve;
	ui32 sizeOfStackCommit;
	ui32 sizeOfHeapReserve;
	ui32 sizeOfHeapCommit;
	ui32 loaderFlag;
	ui32 numberOfRvaAndSize;
	data_directory DataDirectory[16];
};



bool PEIs64Bit(ui8 *appBytes)
{
	bool result = false;
	struct MS_DOS_HEADER *dosHeader = NULL;
	struct PE_HEADER *peHeader = NULL;
	struct PE_OP_HEADER *peOpHeader=NULL;

	dosHeader = (MS_DOS_HEADER*) appBytes;
	peHeader = (PE_HEADER *) ( (  appBytes) +  dosHeader->PEOffset);
	peOpHeader = (PE_OP_HEADER *) ( (  appBytes) +  dosHeader->PEOffset+sizeof(PE_HEADER));

	if (peOpHeader->magic  ==  HDR64_MAGIC)
	{
		result = true;
	}

	return result;
}

//NOTE(): This code was taken from PE_TO_SHELLCODE https://github.com/hasherezade/pe_to_shellcode/
bool overwrite_hdr(ui8 *my_exe, size_t exe_size, ui32 raw)
{
	ui8 redir_code[] = "\x4D" //dec ebp
		"\x5A" //pop edx
		"\x45" //inc ebp
		"\x52" //push edx
		"\xE8\x00\x00\x00\x00" //call <next_line>
		"\x5B" // pop ebx
		"\x48\x83\xEB\x09" // sub ebx,9
		"\x53" // push ebx (Image Base)
		"\x48\x81\xC3" // add ebx,
		"\x59\x04\x00\x00" // value
		"\xFF\xD3" // call ebx
		"\xc3"; // ret

	size_t offset = sizeof(redir_code) - 8;

	memcpy(redir_code + offset, &raw, sizeof(ui32));
	memcpy(my_exe, redir_code, sizeof(redir_code));

	return true;
}

//NOTE(): This code was taken from PE_TO_SHELLCODE https://github.com/hasherezade/pe_to_shellcode/
ui8 * shellcodify(ui8 *my_exe, size_t exe_size, size_t &out_size, bool is64b)
{
	out_size = 0;
	size_t stub_size = 0;

	FILE *fileStub = NULL;
	size_t fileSize = 0;
	size_t ext_size = 0;
	ui8 *stub = NULL;
	ui8 *ext_buf = NULL;
	s32* stubsFile = NULL;

	stubsFile = S32("stub64.bin");

	fileStub = fopen(stubsFile, "rb");

	if (fileStub)
	{
		fseek(fileStub,0,SEEK_END);
		stub_size = ftell(fileStub);
		rewind(fileStub);

		stub = (ui8*) MemoryRaw(stub_size);
		memset(stub,0,stub_size);

		fread(stub,1,stub_size,fileStub);

		ext_size = exe_size + stub_size;
		ext_buf = (ui8*) MemoryRaw(ext_size);
		memset(ext_buf,0,ext_size);

		memcpy(ext_buf, my_exe, exe_size);
		memcpy(ext_buf + exe_size, stub, stub_size);

		ui32 raw_addr = exe_size;
		overwrite_hdr(ext_buf, ext_size, raw_addr);

		out_size = ext_size;
	}

	fclose(fileStub);

	if (stub)
	{
		Free(stub);
		stub = NULL;
	}

	if (stubsFile)
	{
		Free(stubsFile);
		stubsFile=NULL;
	}
	return ext_buf;
	
}

int main(int argc, char *args[])
{
	bool32 isArgValid = true;
	bool32 isPEValid = true;
	FILE *app = NULL;
	ui8 *appBytes = NULL;
	size_t fileSize = 0;
	size_t outSize = 0;
	ui8 *code  = NULL;
	struct MS_DOS_HEADER *dosHeader = NULL;
	struct PE_HEADER *peHeader = NULL;
	struct PE_OP_HEADER *peOpHeader=NULL;
	struct PE_OP_HEADER64 *peOpHeader64=NULL;
	ui8 *payload = NULL;
	FILE *outFile = NULL;
	s32 *filename = NULL;
	s32 *outputFilename = NULL;

	for (int argIndex = 0; argIndex < argc; argIndex++)
	{
		if (StrCmp(args[argIndex], "-f"))
		{
			if (argIndex+1 < argc)
			{
				filename = S32(args[argIndex+1]);
			}
		}

		if (StrCmp(args[argIndex], "-o"))
		{
			if (argIndex+1 < argc)
			{
				outputFilename = S32(args[argIndex+1]);
			}
		}
	}

	if (outputFilename == NULL)
	{
		outputFilename = S32("shellcode.sc");
	}

	if (isArgValid)
	{
		app = fopen(filename, "rb");

		if (app)
		{
			fseek(app,0,SEEK_END);
			fileSize = ftell(app);
			rewind(app);

			appBytes = (uint8*) MemoryRaw(fileSize);

			fread(appBytes,1,fileSize,app);

			fclose(app);

			dosHeader = (MS_DOS_HEADER*) appBytes;
			peHeader = (PE_HEADER *) ( (  appBytes) +  dosHeader->PEOffset);
			peOpHeader = (PE_OP_HEADER *) ( (  appBytes) +  dosHeader->PEOffset+sizeof(PE_HEADER));
			peOpHeader64 = (PE_OP_HEADER64 *) ( (  appBytes) +  dosHeader->PEOffset+sizeof(PE_HEADER));

			printf("Header magic %x\n", dosHeader->magic);
			printf("Filename: %s\n", filename);
			printf("Output name: %s\n", outputFilename);
			if (dosHeader->magic == 0x4d5a || dosHeader->magic == 0x5a4d)
			{

				printf("Appication Type: ");
				if (PEIs64Bit(appBytes))
				{
					printf("64 Bits ");
				} else {
					printf("32 Bits *not yet supportive.");
					isPEValid = false;
				}
				if (peOpHeader64->subSystem ==  SUBSYSTEM_WINDOWS_GUI)
				{
					printf("Windows GUI Appication.\n");
				} else
				if (peOpHeader64->subSystem ==  SUBSYSTEM_WINDOWS_CUI)
				{
					printf("Console Application.\n");
				} else {
					printf("Application is not supportive.\n");
					isPEValid = false;
				}

				

				data_directory dd =  peOpHeader64->DataDirectory[DIRECTORY_ENTRY_COM_DESCRIPTOR];
				if (dd.VirtualAddress != 0)
				{
					printf("Dot net appicaltion are not supportive.\n");
					isPEValid = false;
				}

				data_directory tlsdd =  peOpHeader64->DataDirectory[DIRECTORY_ENTRY_TLS];

				if (tlsdd.VirtualAddress != 0)
				{
					printf("TLS Callbacks are not supportive!\n");
					isPEValid = false;
				}
			} else {
				printf("Invalid Header!\n");
				isPEValid = false;
			}
		} else {
			printf("Can't not open executable file!\n");
			isPEValid = false;
		}

		if (isPEValid)
		{
			printf("Creating Shell Code.\n");
			payload = shellcodify(appBytes, fileSize, outSize,PEIs64Bit(appBytes));

			outFile = fopen(outputFilename,"wb");

			if (outFile)
			{
				printf("Writing  to file...%s\n",outputFilename);
				fwrite(payload,1,outSize,outFile);
				printf("Done...\n");
			} else {

				printf("Can't not create file.");
			}

			fclose(outFile);

			if (payload)
			{
				Free(payload);
				payload = NULL;
			}
		}
	}

	if (outputFilename)
	{
		Free(outputFilename);
		outputFilename=NULL;
	}
	if (filename)
	{
		Free(filename);
		filename = NULL;
	}

	if (appBytes)
	{
		Free(appBytes);
		appBytes=NULL;
	}

	MemoryResults();
}

