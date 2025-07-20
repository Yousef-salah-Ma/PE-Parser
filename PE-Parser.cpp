#include <stdio.h>
#include <Windows.h>
#include <winternl.h>

// Reads a PE file from disk into memory
BOOL ReadPeFile(LPCSTR lp_name_file, PBYTE* ppe, SIZE_T* size_pe) {
    HANDLE hfile = INVALID_HANDLE_VALUE;
    DWORD hfilesize = NULL;
    DWORD dwNumberOfBytesRead = NULL;
    PBYTE pbuff = NULL;

    hfile = CreateFileA(lp_name_file, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hfile == INVALID_HANDLE_VALUE) {
        printf("CreateFileA failed %lu \n", GetLastError());
        return FALSE;
    }

    hfilesize = GetFileSize(hfile, NULL);
    if (hfilesize == NULL) {
        printf("GetFileSize failed %lu \n", GetLastError());
        CloseHandle(hfile);
        return FALSE;
    }

    pbuff = (PBYTE)HeapAlloc(GetProcessHeap(), 0, hfilesize);
    if (pbuff == NULL) {
        printf("HeapAlloc failed %lu \n", GetLastError());
        CloseHandle(hfile);
        return FALSE;
    }

    if (!ReadFile(hfile, pbuff, hfilesize, &dwNumberOfBytesRead, NULL) || hfilesize != dwNumberOfBytesRead) {
        printf("ReadFile failed %lu \n", GetLastError());
        HeapFree(GetProcessHeap(), 0, pbuff);
        CloseHandle(hfile);
        return FALSE;
    }

    *ppe = pbuff;
    *size_pe = hfilesize;
    CloseHandle(hfile);
    return TRUE;
}

VOID parsepe(PBYTE ppe) {
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)ppe;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[-] Not a valid DOS header\n");
        return;
    }

    printf("############## DOS HEADER ##############\n");
    printf("e_magic: 0x%X\n", pDosHeader->e_magic);
    printf("e_lfanew: 0x%X\n", pDosHeader->e_lfanew);

    PIMAGE_NT_HEADERS pNT_Header = (PIMAGE_NT_HEADERS)(ppe + pDosHeader->e_lfanew);
    if (pNT_Header->Signature != IMAGE_NT_SIGNATURE) {
        printf("[-] Not a valid NT header (PE)\n");
        return;
    }

    printf("############## NT HEADER ##############\n");
    printf("Signature: 0x%X\n", pNT_Header->Signature);

    IMAGE_FILE_HEADER image_fileHdr = pNT_Header->FileHeader;
    printf("############## FILE HEADER ##############\n");
    if (image_fileHdr.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) {
        if (image_fileHdr.Characteristics & IMAGE_FILE_DLL)
            printf("[+] Type: DLL\n");
        else if (pNT_Header->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_NATIVE)
            printf("[+] Type: SYS (Driver)\n");
        else
            printf("[+] Type: EXE\n");
    }

    printf("Machine: 0x%X (%s)\n", image_fileHdr.Machine,
        image_fileHdr.Machine == IMAGE_FILE_MACHINE_I386 ? "x32" :
        image_fileHdr.Machine == IMAGE_FILE_MACHINE_AMD64 ? "x64" : "Unknown");
    printf("Number of Sections: %d\n", image_fileHdr.NumberOfSections);

    printf("############## OPTIONAL HEADER ##############\n");
    PIMAGE_OPTIONAL_HEADER pOptionalHeader = &pNT_Header->OptionalHeader;
    printf("Magic: 0x%X (%s)\n", pOptionalHeader->Magic,
        pOptionalHeader->Magic == 0x10b ? "32-bit" :
        pOptionalHeader->Magic == 0x20b ? "64-bit" : "Unknown");
    printf("Entry Point: 0x%X\n", pOptionalHeader->AddressOfEntryPoint);
    printf("Image Base: 0x%llX\n", pOptionalHeader->ImageBase);
    printf("Section Alignment: 0x%X\n", pOptionalHeader->SectionAlignment);
    printf("File Alignment: 0x%X\n", pOptionalHeader->FileAlignment);
    printf("Subsystem: 0x%X\n", pOptionalHeader->Subsystem);
    printf("Size of Image: 0x%X\n", pOptionalHeader->SizeOfImage);
    printf("Size of Headers: 0x%X\n", pOptionalHeader->SizeOfHeaders);

    printf("############## IMPORT DIRECTORY ##############\n");
    IMAGE_DATA_DIRECTORY importDirectory = pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    printf("Import Table RVA: 0x%X\n", importDirectory.VirtualAddress);
    printf("Import Table Size: 0x%X\n", importDirectory.Size);

    printf("############## SECTIONS ##############\n");
    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNT_Header);
    for (int i = 0; i < image_fileHdr.NumberOfSections; i++) {
        printf("Section %d: %.8s\n", i + 1, pSectionHeader[i].Name);
        printf("  RVA: 0x%X\n", pSectionHeader[i].VirtualAddress);
        printf("  Raw Size: 0x%X\n", pSectionHeader[i].SizeOfRawData);
        printf("  Raw Offset: 0x%X\n", pSectionHeader[i].PointerToRawData);

        PBYTE sectionData = ppe + pSectionHeader[i].PointerToRawData;
        printf("  Hex Dump:\n");
        for (DWORD j = 0; j < pSectionHeader[i].SizeOfRawData; j++) {
            if (j % 16 == 0) printf("    %08X  ", j);
            printf("%02X ", sectionData[j]);
            if ((j + 1) % 16 == 0 || j + 1 == pSectionHeader[i].SizeOfRawData)
                printf("\n");
        }
        printf("------------------------------------------------------\n");
    }
}

int main(int argc, char* argv[]) {
    PBYTE ppe = NULL;
    SIZE_T size_pe = 0;

    if (argc < 2) {
        printf("Usage: %s <path_to_pe_file>\n", argv[0]);
        return 1;
    }

    if (ReadPeFile(argv[1], &ppe, &size_pe)) {
        parsepe(ppe);
        HeapFree(GetProcessHeap(), 0, ppe);
    }

    return 0;
}
