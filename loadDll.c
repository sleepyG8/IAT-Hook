#include <Windows.h>
//For testing
int main(int argc, char* argv[]) {
  
if (argc < 2) {
printf("Usage: loadDll.exe <DLL>\n");
}
  
HMODULE hMod = LoadLibraryA(argv[1]);
if (!hMod) return 1;

return 0;
}
