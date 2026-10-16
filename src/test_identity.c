/* Compiles the production identity implementation into a separate local test host. */
#include "proxy.c"
IMPORT HANDLE WINAPI GetStdHandle(DWORD);
IMPORT BOOL WINAPI WriteFile(HANDLE,const void *,DWORD,DWORD *,void *);
IMPORT void WINAPI ExitProcess(DWORD);
static void print(const char *s) {
    DWORD n=0,written=0;while(s[n])n++;
    WriteFile(GetStdHandle((DWORD)-11),s,n,&written,0);
}
void mainCRTStartup(void) {
    static const WCHAR original[]=L"test-input\\original-HiConnectivityService.exe";
    static const WCHAR modified[]=L"test-input\\modified-HiConnectivityService.exe";
    if(!original_file_hash(original) || original_file_hash(modified)) {print("FAIL hash identity\n");ExitProcess(1);}
    InitOnceExecuteOnce(&host_once,initialize_host,0,0);
    if(trusted_host) {print("FAIL unrelated host identity\n");ExitProcess(2);}
    print("PASS production BCrypt SHA256 accepts exact signed original, rejects modified EXE\nPASS host guard rejects unrelated test executable\n");
    ExitProcess(0);
}
