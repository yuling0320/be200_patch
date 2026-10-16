#include "win_min.h"
#include "adapter_policy.h"
#include "exports.h"

static INIT_ONCE real_once={0},host_once={0};
static HMODULE real_module;
static int trusted_host;
void *real_functions[EXPORT_COUNT];

/* No DllMain, loader-lock work, process injection, driver change, or trust-check patch. */
static BOOL WINAPI initialize_real(INIT_ONCE *once,void *parameter,void **context) {
    (void)once;(void)parameter;(void)context;
    WCHAR path[520];
    DWORD n=GetSystemDirectoryW(path,500);
    static const WCHAR suffix[]={ '\\','i','p','h','l','p','a','p','i','.','d','l','l',0 };
    if(!n || n>=500) return 0;
    for(unsigned i=0;i<sizeof(suffix)/sizeof(*suffix);i++) path[n+i]=suffix[i];
    real_module=LoadLibraryExW(path,0,0x00000800); /* LOAD_LIBRARY_SEARCH_SYSTEM32 */
    if(!real_module) return 0;
    for(unsigned i=0;i<EXPORT_COUNT;i++) {
        real_functions[i]=GetProcAddress(real_module,export_names[i]);
        if(!real_functions[i]) return 0;
    }
    return 1;
}
void *resolve_export(unsigned index) {
    DWORD error=GetLastError();
    if(index>=EXPORT_COUNT || !InitOnceExecuteOnce(&real_once,initialize_real,0,0) || !real_functions[index]) {
        RaiseFailFastException(0,0,0);
        return 0;
    }
    void *result=real_functions[index];
    SetLastError(error);
    return result;
}
static int original_file_hash(const WCHAR *path) {
    static const unsigned char expected[32]={
        0x4c,0x95,0x01,0x23,0x5b,0x9a,0xce,0x24,0x20,0x97,0x65,0x64,0xde,0x49,0xc9,0x6d,
        0xee,0x2f,0x2b,0x0c,0xee,0xa4,0xa5,0x6b,0xdf,0x62,0x49,0x95,0x7a,0x9e,0x03,0xa4};
    static const WCHAR sha256[]={'S','H','A','2','5','6',0};
    static const WCHAR object_length[]={'O','b','j','e','c','t','L','e','n','g','t','h',0};
    HANDLE file=CreateFileW(path,0x80000000,7,0,3,0x08000000,0);
    if(file==INVALID_HANDLE_VALUE) return 0;
    void *algorithm=0,*hash=0,*object=0;
    ULONG object_size=0,returned=0;
    unsigned char output[32],buffer[1024];
    int ok=0;
    if(BCryptOpenAlgorithmProvider(&algorithm,sha256,0,0)<0) goto done;
    if(BCryptGetProperty(algorithm,object_length,(unsigned char *)&object_size,sizeof(object_size),&returned,0)<0 || returned!=sizeof(object_size) || !object_size || object_size>1048576) goto done;
    object=HeapAlloc(GetProcessHeap(),0,object_size);
    if(!object || BCryptCreateHash(algorithm,&hash,object,object_size,0,0,0)<0) goto done;
    for(;;) {
        DWORD read=0;
        if(!ReadFile(file,buffer,sizeof(buffer),&read,0)) goto done;
        if(!read) break;
        if(BCryptHashData(hash,buffer,read,0)<0) goto done;
    }
    if(BCryptFinishHash(hash,output,sizeof(output),0)<0) goto done;
    ok=1;
    for(unsigned i=0;i<sizeof(output);i++) if(output[i]!=expected[i]) ok=0;
done:
    if(hash) BCryptDestroyHash(hash);
    if(object) HeapFree(GetProcessHeap(),0,object);
    if(algorithm) BCryptCloseAlgorithmProvider(algorithm,0);
    CloseHandle(file);
    return ok;
}
static BOOL WINAPI initialize_host(INIT_ONCE *once,void *parameter,void **context) {
    (void)once;(void)parameter;(void)context;
    WCHAR path[520];
    static const WCHAR name[]={'H','i','C','o','n','n','e','c','t','i','v','i','t','y','S','e','r','v','i','c','e','.','e','x','e',0};
    DWORD n=GetModuleFileNameW(0,path,520),start=0;
    if(!n || n>=520) return 1;
    for(DWORD i=0;i<n;i++) if(path[i]=='\\'||path[i]=='/') start=i+1;
    if(n-start!=sizeof(name)/sizeof(*name)-1) return 1;
    for(unsigned i=0;i<sizeof(name)/sizeof(*name);i++) if(path[start+i]!=name[i]) return 1;
    trusted_host=original_file_hash(path);
    return 1;
}

ULONG WINAPI CompatGetAdaptersInfo(IP_ADAPTER_INFO *info,ULONG *size) {
    typedef ULONG (WINAPI *GET_INFO)(IP_ADAPTER_INFO *,ULONG *);
    GET_INFO real=(GET_INFO)resolve_export(GET_ADAPTERS_INFO_INDEX);
    ULONG capacity=size?*size:0;
    ULONG status=real(info,size);
    DWORD error=GetLastError();
    if(status==0 && info && size && *size<=capacity) {
        uintptr_t caller=(uintptr_t)__builtin_return_address(0);
        uintptr_t base=(uintptr_t)GetModuleHandleW(0);
        /* Exact original GetAdaptersInfoExt call sites only; helper call cannot alter other app queries. */
        if(caller>=base+0xad1f0 && caller<base+0xad460) {
            InitOnceExecuteOnce(&host_once,initialize_host,0,0);
            if(trusted_host) {
                char local_ip[16]={0}; DWORD n=sizeof(local_ip),type=0;
                if(RegGetValueA(HKEY_LOCAL_MACHINE,"SYSTEM\\ControlSet001\\Services\\WlanSvc\\Parameters\\EapolKeyIpAddress","LocalAddress",0x00000002,&type,local_ip,&n)==0 && type==1 && n>1 && n<=sizeof(local_ip) && local_ip[n-1]==0)
                    adapt_be200(info,*size,local_ip);
            }
        }
    }
    SetLastError(error);
    return status;
}
