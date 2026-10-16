#include "win_min.h"
#include "adapter_policy.h"
IMPORT ULONG WINAPI GetAdaptersInfo(IP_ADAPTER_INFO *,ULONG *);
IMPORT ULONG WINAPI GetNumberOfInterfaces(ULONG *);
IMPORT ULONG WINAPI GetIfTable2(void **);
IMPORT void WINAPI FreeMibTable(void *);
IMPORT HANDLE WINAPI GetStdHandle(DWORD);
IMPORT BOOL WINAPI WriteFile(HANDLE,const void *,DWORD,DWORD *,void *);
IMPORT void WINAPI ExitProcess(DWORD);
IMPORT HANDLE WINAPI CreateThread(void *,size_t,DWORD (WINAPI *)(void *),void *,DWORD,DWORD *);
IMPORT DWORD WINAPI WaitForMultipleObjects(DWORD,const HANDLE *,BOOL,DWORD);
static void print(const char *s) {
    DWORD n=0,written=0; while(s[n]) n++;
    WriteFile(GetStdHandle((DWORD)-11),s,n,&written,0);
}
static int same_bytes(const void *x,const void *y,size_t n) {
    const unsigned char *a=x,*b=y;for(size_t i=0;i<n;i++) if(a[i]!=b[i]) return 0;return 1;
}
static void copy_bytes(void *x,const void *y,size_t n) {
    unsigned char *a=x;const unsigned char *b=y;for(size_t i=0;i<n;i++) a[i]=b[i];
}
static void zero_bytes(void *x,size_t n) { unsigned char *a=x;for(size_t i=0;i<n;i++) a[i]=0; }
static void put(char *out,const char *in) { for(size_t i=0;;i++) {out[i]=in[i];if(!in[i])break;} }
static int policy_tests(void) {
    static IP_ADAPTER_INFO records[3],saved[3];
    zero_bytes(records,sizeof(records));
    for(unsigned i=0;i<3;i++) {
        records[i].Next=i<2?&records[i+1]:0;
        records[i].AddressLength=6;records[i].Address[0]=0x2a;records[i].Address[5]=(unsigned char)i;
        records[i].Index=i+10;records[i].Type=71;
    }
    put(records[0].Description,"Intel(R) Wi-Fi 7 BE200 320MHz");put(records[0].IpAddressList.IpAddress,"192.0.2.10");
    put(records[1].Description,"Intel(R) Wi-Fi 7 BE200 320MHz #2");put(records[1].IpAddressList.IpAddress,"0.0.0.0");
    put(records[2].Description,"Intel(R) Wi-Fi 7 BE200 320MHz #4");put(records[2].IpAddressList.IpAddress,"192.168.137.1");
    copy_bytes(saved,records,sizeof(records));
    if(adapt_be200(records,sizeof(records),"192.168.137.1")!=1) return 1;
    if(!bounded_equal(records[2].Description,"Microsoft Wi-Fi Direct Virtual Adapter",132)) return 2;
    for(size_t i=0;i<sizeof(records);i++) {
        size_t start=sizeof(IP_ADAPTER_INFO)*2+offsetof(IP_ADAPTER_INFO,Description);
        if(i>=start && i<start+39) continue;
        if(((unsigned char *)records)[i]!=((unsigned char *)saved)[i]) return 3;
    }
    /* Ambiguity, invalid pointer, cycle and malformed description fail without any mutation. */
    copy_bytes(records,saved,sizeof(records));put(records[1].IpAddressList.IpAddress,"192.168.137.1");copy_bytes(saved,records,sizeof(records));
    if(adapt_be200(records,sizeof(records),"192.168.137.1") || !same_bytes(records,saved,sizeof(records))) return 4;
    put(records[1].IpAddressList.IpAddress,"0.0.0.0");records[2].Next=(IP_ADAPTER_INFO *)((uintptr_t)records-8);copy_bytes(saved,records,sizeof(records));
    if(adapt_be200(records,sizeof(records),"192.168.137.1") || !same_bytes(records,saved,sizeof(records))) return 5;
    records[2].Next=records;copy_bytes(saved,records,sizeof(records));
    if(adapt_be200(records,sizeof(records),"192.168.137.1") || !same_bytes(records,saved,sizeof(records))) return 6;
    records[2].Next=0;put(records[2].Description,"Intel(R) Wi-Fi 7 BE200 320MHz #4x");copy_bytes(saved,records,sizeof(records));
    if(adapt_be200(records,sizeof(records),"192.168.137.1") || !same_bytes(records,saved,sizeof(records))) return 7;
    if(adapt_be200(records,sizeof(records),"0.0.0.0")) return 8;
    return 0;
}
typedef ULONG (WINAPI *GET_INFO)(IP_ADAPTER_INFO *,ULONG *);
static GET_INFO system_info;
static DWORD WINAPI exercise(void *ignored) {
    (void)ignored;
    for(unsigned i=0;i<30;i++) {
        ULONG n=0,count=0;
        if(GetAdaptersInfo(0,&n)!=111 || !n) return 1;
        IP_ADAPTER_INFO *buffer=HeapAlloc(GetProcessHeap(),0,n);
        if(!buffer) return 2;
        ULONG result=GetAdaptersInfo(buffer,&n);
        HeapFree(GetProcessHeap(),0,buffer);
        if(result || GetNumberOfInterfaces(&count) || !count) return 3;
        void *table=0;
        if(GetIfTable2(&table) || !table) return 4;
        FreeMibTable(table);
    }
    return 0;
}
IMPORT BOOL WINAPI GetExitCodeThread(HANDLE,DWORD *);
void mainCRTStartup(void) {
    int policy=policy_tests();
    if(policy) {print("FAIL policy\n");ExitProcess(10+(DWORD)policy);}
    static const WCHAR ip_name[]={'i','p','h','l','p','a','p','i','.','d','l','l',0};
    WCHAR loaded[520],system_path[520];
    HMODULE proxy=GetModuleHandleW(ip_name);
    DWORD n=GetModuleFileNameW(proxy,loaded,520),s=GetSystemDirectoryW(system_path,500);
    if(!n||n>=520||!s||s>=500){print("FAIL module path\n");ExitProcess(30);}
    for(unsigned i=0;i<sizeof(ip_name)/sizeof(*ip_name);i++)system_path[s+1+i]=ip_name[i];system_path[s]='\\';
    HMODULE system=LoadLibraryExW(system_path,0,0x800);
    if(!system || system==proxy){print("FAIL real module identity\n");ExitProcess(31);}
    system_info=(GET_INFO)GetProcAddress(system,"GetAdaptersInfo");
    if(!system_info){print("FAIL real export\n");ExitProcess(32);}
    /* The proxy's transparent host guard is checked against the real OS response. */
    ULONG pn=0,sn=0;
    if(GetAdaptersInfo(0,&pn)!=system_info(0,&sn) || pn!=sn){print("FAIL size forwarding\n");ExitProcess(33);}
    IP_ADAPTER_INFO *p=HeapAlloc(GetProcessHeap(),0,pn),*q=HeapAlloc(GetProcessHeap(),0,sn);
    if(!p||!q || GetAdaptersInfo(p,&pn) || system_info(q,&sn)){print("FAIL data query\n");ExitProcess(34);}
    IP_ADAPTER_INFO *a=p,*b=q;unsigned nodes=0;
    while(a&&b&&nodes++<128) {
        if(a->Index!=b->Index || a->Type!=b->Type || a->AddressLength!=b->AddressLength || !same_bytes(a->Address,b->Address,8) || !bounded_equal(a->Description,b->Description,132) || !bounded_equal(a->AdapterName,b->AdapterName,260) || !bounded_equal(a->IpAddressList.IpAddress,b->IpAddressList.IpAddress,16)) {
            print("FAIL transparent host comparison\n");ExitProcess(35);
        }
        a=a->Next;b=b->Next;
    }
    HeapFree(GetProcessHeap(),0,p);HeapFree(GetProcessHeap(),0,q);
    if(a||b){print("FAIL adapter count\n");ExitProcess(36);}
    HANDLE threads[12];
    for(unsigned i=0;i<12;i++) {threads[i]=CreateThread(0,0,exercise,0,0,0);if(!threads[i]){print("FAIL thread start\n");ExitProcess(37);}}
    if(WaitForMultipleObjects(12,threads,1,20000)!=0){print("FAIL thread wait\n");ExitProcess(38);}
    for(unsigned i=0;i<12;i++){DWORD exit=99;if(!GetExitCodeThread(threads[i],&exit)||exit){print("FAIL threaded forwarding\n");ExitProcess(39);}CloseHandle(threads[i]);}
    print("PASS policy byte preservation, ambiguity and malformed data guards\nPASS local DLL loaded separately from System32 IP Helper\nPASS genuine OS adapter data unchanged for unrelated host\nPASS 12 threads x 30 calls across GetAdaptersInfo/GetNumberOfInterfaces/GetIfTable2/FreeMibTable\n");
    ExitProcess(0);
}
