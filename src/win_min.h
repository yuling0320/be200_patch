#pragma once
#include <stdint.h>
#include <stddef.h>
typedef unsigned long DWORD;
typedef unsigned long ULONG;
typedef long LONG;
typedef int BOOL;
typedef unsigned short WCHAR;
typedef void *HANDLE;
typedef void *HMODULE;
typedef void *HKEY;
typedef void *FARPROC;
typedef struct { void *ptr; } INIT_ONCE;
#define WINAPI __stdcall
#define IMPORT __declspec(dllimport)
#define INVALID_HANDLE_VALUE ((HANDLE)(intptr_t)-1)
#define HKEY_LOCAL_MACHINE ((HKEY)(intptr_t)(long)0x80000002)
IMPORT BOOL WINAPI InitOnceExecuteOnce(INIT_ONCE *, BOOL (WINAPI *)(INIT_ONCE *,void *,void **),void *,void **);
IMPORT HMODULE WINAPI LoadLibraryExW(const WCHAR *,HANDLE,DWORD);
IMPORT FARPROC WINAPI GetProcAddress(HMODULE,const char *);
IMPORT DWORD WINAPI GetSystemDirectoryW(WCHAR *,DWORD);
IMPORT DWORD WINAPI GetModuleFileNameW(HMODULE,WCHAR *,DWORD);
IMPORT HMODULE WINAPI GetModuleHandleW(const WCHAR *);
IMPORT DWORD WINAPI GetLastError(void);
IMPORT void WINAPI SetLastError(DWORD);
IMPORT void WINAPI RaiseFailFastException(void *,void *,DWORD);
IMPORT HANDLE WINAPI CreateFileW(const WCHAR *,DWORD,DWORD,void *,DWORD,DWORD,HANDLE);
IMPORT BOOL WINAPI ReadFile(HANDLE,void *,DWORD,DWORD *,void *);
IMPORT BOOL WINAPI CloseHandle(HANDLE);
IMPORT HANDLE WINAPI GetProcessHeap(void);
IMPORT void *WINAPI HeapAlloc(HANDLE,DWORD,size_t);
IMPORT BOOL WINAPI HeapFree(HANDLE,DWORD,void *);
IMPORT LONG WINAPI RegGetValueA(HKEY,const char *,const char *,DWORD,DWORD *,void *,DWORD *);
IMPORT LONG WINAPI BCryptOpenAlgorithmProvider(void **,const WCHAR *,const WCHAR *,ULONG);
IMPORT LONG WINAPI BCryptGetProperty(void *,const WCHAR *,unsigned char *,ULONG,ULONG *,ULONG);
IMPORT LONG WINAPI BCryptCreateHash(void *,void **,unsigned char *,ULONG,unsigned char *,ULONG,ULONG);
IMPORT LONG WINAPI BCryptHashData(void *,unsigned char *,ULONG,ULONG);
IMPORT LONG WINAPI BCryptFinishHash(void *,unsigned char *,ULONG,ULONG);
IMPORT LONG WINAPI BCryptDestroyHash(void *);
IMPORT LONG WINAPI BCryptCloseAlgorithmProvider(void *,ULONG);

typedef struct IP_ADDR_STRING {
    struct IP_ADDR_STRING *Next;
    char IpAddress[16];
    char IpMask[16];
    DWORD Context;
} IP_ADDR_STRING;
typedef struct IP_ADAPTER_INFO {
    struct IP_ADAPTER_INFO *Next;
    DWORD ComboIndex;
    char AdapterName[260];
    char Description[132];
    ULONG AddressLength;
    unsigned char Address[8];
    DWORD Index;
    ULONG Type;
    ULONG DhcpEnabled;
    IP_ADDR_STRING *CurrentIpAddress;
    IP_ADDR_STRING IpAddressList;
    IP_ADDR_STRING GatewayList;
    IP_ADDR_STRING DhcpServer;
    BOOL HaveWins;
    IP_ADDR_STRING PrimaryWinsServer;
    IP_ADDR_STRING SecondaryWinsServer;
    int64_t LeaseObtained;
    int64_t LeaseExpires;
} IP_ADAPTER_INFO;
_Static_assert(offsetof(IP_ADAPTER_INFO,Description)==0x110,"Description offset");
_Static_assert(offsetof(IP_ADAPTER_INFO,AddressLength)==0x194,"AddressLength offset");
_Static_assert(offsetof(IP_ADAPTER_INFO,Index)==0x1a0,"Index offset");
_Static_assert(offsetof(IP_ADAPTER_INFO,IpAddressList.IpAddress)==0x1c0,"IPv4 offset");
