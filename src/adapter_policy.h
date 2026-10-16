#pragma once
#include "win_min.h"

static int bounded_equal(const char *a,const char *b,size_t n) {
    for(size_t i=0;i<n;i++) { if(a[i]!=b[i]) return 0; if(!a[i]) return 1; }
    return 0;
}
static int numbered_be200(const char *s) {
    static const char prefix[]="Intel(R) Wi-Fi 7 BE200 320MHz #";
    for(size_t i=0;i<sizeof(prefix)-1;i++) if(s[i]!=prefix[i]) return 0;
    size_t i=sizeof(prefix)-1;
    if(s[i]<'1'||s[i]>'9') return 0;
    for(i++;i<132;i++) { if(!s[i]) return 1; if(s[i]<'0'||s[i]>'9') return 0; }
    return 0;
}
static int contained(const void *ptr,size_t n,uintptr_t lo,uintptr_t hi) {
    uintptr_t p=(uintptr_t)ptr;
    return p>=lo && p<=hi && n<=hi-p;
}
/* Only the active BE200 virtual interface may change. Every other byte stays as returned by Windows. */
static int adapt_be200(IP_ADAPTER_INFO *head,ULONG length,const char local_ip[16]) {
    static const char compatibility_name[]="Microsoft Wi-Fi Direct Virtual Adapter";
    if(!head || !length || !local_ip[0] || bounded_equal(local_ip,"0.0.0.0",16)) return 0;
    uintptr_t lo=(uintptr_t)head,hi=lo+length;
    if(hi<lo) return 0;
    IP_ADAPTER_INFO *match=0;
    IP_ADAPTER_INFO *seen[128];
    unsigned count=0;
    for(IP_ADAPTER_INFO *a=head;a;a=a->Next) {
        if(count>=128 || !contained(a,sizeof(*a),lo,hi)) return 0;
        for(unsigned i=0;i<count;i++) if(seen[i]==a) return 0;
        seen[count++]=a;
        if(a->Type!=71 || a->AddressLength!=6 || !a->Index || !numbered_be200(a->Description)) continue;
        unsigned ips=0;
        int ip_match=0;
        for(IP_ADDR_STRING *ip=&a->IpAddressList;ip;ip=ip->Next) {
            if(++ips>32 || !contained(ip,sizeof(*ip),lo,hi)) return 0;
            if(bounded_equal(ip->IpAddress,local_ip,16)) ip_match=1;
        }
        if(ip_match) { if(match) return 0; match=a; }
    }
    if(!match) return 0;
    for(size_t i=0;i<sizeof(compatibility_name);i++) match->Description[i]=compatibility_name[i];
    return 1;
}
