#include "adapter_policy.h"
__declspec(dllexport) int Replay(IP_ADAPTER_INFO *head,ULONG length,const char *ip) {
    return adapt_be200(head,length,ip);
}
